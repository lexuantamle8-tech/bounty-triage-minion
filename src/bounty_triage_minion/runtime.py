"""OpenMinion 0.1 runtime integration for BountyTriage Minion."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
from typing import Any

from openminion import (
    APIRuntime,
    Agent,
    MemoryBundle,
    OpenMinionConfig,
    ProviderError,
    TurnTimeoutError,
    __version__ as OPENMINION_VERSION,
)
from openminion.api.queries.runs import list_runs
from openminion.base.config import AgentProfileConfig, save_config
from openminion.modules.artifact import ArtifactCtl
from openminion.modules.memory.portability import (
    export_bundle,
    import_bundle,
    load_bundle,
    save_bundle,
)
from openminion.modules.skill.interfaces import SkillIngestAuthority
from openminion.modules.skill.runtime.skill import Skill
from openminion.modules.storage.engine import StorageEngine
from openminion.modules.task import (
    PlanDraft,
    PlanStepDraft,
    PlanStepStatus,
    SqlTaskCtl,
    StepUpdateInput,
    TaskCreateInput,
)
from openminion.modules.tool.framework import build_registrar

from .models import (
    LicenseSecretsReport,
    ReleaseReadinessReport,
    RepoHealthReport,
)
from .tools import (
    ALL_TRIAGE_TOOLS,
    READONLY_TRIAGE_TOOLS,
    export_triage_report,
    generate_release_checklist,
    inspect_repo_health,
    set_workspace_root,
    verify_license_and_secrets,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SKILL_PATH = PROJECT_ROOT / "skills" / "bounty-triage-readonly" / "SKILL.md"
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "agents.json"

PROVIDER_ENV_CATALOG: tuple[tuple[str, str, str], ...] = (
    ("cortensor-portal", "CORTENSOR_API_KEY", "Cortensor Portal (OpenAI-compatible)"),
    ("cortensor-router", "CORTENSOR_API_KEY", "Cortensor Router (direct completion)"),
    ("openai", "OPENAI_API_KEY", "OpenAI"),
    ("anthropic", "ANTHROPIC_API_KEY", "Anthropic"),
    ("gemini", "GEMINI_API_KEY", "Google Gemini"),
    ("openrouter", "OPENROUTER_API_KEY", "OpenRouter"),
    ("ollama", "OLLAMA_HOST", "Local Ollama (optional env; defaults to 127.0.0.1:11434)"),
)


def provider_env_diagnostics() -> dict[str, Any]:
    """Report which live LLM provider env vars are present without reading/printing secrets."""
    providers: list[dict[str, Any]] = []
    any_cloud_key = False
    for preset_id, env_var, label in PROVIDER_ENV_CATALOG:
        is_set = bool(os.environ.get(env_var, "").strip())
        if preset_id != "ollama" and is_set:
            any_cloud_key = True
        providers.append(
            {
                "preset_id": preset_id,
                "label": label,
                "credential_env": env_var,
                "configured": is_set,
            }
        )
    return {
        "openminion_version": OPENMINION_VERSION,
        "any_cloud_provider_key_configured": any_cloud_key,
        "live_model_turn_ready": any_cloud_key,
        "providers": providers,
    }


def create_isolated_demo_runtime(
    state_root: Path,
    *,
    agent_id: str = "bounty-triage-readonly",
) -> tuple[APIRuntime, Path]:
    """Create an isolated local OpenMinion APIRuntime backed by SQLite and the echo demo provider.

    Demo mode exercises OpenMinion's real configuration, storage, sessions,
    policy, tool registry, and turn ingress plumbing without calling an external LLM.
    """
    state_root = state_root.expanduser().resolve()
    data_root = state_root / ".openminion"
    data_root.mkdir(parents=True, exist_ok=True)

    config = OpenMinionConfig()
    config.default_agent = agent_id
    config.runtime.log_level = "ERROR"
    config.storage.path = str(data_root / "state" / "openminion.db")
    config.agents[agent_id] = AgentProfileConfig(
        name=agent_id,
        provider="echo",
        default_channel="console",
        structural_tool_results=True,
    )
    config_path = data_root / "agents.json"
    save_config(config, str(config_path))

    runtime = APIRuntime.from_config_path(
        str(config_path),
        home_root=state_root,
        data_root=data_root,
    )
    return runtime, config_path


@dataclass
class AuditExecutionRecord:
    """Inspectable record of a full BountyTriage Minion audit run across OpenMinion subsystems."""

    execution_mode: str
    openminion_version: str
    session_id: str
    run_id: str | None
    task_id: str
    plan_id: str
    skill_id: str
    skill_version_hash: str
    skill_match_count: int
    artifact_sha256: str
    policy_checks: dict[str, dict[str, str]]
    health: RepoHealthReport
    hygiene: LicenseSecretsReport
    release: ReleaseReadinessReport
    memory_bundle_path: str | None = None
    exported_report_path: str | None = None
    runtime_posture_summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_mode": self.execution_mode,
            "openminion_version": self.openminion_version,
            "session_id": self.session_id,
            "run_id": self.run_id,
            "task_id": self.task_id,
            "plan_id": self.plan_id,
            "skill_id": self.skill_id,
            "skill_version_hash": self.skill_version_hash,
            "skill_match_count": self.skill_match_count,
            "artifact_sha256": self.artifact_sha256,
            "policy_checks": self.policy_checks,
            "health": self.health.model_dump(),
            "hygiene": self.hygiene.model_dump(),
            "release": self.release.model_dump(),
            "memory_bundle_path": self.memory_bundle_path,
            "exported_report_path": self.exported_report_path,
            "runtime_posture_summary": self.runtime_posture_summary,
        }


class TriageWorkflowRunner:
    """Runs repeatable repository triage & release readiness using real OpenMinion 0.1 subsystems."""

    def __init__(
        self,
        *,
        workspace_root: Path,
        state_root: Path,
        skill_path: Path = DEFAULT_SKILL_PATH,
        agent_id: str = "bounty-triage-readonly",
    ) -> None:
        self.workspace_root = workspace_root.expanduser().resolve()
        self.state_root = state_root.expanduser().resolve()
        self.skill_path = skill_path.expanduser().resolve()
        self.agent_id = agent_id

    def run_audit(
        self,
        *,
        repo_path: Path,
        version: str = "0.1.0",
        issues: list[dict[str, Any]] | None = None,
        session_id: str = "bounty-triage-session",
        export_bundle_path: Path | None = None,
        export_markdown_path: Path | None = None,
        approve_write_export: bool = False,
    ) -> AuditExecutionRecord:
        runtime, _config_path = create_isolated_demo_runtime(
            self.state_root,
            agent_id=self.agent_id,
        )
        data_root = self.state_root / ".openminion"
        issues_list = list(issues or [])
        issues_json = json.dumps(issues_list, ensure_ascii=True)

        try:
            # 1. Register triage tools into OpenMinion's ToolRegistry & verify ActionPolicy decisions.
            for tool_fn in ALL_TRIAGE_TOOLS:
                if tool_fn.tool_decl.name not in runtime.tools.list():
                    build_registrar(tool_fn.tool_family_spec()).register(runtime.tools)

            policy_checks: dict[str, dict[str, str]] = {}
            with runtime.action_policy.temporary_tool_risks(
                {
                    tool_fn.tool_decl.name: runtime.tools.get(tool_fn.tool_decl.name)
                    for tool_fn in ALL_TRIAGE_TOOLS
                }
            ):
                for tool_fn in ALL_TRIAGE_TOOLS:
                    tname = tool_fn.tool_decl.name
                    decision = runtime.action_policy.check(
                        {"tool": tname, "method": "default", "args": {}},
                        {},
                    )
                    policy_checks[tname] = {
                        "decision": decision.decision,
                        "risk_class": decision.risk.risk_class,
                    }

            # 2. Ingest, admit, and match our SKILL.md through OpenMinion's real Skill subsystem.
            skill_id, version_hash, match_count = self._run_skill_lifecycle(data_root)

            # 3. Create a durable multi-step task & plan in OpenMinion's SqlTaskCtl.
            task_db = data_root / "state" / "triage_tasks.db"
            task_engine = StorageEngine.from_paths(
                root_dir=data_root / "blobs" / "tasks",
                sqlite_path=task_db,
                fallback_root=data_root / "fallback" / "tasks",
                wal=True,
                default_namespace="task",
            )
            try:
                task_ctl = SqlTaskCtl(task_engine.record_store)
                task = task_ctl.create_task(
                    TaskCreateInput(
                        title=f"Release readiness audit v{version} ({repo_path.name})",
                        description="Automated local-first OpenMinion triage workflow.",
                        labels=["triage", "release-readiness"],
                    )
                )
                plan = task_ctl.attach_plan(
                    task.task_id,
                    PlanDraft(
                        plan_name="bounty-triage-readonly-plan",
                        steps=[
                            PlanStepDraft(
                                title="Inspect repository health",
                                instruction="Run inspect_repo_health within workspace boundary.",
                            ),
                            PlanStepDraft(
                                title="Verify license and secret hygiene",
                                instruction="Run verify_license_and_secrets with redaction.",
                            ),
                            PlanStepDraft(
                                title="Generate release readiness checklist",
                                instruction="Score open issues and compute GO/CONDITIONAL_GO/NO_GO verdict.",
                            ),
                        ],
                    ),
                )

                # 4. Execute confined read-only tools and advance durable task steps.
                with set_workspace_root(self.workspace_root):
                    health_raw = inspect_repo_health(repo_path=str(repo_path))
                    health = RepoHealthReport.model_validate(health_raw)
                    task_ctl.step_update(
                        task.task_id,
                        plan.steps[0].step_id,
                        StepUpdateInput(
                            status=PlanStepStatus.DONE,
                            note=f"health_score={health.health_score}",
                        ),
                    )

                    hygiene_raw = verify_license_and_secrets(repo_path=str(repo_path))
                    hygiene = LicenseSecretsReport.model_validate(hygiene_raw)
                    task_ctl.step_update(
                        task.task_id,
                        plan.steps[1].step_id,
                        StepUpdateInput(
                            status=PlanStepStatus.DONE,
                            note=f"hygiene_status={hygiene.status}, spdx={hygiene.spdx_guess}",
                        ),
                    )

                    release_raw = generate_release_checklist(
                        repo_path=str(repo_path),
                        version=version,
                        open_issues_json=issues_json,
                    )
                    release = ReleaseReadinessReport.model_validate(release_raw)
                    task_ctl.step_update(
                        task.task_id,
                        plan.steps[2].step_id,
                        StepUpdateInput(
                            status=PlanStepStatus.DONE,
                            note=f"verdict={release.verdict}, blockers={release.blocker_count}",
                        ),
                    )

                    # Optional operator-approved write export (respects ActionPolicy gate).
                    exported_path_str: str | None = None
                    if export_markdown_path is not None and approve_write_export:
                        export_result = export_triage_report(
                            output_path=str(export_markdown_path),
                            report_markdown=release.checklist_markdown,
                        )
                        exported_path_str = str(export_result["path"])
            finally:
                task_engine.close()

            # 5. Record a durable OpenMinion Agent turn in the session log (demo/echo plumbing).
            summary_prompt = (
                f"Recorded BountyTriage audit for {repo_path.name} v{version}: "
                f"verdict={release.verdict}, health={health.health_score}/100, "
                f"hygiene={hygiene.status}, blockers={release.blocker_count}."
            )
            with Agent(
                runtime=runtime,
                agent_id=self.agent_id,
                session_id=session_id,
                instructions="Record concise triage audit summary.",
            ) as agent:
                agent_result = agent.run(summary_prompt)

            # Verify durable run log exists via OpenMinion's runs query API.
            recorded_runs = list_runs(None, session_id=session_id, runtime=runtime)["runs"]
            run_id = agent_result.run_id or (
                recorded_runs[0]["run_id"] if recorded_runs else None
            )

            # 6. Persist immutable content-addressed artifact via ArtifactCtl.
            artifact_sha256 = self._persist_artifact(
                data_root=data_root,
                release=release,
                session_id=session_id,
            )

            # 7. Export & verify portable MemoryBundle snapshot.
            bundle_path_str: str | None = None
            if export_bundle_path is not None:
                bundle = export_bundle(
                    items=[
                        {
                            "kind": "triage_audit",
                            "repo": str(repo_path),
                            "version": version,
                            "verdict": release.verdict,
                            "health_score": health.health_score,
                            "hygiene_status": hygiene.status,
                            "blocker_count": release.blocker_count,
                            "artifact_sha256": artifact_sha256,
                        }
                    ],
                    metadata={
                        "agent_id": self.agent_id,
                        "session_id": session_id,
                        "openminion_version": OPENMINION_VERSION,
                        "execution_mode": "local_deterministic_plus_echo_runtime",
                    },
                )
                export_bundle_path.parent.mkdir(parents=True, exist_ok=True)
                save_bundle(bundle, export_bundle_path)
                loaded = load_bundle(export_bundle_path)
                import_bundle(loaded, trust_mode="candidate")
                bundle_path_str = str(export_bundle_path.resolve())

            posture = runtime.runtime_posture(agent_id=self.agent_id)
            posture_summary = {
                "agent_id": self.agent_id,
                "runtime_mode": posture.get("runtime_mode"),
                "canonical_turn_path_steps": len(posture.get("canonical_turn_path", [])),
                "has_execution_boundary_policy": bool(
                    posture.get("execution_boundary_policy")
                ),
            }

            return AuditExecutionRecord(
                execution_mode="local_deterministic_plus_echo_runtime",
                openminion_version=OPENMINION_VERSION,
                session_id=session_id,
                run_id=run_id,
                task_id=task.task_id,
                plan_id=plan.plan_id,
                skill_id=skill_id,
                skill_version_hash=version_hash,
                skill_match_count=match_count,
                artifact_sha256=artifact_sha256,
                policy_checks=policy_checks,
                health=health,
                hygiene=hygiene,
                release=release,
                memory_bundle_path=bundle_path_str,
                exported_report_path=exported_path_str,
                runtime_posture_summary=posture_summary,
            )
        finally:
            runtime.close()

    def _run_skill_lifecycle(self, data_root: Path) -> tuple[str, str, int]:
        skill_cfg = {
            "sqlite_path": str(data_root / "state" / "skills.db"),
            "blob_root": str(data_root / "blobs" / "skills"),
            "fallback_root": str(data_root / "fallback" / "skills"),
        }
        ctl = Skill(
            skill_cfg,
            home_root=self.state_root,
            known_tools=[t.tool_decl.name for t in ALL_TRIAGE_TOOLS],
        )
        try:
            authority = SkillIngestAuthority.local_operator(
                principal_id="local-triage-operator",
                surface="bounty_triage_minion.runtime",
            )
            skill_id, version_hash, _warnings = ctl.ingest_file(
                self.skill_path,
                name="bounty-triage-readonly",
                scope="agent",
                agent_id=self.agent_id,
                trust="trusted_local",
                authority=authority,
            )
            state = ctl.get_skill_version_state(
                skill_id=skill_id, version_hash=version_hash
            )
            active_hash = state.get("active_version_hash") if state else None
            if active_hash != version_hash:
                ctl.admit_skill_version(
                    skill_id=skill_id,
                    version_hash=version_hash,
                    expected_active_version_hash=active_hash,
                    target_status="verified",
                    reason="Verified read-only triage skill for BountyTriage Minion.",
                    authority=authority,
                )
            matches = ctl.match(
                intent_text="bounty triage readonly repository health and release-readiness audit",
                step_hint={"risk": "low", "tool_id": "inspect_repo_health"},
                agent_id=self.agent_id,
                k=3,
            )
            return skill_id, version_hash, len(matches)
        finally:
            ctl.close()

    def _persist_artifact(
        self,
        *,
        data_root: Path,
        release: ReleaseReadinessReport,
        session_id: str,
    ) -> str:
        artifact_cfg = {
            "blob_store": {
                "backend": "filesystem_cas",
                "root_dir": str(data_root / "artifacts" / "blobs"),
            },
            "index": {
                "backend": "sqlite",
                "sqlite_path": str(data_root / "artifacts" / "index.db"),
                "wal": True,
            },
        }
        prev_home = os.environ.get("OPENMINION_HOME")
        prev_data = os.environ.get("OPENMINION_DATA_ROOT")
        os.environ["OPENMINION_HOME"] = str(self.state_root)
        os.environ["OPENMINION_DATA_ROOT"] = str(data_root)
        try:
            with ArtifactCtl(artifact_cfg) as ctl:
                ref = ctl.ingest_bytes(
                    release.model_dump_json(indent=2).encode("utf-8"),
                    mime="application/json",
                    original_name=f"release-checklist-v{release.version}.json",
                    label=f"triage-release-v{release.version}",
                    session_id=session_id,
                    agent_id=self.agent_id,
                )
                return ref.sha256
        finally:
            if prev_home is None:
                os.environ.pop("OPENMINION_HOME", None)
            else:
                os.environ["OPENMINION_HOME"] = prev_home
            if prev_data is None:
                os.environ.pop("OPENMINION_DATA_ROOT", None)
            else:
                os.environ["OPENMINION_DATA_ROOT"] = prev_data


def run_provider_agent(
    *,
    prompt: str,
    config_path: Path | None = None,
    agent_id: str | None = None,
    session_id: str = "bounty-triage-agent",
    workspace_root: Path | None = None,
    timeout_seconds: float = 120.0,
) -> dict[str, Any]:
    """Run a provider-neutral OpenMinion Agent with the read-only triage tools registered.

    Works identically with:
      - `bounty-triage-readonly` (echo demo plumbing)
      - `bounty-triage-cortensor` (requires CORTENSOR_API_KEY)
      - `bounty-triage-ollama` (requires local Ollama daemon)
      - any user-configured OpenMinion profile
    """
    resolved_config = str((config_path or DEFAULT_CONFIG_PATH).expanduser().resolve())
    resolved_workspace = (workspace_root or Path.cwd()).expanduser().resolve()

    with set_workspace_root(resolved_workspace):
        try:
            with Agent(
                config_path=resolved_config,
                agent_id=agent_id,
                instructions=(
                    "You are BountyTriage Minion, a read-only local-first repository "
                    "triage and release-readiness auditor. Use inspect_repo_health, "
                    "verify_license_and_secrets, score_issue_triage, and "
                    "generate_release_checklist to ground every claim in evidence."
                ),
                tools=READONLY_TRIAGE_TOOLS,
                session_id=session_id,
            ) as agent:
                result = agent.run(prompt, timeout_seconds=timeout_seconds)
                return {
                    "ok": True,
                    "session_id": result.session_id,
                    "run_id": result.run_id,
                    "run_state": result.run_state,
                    "text": result.text,
                    "stats": result.stats,
                }
        except ProviderError as exc:
            return {
                "ok": False,
                "error_type": "ProviderError",
                "code": exc.code,
                "message": exc.message,
                "hint": "Set the required provider API key (e.g. CORTENSOR_API_KEY) or run `bounty-triage doctor`.",
            }
        except TurnTimeoutError as exc:
            return {
                "ok": False,
                "error_type": "TurnTimeoutError",
                "message": str(exc),
            }
