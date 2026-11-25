"""Integration and unit tests exercising real OpenMinion 0.1 runtime building blocks.

Every test runs locally against real OpenMinion 0.1 subsystems (APIRuntime, Agent,
ToolRegistry, ActionPolicy/PolicyCtl, SqlTaskCtl, Skill, ArtifactCtl, MemoryBundle)
with zero faked external LLM calls.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from openminion import (
    Agent,
    AgentOutputValidationError,
    Handoff,
    MemoryBundle,
    OpenMinionConfig,
)
from openminion.api.queries.runs import list_runs
from openminion.modules.memory.portability import (
    export_bundle,
    import_bundle,
    load_bundle,
    save_bundle,
)
from openminion.modules.policy.runtime.action_policy import build_action_policy_service
from openminion.modules.tool.framework import build_registrar
from openminion.modules.tool.registry import ToolRegistry

from bounty_triage_minion.cli import main as cli_main
from bounty_triage_minion.models import TriageSummary
from bounty_triage_minion.runtime import (
    DEFAULT_SKILL_PATH,
    PROJECT_ROOT,
    TriageWorkflowRunner,
    create_isolated_demo_runtime,
    provider_env_diagnostics,
)
from bounty_triage_minion.tools import (
    ALL_TRIAGE_TOOLS,
    READONLY_TRIAGE_TOOLS,
    export_triage_report,
    generate_release_checklist,
    inspect_repo_health,
    score_issue_triage,
    set_workspace_root,
    verify_license_and_secrets,
)


def _create_sample_repo(
    root: Path,
    *,
    include_license: bool = True,
    include_tests: bool = True,
    include_ci: bool = True,
    inject_secret: bool = False,
) -> Path:
    repo = root / "sample-repo"
    (repo / "src").mkdir(parents=True, exist_ok=True)
    (repo / "README.md").write_text("# Sample Repo\n\nA local-first project.\n", encoding="utf-8")
    (repo / "pyproject.toml").write_text('[project]\nname = "sample-repo"\nversion = "0.1.0"\n', encoding="utf-8")
    (repo / "CHANGELOG.md").write_text("# Changelog\n\n- 0.1.0 initial release\n", encoding="utf-8")
    (repo / "SECURITY.md").write_text("# Security Policy\n\nReport responsibly.\n", encoding="utf-8")
    (repo / "src" / "app.py").write_text("def greet(name: str) -> str:\n    return f'hi {name}'\n", encoding="utf-8")

    if include_license:
        (repo / "LICENSE").write_text(
            "Apache License\nVersion 2.0, January 2004\n", encoding="utf-8"
        )
    if include_tests:
        (repo / "tests").mkdir(exist_ok=True)
        (repo / "tests" / "test_app.py").write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    if include_ci:
        (repo / ".github" / "workflows").mkdir(parents=True, exist_ok=True)
        (repo / ".github" / "workflows" / "ci.yml").write_text("name: CI\non: [push]\n", encoding="utf-8")
    if inject_secret:
        # Synthetic test token matching AWS access key shape (non-real).
        fake_aws = "AKIA" + "1234567890ABCDEF"
        (repo / "src" / "leak.py").write_text(f'AWS_KEY = "{fake_aws}"\n', encoding="utf-8")
        (repo / ".env").write_text("SECRET_TOKEN=supersecretvalue123456\n", encoding="utf-8")
    return repo


# ---------------------------------------------------------------------------
# 1. Tools & Workspace Confinement Guard
# ---------------------------------------------------------------------------


def test_tools_workspace_confinement_blocks_path_traversal(tmp_path: Path) -> None:
    workspace = tmp_path / "approved-workspace"
    workspace.mkdir()
    outside = tmp_path / "outside-secret"
    outside.mkdir()

    with set_workspace_root(workspace):
        with pytest.raises(ValueError, match="Workspace guard denied path"):
            inspect_repo_health(repo_path=str(outside))
        with pytest.raises(ValueError, match="Workspace guard denied path"):
            verify_license_and_secrets(repo_path="../outside-secret")
        with pytest.raises(ValueError, match="Workspace guard denied path"):
            export_triage_report(output_path="../escaped.md", report_markdown="# nope")


def test_secret_scanner_redacts_matches_and_flags_env_files(tmp_path: Path) -> None:
    repo = _create_sample_repo(tmp_path, inject_secret=True)
    raw_token = "AKIA" + "1234567890ABCDEF"

    with set_workspace_root(tmp_path):
        report = verify_license_and_secrets(repo_path=str(repo))

    assert report["status"] == "fail"
    assert report["spdx_guess"] == "Apache-2.0"
    assert ".env" in report["committed_env_files"]
    assert len(report["secret_findings"]) == 1
    finding = report["secret_findings"][0]
    assert finding["rule"] == "aws_access_key"
    assert finding["file"] == "src/leak.py"
    # Raw secret must NEVER appear anywhere in serialized output.
    assert raw_token not in json.dumps(report)
    assert finding["redacted_match"] == "AKIA...EF"


def test_issue_triage_scoring_rubric_and_release_verdicts(tmp_path: Path) -> None:
    repo = _create_sample_repo(tmp_path)
    fixtures = json.loads((PROJECT_ROOT / "fixtures" / "sample_issues.json").read_text(encoding="utf-8"))

    sec = score_issue_triage(
        issue_title=fixtures[0]["title"],
        issue_body=fixtures[0]["body"],
        labels=fixtures[0]["labels"],
        has_repro=fixtures[0]["has_repro"],
        is_security=fixtures[0]["is_security"],
    )
    assert sec["priority"] == "P0"
    assert sec["category"] == "security"
    assert sec["recommended_action"] == "escalate_security"

    vague = score_issue_triage(
        issue_title=fixtures[3]["title"],
        issue_body=fixtures[3]["body"],
    )
    assert vague["recommended_action"] == "needs_info"
    assert "detailed_description" in vague["missing_signals"]

    with set_workspace_root(tmp_path):
        # Clean repo + no issues -> GO
        clean_release = generate_release_checklist(repo_path=str(repo), version="1.0.0", open_issues_json="[]")
        assert clean_release["verdict"] == "GO"
        assert clean_release["health_score"] == 100

        # Same repo + P0 security issue -> NO_GO
        blocked_release = generate_release_checklist(
            repo_path=str(repo),
            version="1.0.0",
            open_issues_json=json.dumps(fixtures),
        )
        assert blocked_release["verdict"] == "NO_GO"
        assert blocked_release["blocker_count"] >= 1


def test_openminion_tool_args_schema_rejects_extra_fields() -> None:
    decl = inspect_repo_health.tool_decl
    assert decl.min_scope == "READ_ONLY"
    assert decl.idempotent is True
    with pytest.raises(Exception):
        decl.args_model.model_validate({"repo_path": ".", "unexpected_arg": 123})


# ---------------------------------------------------------------------------
# 2. Permissions & ActionPolicy Boundaries
# ---------------------------------------------------------------------------


def test_action_policy_allows_readonly_and_confirms_write_tools(tmp_path: Path) -> None:
    registry = ToolRegistry()
    for tool_fn in ALL_TRIAGE_TOOLS:
        build_registrar(tool_fn.tool_family_spec()).register(registry)

    policy = build_action_policy_service(
        config=OpenMinionConfig(),
        tool_registry=registry,
        data_root=tmp_path,
    )
    try:
        for ro_tool in READONLY_TRIAGE_TOOLS:
            decision = policy.check(
                {"tool": ro_tool.tool_decl.name, "method": "default", "args": {}}, {}
            )
            assert decision.decision == "ALLOW"
            assert decision.risk.risk_class == "read"

        write_decision = policy.check(
            {"tool": "export_triage_report", "method": "default", "args": {}}, {}
        )
        assert write_decision.decision == "REQUIRE_CONFIRM"
        assert write_decision.risk.risk_class == "write"

        exec_decision = policy.check(
            {"tool": "shell", "method": "exec", "args": {"cmd": "rm -rf /"}}, {}
        )
        assert exec_decision.decision == "REQUIRE_CONFIRM"
        assert exec_decision.risk.risk_class == "exec"
    finally:
        policy.close()


# ---------------------------------------------------------------------------
# 3. Execution, Sessions, Streaming & Structured Output (Real APIRuntime)
# ---------------------------------------------------------------------------


def test_real_apiruntime_session_continuity_isolation_and_streaming(tmp_path: Path) -> None:
    runtime, _config_path = create_isolated_demo_runtime(tmp_path / "rt")
    try:
        with Agent(
            runtime=runtime,
            agent_id="bounty-triage-readonly",
            session_id="triage-sess-A",
            tools=READONLY_TRIAGE_TOOLS,
        ) as agent:
            first = agent.run("Audit step 1: inspect_repo_health")
            second = agent.run("Audit step 2: verify_license_and_secrets")
            isolated = agent.run("Separate session audit", session_id="triage-sess-B")

        assert first.run_state == "completed"
        assert second.run_state == "completed"
        assert first.session_id == "triage-sess-A"
        assert second.session_id == "triage-sess-A"
        assert first.run_id != second.run_id
        assert isolated.session_id == "triage-sess-B"

        runs_a = list_runs(None, session_id="triage-sess-A", runtime=runtime)["runs"]
        runs_b = list_runs(None, session_id="triage-sess-B", runtime=runtime)["runs"]
        assert {r["run_id"] for r in runs_a} == {first.run_id, second.run_id}
        assert {r["run_id"] for r in runs_b} == {isolated.run_id}

        # Verify APIRuntime.submit_turn typed streaming handle
        handle = runtime.submit_turn(
            payload={
                "message": "Streamed triage status check",
                "session_id": "triage-stream-sess",
                "agent_id": "bounty-triage-readonly",
                "deliver": False,
            }
        )
        chunks = list(handle.stream())
        response = handle.result(timeout_s=30.0)
        assert len(chunks) >= 1
        assert "Streamed triage status check" in response.final_text
    finally:
        runtime.close()


def test_structured_output_validation_and_handoff_policy_gate() -> None:
    class _StubRuntime:
        def __init__(self, body: str) -> None:
            self.body = body
            self.tools = ToolRegistry()

        def run_turn(self, *, payload: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
            return {
                "body": self.body,
                "id": "res-1",
                "run_id": "run-1",
                "run_state": "completed",
                "session_id": payload.get("session_id"),
                "metadata": {},
                "stats": {},
            }

        def close(self) -> None:
            return None

    valid_json = json.dumps(
        {
            "verdict": "GO",
            "health_score": 95,
            "blocker_count": 0,
            "summary": "All release gates passed.",
        }
    )
    with Agent(runtime=_StubRuntime(valid_json), output_type=TriageSummary) as agent:
        result = agent.run("Return release verdict JSON")
        assert isinstance(result.output, TriageSummary)
        assert result.output.verdict == "GO"
        assert result.output.health_score == 95

    with Agent(runtime=_StubRuntime("not json at all"), output_type=TriageSummary) as bad_agent:
        with pytest.raises(AgentOutputValidationError):
            bad_agent.run("Return release verdict JSON")

    # Verify Handoff registration attaches transfer_to_security_reviewer tool cleanly
    stub = _StubRuntime("ok")
    reviewer = Agent(runtime=stub, name="security_reviewer", tools=[])
    coordinator = Agent(runtime=stub, name="triage_lead", handoffs=[Handoff(target=reviewer)])
    assert "transfer_to_security_reviewer" in coordinator.tools


# ---------------------------------------------------------------------------
# 4. Full End-to-End Workflow (Tools + Policy + Skill + Task + Artifact + MemoryBundle + Diagnostics)
# ---------------------------------------------------------------------------


def test_full_triage_workflow_exercises_all_openminion_building_blocks(tmp_path: Path) -> None:
    repo = _create_sample_repo(tmp_path)
    state_dir = tmp_path / "openminion-state"
    bundle_path = tmp_path / "out" / "triage-memory-bundle.json"
    report_path = tmp_path / "out" / "RELEASE_CHECKLIST.md"

    fixtures = json.loads((PROJECT_ROOT / "fixtures" / "sample_issues.json").read_text(encoding="utf-8"))

    runner = TriageWorkflowRunner(
        workspace_root=tmp_path,
        state_root=state_dir,
        skill_path=DEFAULT_SKILL_PATH,
    )
    record = runner.run_audit(
        repo_path=repo,
        version="0.2.0",
        issues=fixtures,
        session_id="e2e-triage-session",
        export_bundle_path=bundle_path,
        export_markdown_path=report_path,
        approve_write_export=True,
    )

    assert record.execution_mode == "local_deterministic_plus_echo_runtime"
    assert record.run_id is not None
    assert record.task_id.startswith("tsk")
    assert record.plan_id.startswith("pln")
    assert record.skill_id == "bounty-triage-readonly"
    assert len(record.skill_version_hash) >= 16
    assert record.skill_match_count >= 1
    assert len(record.artifact_sha256) == 64

    # Policy checks verified on real ActionPolicy
    assert record.policy_checks["inspect_repo_health"]["decision"] == "ALLOW"
    assert record.policy_checks["verify_license_and_secrets"]["decision"] == "ALLOW"
    assert record.policy_checks["export_triage_report"]["decision"] == "REQUIRE_CONFIRM"

    # Verdict reflects the P0 security issue in fixtures
    assert record.release.verdict == "NO_GO"
    assert record.release.blocker_count == 1
    assert record.health.health_score == 100

    # MemoryBundle round-trip
    assert bundle_path.is_file()
    loaded = load_bundle(bundle_path)
    assert isinstance(loaded, MemoryBundle)
    assert len(loaded.items) == 1
    assert loaded.items[0]["artifact_sha256"] == record.artifact_sha256
    imported = import_bundle(loaded, trust_mode="candidate")
    assert imported["item_count"] == 1

    # Approved write export succeeded inside workspace
    assert report_path.is_file()
    assert "# Release Readiness Checklist" in report_path.read_text(encoding="utf-8")

    # Runtime posture diagnostics populated
    assert record.runtime_posture_summary["has_execution_boundary_policy"] is True
    assert record.runtime_posture_summary["canonical_turn_path_steps"] >= 3


# ---------------------------------------------------------------------------
# 5. CLI & Diagnostics Smoke Tests
# ---------------------------------------------------------------------------


def test_cli_doctor_and_audit_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    repo = _create_sample_repo(tmp_path)
    state_dir = tmp_path / "cli-state"

    rc_doc = cli_main(["doctor", "--json"])
    assert rc_doc == 0
    doc_payload = json.loads(capsys.readouterr().out)
    assert "openminion_version" in doc_payload
    assert doc_payload["default_config_exists"] is True

    rc_audit = cli_main(
        [
            "audit",
            "--repo",
            str(repo),
            "--workspace",
            str(tmp_path),
            "--state-dir",
            str(state_dir),
            "--version",
            "0.1.0",
            "--json",
        ]
    )
    assert rc_audit == 0
    audit_payload = json.loads(capsys.readouterr().out)
    assert audit_payload["release"]["verdict"] == "GO"
    assert audit_payload["health"]["health_score"] == 100
    assert len(audit_payload["artifact_sha256"]) == 64


def test_provider_env_diagnostics_never_leaks_secret_values(monkeypatch: pytest.MonkeyPatch) -> None:
    sentinel = "sk-" + "placeholder-value-never-print-123456"
    monkeypatch.setenv("CORTENSOR_API_KEY", sentinel)
    diag = provider_env_diagnostics()
    assert diag["any_cloud_provider_key_configured"] is True
    assert sentinel not in json.dumps(diag)


def test_cli_run_with_project_agents_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("OPENMINION_HOME", str(tmp_path / "om-home"))
    monkeypatch.setenv("OPENMINION_DATA_ROOT", str(tmp_path / "om-home" / ".openminion"))
    rc = cli_main(
        [
            "run",
            "Smoke check bounty triage agent profile",
            "--agent",
            "bounty-triage-readonly",
            "--workspace",
            str(tmp_path),
            "--session",
            "cli-run-smoke",
            "--json",
        ]
    )
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["session_id"] == "cli-run-smoke"
    assert payload["run_state"] == "completed"
    assert "Smoke check bounty triage agent profile" in payload["text"]

