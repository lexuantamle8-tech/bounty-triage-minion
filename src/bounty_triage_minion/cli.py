"""Command-line interface for BountyTriage Minion."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Sequence

from openminion import __version__ as OPENMINION_VERSION

from . import __version__
from .runtime import (
    DEFAULT_CONFIG_PATH,
    TriageWorkflowRunner,
    provider_env_diagnostics,
    run_provider_agent,
)


def _cmd_audit(args: argparse.Namespace) -> int:
    repo_path = Path(args.repo).expanduser().resolve()
    workspace_root = (
        Path(args.workspace).expanduser().resolve()
        if args.workspace
        else repo_path.parent
    )
    state_root = (
        Path(args.state_dir).expanduser().resolve()
        if args.state_dir
        else (Path.cwd() / ".bounty-triage-state").resolve()
    )

    issues: list[dict[str, object]] = []
    if args.issues:
        issues_path = Path(args.issues).expanduser().resolve()
        raw = json.loads(issues_path.read_text(encoding="utf-8"))
        if not isinstance(raw, list):
            print("Error: --issues file must contain a JSON array.", file=sys.stderr)
            return 2
        issues = raw

    export_bundle_path = (
        Path(args.export_bundle).expanduser().resolve() if args.export_bundle else None
    )
    export_md_path = (
        Path(args.export_markdown).expanduser().resolve()
        if args.export_markdown
        else None
    )

    runner = TriageWorkflowRunner(
        workspace_root=workspace_root,
        state_root=state_root,
    )
    record = runner.run_audit(
        repo_path=repo_path,
        version=args.version,
        issues=issues,
        session_id=args.session,
        export_bundle_path=export_bundle_path,
        export_markdown_path=export_md_path,
        approve_write_export=bool(args.approve_write),
    )

    if args.json:
        print(json.dumps(record.to_dict(), indent=2, ensure_ascii=True))
    else:
        print(record.release.checklist_markdown)
        print()
        print("--- OpenMinion 0.1 Runtime Proof ---")
        print(f"Execution mode : {record.execution_mode}")
        print(f"OpenMinion SDK : {record.openminion_version}")
        print(f"Session / Run  : {record.session_id} / {record.run_id}")
        print(f"Task / Plan    : {record.task_id} / {record.plan_id}")
        print(
            f"Skill Admitted : {record.skill_id} ({record.skill_version_hash[:12]}..., matches={record.skill_match_count})"
        )
        print(f"Artifact SHA256: {record.artifact_sha256}")
        if record.memory_bundle_path:
            print(f"MemoryBundle   : {record.memory_bundle_path}")
        if record.exported_report_path:
            print(f"Markdown Export: {record.exported_report_path}")
        elif export_md_path is not None:
            print("Markdown Export: skipped (policy gate requires --approve-write)")
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    config_path = (
        Path(args.config).expanduser().resolve()
        if args.config
        else DEFAULT_CONFIG_PATH
    )
    workspace_root = (
        Path(args.workspace).expanduser().resolve()
        if args.workspace
        else Path.cwd().resolve()
    )
    result = run_provider_agent(
        prompt=args.prompt,
        config_path=config_path,
        agent_id=args.agent,
        session_id=args.session,
        workspace_root=workspace_root,
        timeout_seconds=args.timeout,
    )
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=True))
    elif result.get("ok"):
        print(result["text"])
        print(
            f"\n[session={result.get('session_id')} run={result.get('run_id')} state={result.get('run_state')}]"
        )
    else:
        print(
            f"{result.get('error_type')}: {result.get('code', '')} {result.get('message')}",
            file=sys.stderr,
        )
        if result.get("hint"):
            print(f"Hint: {result['hint']}", file=sys.stderr)
        return 1
    return 0


def _cmd_doctor(args: argparse.Namespace) -> int:
    diag = provider_env_diagnostics()
    diag["bounty_triage_version"] = __version__
    diag["default_config_path"] = str(DEFAULT_CONFIG_PATH)
    diag["default_config_exists"] = DEFAULT_CONFIG_PATH.is_file()
    if args.json:
        print(json.dumps(diag, indent=2, ensure_ascii=True))
    else:
        print(
            f"BountyTriage Minion {__version__} (OpenMinion {OPENMINION_VERSION})"
        )
        print(f"Default config : {DEFAULT_CONFIG_PATH}")
        print(
            f"Live LLM ready : {'YES' if diag['live_model_turn_ready'] else 'NO (local deterministic/demo mode only until an API key or Ollama is configured)'}"
        )
        print("\nProvider credential status (boolean only; values never read/printed):")
        for item in diag["providers"]:
            status = "SET" if item["configured"] else "UNSET"
            print(
                f"  - {item['preset_id']:18s} {item['credential_env']:20s} [{status}] ({item['label']})"
            )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bounty-triage",
        description="Local-first GitHub Issue/PR Triage & Release Readiness Agent on OpenMinion 0.1",
    )
    parser.add_argument(
        "--version", action="version", version=f"bounty-triage {__version__}"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    audit = sub.add_parser(
        "audit",
        help="Run repeatable local-first repo health, license/secret scan, issue triage, and release checklist",
    )
    audit.add_argument("--repo", default=".", help="Path to target local repository")
    audit.add_argument(
        "--workspace",
        default=None,
        help="Approved workspace confinement root (defaults to parent of --repo)",
    )
    audit.add_argument(
        "--state-dir",
        default=None,
        help="Directory for isolated OpenMinion SQLite/artifact/skill state",
    )
    audit.add_argument(
        "--issues",
        default=None,
        help="Optional path to JSON array of open issues/bounties to score",
    )
    audit.add_argument("--version", default="0.1.0", help="Target release version")
    audit.add_argument(
        "--session", default="bounty-triage-session", help="OpenMinion session ID"
    )
    audit.add_argument(
        "--export-bundle",
        default=None,
        help="Optional path to export a portable OpenMinion MemoryBundle JSON",
    )
    audit.add_argument(
        "--export-markdown",
        default=None,
        help="Optional path (inside workspace) to write the Markdown checklist",
    )
    audit.add_argument(
        "--approve-write",
        action="store_true",
        help="Explicit operator confirmation required for --export-markdown (WRITE_SAFE policy gate)",
    )
    audit.add_argument("--json", action="store_true", help="Emit JSON output")
    audit.set_defaults(func=_cmd_audit)

    run_cmd = sub.add_parser(
        "run",
        help="Run a provider-neutral OpenMinion Agent turn with read-only triage tools registered",
    )
    run_cmd.add_argument("prompt", help="Prompt to send to the configured OpenMinion agent")
    run_cmd.add_argument("--config", default=None, help="Path to agents.json")
    run_cmd.add_argument(
        "--agent",
        default=None,
        help="Configured agent profile (e.g. bounty-triage-readonly or bounty-triage-cortensor)",
    )
    run_cmd.add_argument("--workspace", default=None, help="Approved workspace root")
    run_cmd.add_argument("--session", default="bounty-triage-agent", help="Session ID")
    run_cmd.add_argument("--timeout", type=float, default=120.0, help="Turn timeout (seconds)")
    run_cmd.add_argument("--json", action="store_true", help="Emit JSON output")
    run_cmd.set_defaults(func=_cmd_run)

    doctor = sub.add_parser(
        "doctor",
        help="Inspect OpenMinion SDK version, config status, and provider credential readiness",
    )
    doctor.add_argument("--json", action="store_true", help="Emit JSON output")
    doctor.set_defaults(func=_cmd_doctor)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
