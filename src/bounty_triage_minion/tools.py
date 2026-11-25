"""OpenMinion 0.1 structured tools with workspace confinement and redaction guards."""

from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any, Iterator

from openminion import tool

from .models import (
    IssueTriageScore,
    LicenseSecretsReport,
    ReleaseReadinessReport,
    RepoHealthReport,
    SecretMatch,
)

_WORKSPACE_ROOT_ENV = "BOUNTY_TRIAGE_WORKSPACE_ROOT"
_ACTIVE_WORKSPACE_ROOT: Path | None = None

_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "dist",
    "build",
    ".openminion",
}

_SOURCE_EXTENSIONS = {
    ".py",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".rs",
    ".go",
    ".java",
    ".kt",
    ".sol",
    ".c",
    ".cpp",
    ".h",
}

_BINARY_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".ico",
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
    ".whl",
    ".pyc",
    ".pyo",
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".db",
    ".sqlite",
    ".sqlite3",
}

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b")),
    ("github_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b")),
    ("private_key_header", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    (
        "generic_api_key",
        re.compile(r"\b(?:sk-[A-Za-z0-9_-]{20,}|sk-proj-[A-Za-z0-9_-]{20,})\b"),
    ),
)

_PLACEHOLDER_MARKERS = (
    "example",
    "dummy",
    "placeholder",
    "redacted",
    "your_api_key",
    "fake_key",
    "test_key",
    "xxxx",
)


def get_workspace_root() -> Path:
    """Return the active workspace root used for path confinement."""
    if _ACTIVE_WORKSPACE_ROOT is not None:
        return _ACTIVE_WORKSPACE_ROOT
    env_root = os.environ.get(_WORKSPACE_ROOT_ENV, "").strip()
    if env_root:
        return Path(env_root).expanduser().resolve()
    return Path.cwd().resolve()


@contextmanager
def set_workspace_root(root: str | Path) -> Iterator[Path]:
    """Temporarily bind the workspace confinement root for tool calls."""
    global _ACTIVE_WORKSPACE_ROOT
    previous = _ACTIVE_WORKSPACE_ROOT
    resolved = Path(root).expanduser().resolve()
    _ACTIVE_WORKSPACE_ROOT = resolved
    try:
        yield resolved
    finally:
        _ACTIVE_WORKSPACE_ROOT = previous


def _resolve_confined_path(raw_path: str, *, must_exist: bool = True) -> Path:
    """Resolve ``raw_path`` and assert it remains inside the workspace root."""
    workspace = get_workspace_root()
    candidate = Path(raw_path).expanduser()
    if not candidate.is_absolute():
        candidate = workspace / candidate
    resolved = candidate.resolve(strict=False)
    try:
        resolved.relative_to(workspace)
    except ValueError as exc:
        raise ValueError(
            f"Workspace guard denied path {raw_path!r}: resolves outside "
            f"approved workspace root {str(workspace)!r}"
        ) from exc
    if must_exist and not resolved.exists():
        raise FileNotFoundError(f"Path does not exist inside workspace: {resolved}")
    return resolved


def _redact_secret(raw: str) -> str:
    cleaned = raw.strip()
    if "PRIVATE KEY" in cleaned:
        return "-----BEGIN [REDACTED] PRIVATE KEY-----"
    if len(cleaned) <= 8:
        return "[REDACTED]"
    return f"{cleaned[:4]}...{cleaned[-2:]}"


def _run_git(repo: Path, args: list[str]) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip()


def _iter_repo_files(repo: Path, *, max_files: int = 500) -> list[Path]:
    collected: list[Path] = []
    for root, dirs, files in os.walk(repo):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)
        for filename in sorted(files):
            collected.append(Path(root) / filename)
            if len(collected) >= max_files:
                return collected
    return collected


def _detect_spdx(license_path: Path | None) -> str:
    if license_path is None or not license_path.is_file():
        return "NONE"
    text = license_path.read_text(encoding="utf-8", errors="ignore")[:4000]
    upper = text.upper()
    if "APACHE LICENSE" in upper and "2.0" in upper:
        return "Apache-2.0"
    if "MIT LICENSE" in upper or "PERMISSION IS HEREBY GRANTED, FREE OF CHARGE" in upper:
        return "MIT"
    if "GNU GENERAL PUBLIC LICENSE" in upper:
        return "GPL-3.0" if "VERSION 3" in upper else "GPL"
    if "BSD 3-CLAUSE" in upper or "REDISTRIBUTION AND USE IN SOURCE AND BINARY FORMS" in upper:
        return "BSD-3-Clause"
    if "MOZILLA PUBLIC LICENSE" in upper:
        return "MPL-2.0"
    return "CUSTOM-OR-UNKNOWN"


@tool(
    name="inspect_repo_health",
    min_scope="READ_ONLY",
    idempotent=True,
    tags=("triage", "repo", "readonly"),
)
def inspect_repo_health(repo_path: str = ".") -> dict[str, Any]:
    """Inspect a local repository within the workspace root and return a health score and findings."""
    repo = _resolve_confined_path(repo_path, must_exist=True)
    if not repo.is_dir():
        raise ValueError(f"repo_path must be a directory, got: {repo}")

    top_names = {p.name.lower(): p for p in repo.iterdir()}
    has_readme = any(name.startswith("readme") for name in top_names)
    has_license = any(
        name.startswith("license") or name.startswith("copying") for name in top_names
    )
    has_manifest = any(
        name in top_names
        for name in ("pyproject.toml", "setup.py", "package.json", "cargo.toml", "go.mod")
    )
    has_changelog = any(name.startswith("changelog") for name in top_names)
    has_security_policy = "security.md" in top_names or (
        repo / ".github" / "SECURITY.md"
    ).is_file()

    workflows_dir = repo / ".github" / "workflows"
    has_ci = workflows_dir.is_dir() and any(
        p.suffix.lower() in {".yml", ".yaml"} for p in workflows_dir.iterdir()
    )

    files = _iter_repo_files(repo, max_files=600)
    source_count = 0
    test_count = 0
    for file_path in files:
        rel_parts = [part.lower() for part in file_path.relative_to(repo).parts]
        name_lower = file_path.name.lower()
        is_test = (
            "tests" in rel_parts
            or "test" in rel_parts
            or name_lower.startswith("test_")
            or name_lower.endswith("_test.py")
            or ".test." in name_lower
            or ".spec." in name_lower
        )
        if is_test and file_path.suffix.lower() in _SOURCE_EXTENSIONS:
            test_count += 1
        elif file_path.suffix.lower() in _SOURCE_EXTENSIONS:
            source_count += 1

    has_tests = test_count > 0 or (repo / "tests").is_dir() or (repo / "test").is_dir()

    git_branch = _run_git(repo, ["rev-parse", "--abbrev-ref", "HEAD"])
    is_git_repo = git_branch is not None
    git_dirty: bool | None = None
    if is_git_repo:
        porcelain = _run_git(repo, ["status", "--porcelain"])
        git_dirty = bool(porcelain)

    score = 0
    findings: list[str] = []
    checks = (
        (has_readme, 20, "Missing README file at repository root."),
        (has_license, 20, "Missing LICENSE file at repository root."),
        (has_tests, 25, "No automated tests detected (`tests/` or `test_*` files)."),
        (has_manifest, 15, "No package manifest found (pyproject.toml/package.json/etc.)."),
        (has_ci, 10, "No GitHub Actions CI workflow detected in `.github/workflows/`."),
        (has_security_policy, 5, "No SECURITY.md vulnerability reporting policy found."),
        (has_changelog, 5, "No CHANGELOG file found."),
    )
    for passed, weight, missing_msg in checks:
        if passed:
            score += weight
        else:
            findings.append(missing_msg)

    if git_dirty:
        findings.append("Working tree has uncommitted changes (`git status --porcelain` non-empty).")
    if source_count > 0 and test_count == 0:
        findings.append(f"Found {source_count} source files but 0 test files.")

    report = RepoHealthReport(
        repo_path=str(repo),
        is_git_repo=is_git_repo,
        git_branch=git_branch,
        git_dirty=git_dirty,
        has_readme=has_readme,
        has_license=has_license,
        has_tests=has_tests,
        has_ci=has_ci,
        has_manifest=has_manifest,
        has_changelog=has_changelog,
        has_security_policy=has_security_policy,
        source_file_count=source_count,
        test_file_count=test_count,
        health_score=score,
        findings=findings,
    )
    return report.model_dump()


@tool(
    name="score_issue_triage",
    min_scope="READ_ONLY",
    idempotent=True,
    tags=("triage", "issues", "readonly"),
)
def score_issue_triage(
    issue_title: str,
    issue_body: str,
    labels: list[str] | None = None,
    has_repro: bool = False,
    is_security: bool = False,
) -> dict[str, Any]:
    """Score a GitHub issue, PR, or bounty report with priority, category, completeness, and triage action."""
    title_clean = issue_title.strip()
    body_clean = issue_body.strip()
    lower_labels = [lbl.strip().lower() for lbl in (labels or []) if lbl.strip()]
    combined = f"{title_clean}\n{body_clean}".lower()

    security_keywords = (
        "security:",
        "vulnerability",
        "cve-",
        "rce",
        "path traversal",
        "auth bypass",
        "bypass",
        "sql injection",
        "command injection",
        "xss",
        "csrf",
        "secret leak",
        "leaked secret",
        "credential leak",
        "privilege escalation",
    )
    bug_keywords = (
        "crash",
        "traceback",
        "exception",
        "error",
        "bug",
        "fails",
        "broken",
        "regression",
        "hang",
        "timeout",
    )
    docs_keywords = ("docs", "documentation", "readme", "typo", "example")

    detected_security = (
        is_security
        or "security" in lower_labels
        or any(word in combined for word in security_keywords)
    )
    if detected_security:
        category = "security"
    elif "bug" in lower_labels or any(word in combined for word in bug_keywords):
        category = "bug"
    elif "documentation" in lower_labels or "docs" in lower_labels or any(
        word in combined for word in docs_keywords
    ):
        category = "docs"
    elif "enhancement" in lower_labels or "feature" in lower_labels or "add " in title_clean.lower():
        category = "feature"
    else:
        category = "chore"

    missing_signals: list[str] = []
    completeness = 20 if len(title_clean) >= 12 else 5
    if len(title_clean) < 12:
        missing_signals.append("descriptive_title")

    if len(body_clean) >= 60:
        completeness += 25
    else:
        missing_signals.append("detailed_description")

    mentions_repro = has_repro or any(
        token in combined for token in ("steps to reproduce", "repro", "reproduce", "1.")
    )
    if mentions_repro:
        completeness += 25
    elif category in {"security", "bug"}:
        missing_signals.append("reproduction_steps")

    mentions_expected_actual = "expected" in combined and "actual" in combined
    if mentions_expected_actual:
        completeness += 20
    elif category in {"security", "bug"}:
        missing_signals.append("expected_vs_actual")

    mentions_env = any(
        token in combined
        for token in ("version", "windows", "linux", "macos", "python", "traceback", "os")
    )
    if mentions_env:
        completeness += 10
    elif category in {"security", "bug"}:
        missing_signals.append("environment_or_version")

    completeness = min(100, completeness)

    if category == "security":
        priority = "P0"
        recommended_action = "escalate_security"
        effort_tier = "L"
    elif category == "bug" and any(
        word in combined for word in ("crash", "data loss", "regression", "deadlock", "unicodeencodeerror")
    ):
        priority = "P1"
        recommended_action = "accept" if completeness >= 60 else "needs_info"
        effort_tier = "M"
    elif category == "bug":
        priority = "P2"
        recommended_action = "accept" if completeness >= 55 else "needs_info"
        effort_tier = "S" if len(body_clean) < 250 else "M"
    elif category == "feature":
        priority = "P2" if completeness >= 50 else "P3"
        recommended_action = "accept" if completeness >= 45 else "backlog"
        effort_tier = "L" if any(w in combined for w in ("pipeline", "sarif", "protocol", "architecture")) else "M"
    else:
        priority = "P3"
        recommended_action = "needs_info" if completeness < 40 else "backlog"
        effort_tier = "S"

    suggested_labels = sorted(
        set(
            lower_labels
            + [
                f"priority:{priority}",
                f"type:{category}",
                f"effort:{effort_tier}",
            ]
            + (["needs-info"] if recommended_action == "needs_info" else [])
            + (["security-escalation"] if recommended_action == "escalate_security" else [])
        )
    )

    rationale = (
        f"Classified as {category} ({priority}, effort {effort_tier}) with "
        f"completeness {completeness}/100; recommended action: {recommended_action}."
    )

    score = IssueTriageScore(
        issue_title=title_clean,
        priority=priority,
        category=category,
        effort_tier=effort_tier,
        completeness_score=completeness,
        recommended_action=recommended_action,
        suggested_labels=suggested_labels,
        missing_signals=missing_signals,
        rationale=rationale,
    )
    return score.model_dump()


@tool(
    name="verify_license_and_secrets",
    min_scope="READ_ONLY",
    idempotent=True,
    tags=("triage", "security", "hygiene", "readonly"),
)
def verify_license_and_secrets(repo_path: str = ".", max_files: int = 200) -> dict[str, Any]:
    """Verify SPDX license presence and scan repository files for committed .env files or leaked secrets."""
    repo = _resolve_confined_path(repo_path, must_exist=True)
    if not repo.is_dir():
        raise ValueError(f"repo_path must be a directory, got: {repo}")

    license_file: Path | None = None
    for child in repo.iterdir():
        if child.is_file() and (
            child.name.lower().startswith("license")
            or child.name.lower().startswith("copying")
        ):
            license_file = child
            break

    spdx_guess = _detect_spdx(license_file)
    license_detected = license_file is not None

    files = _iter_repo_files(repo, max_files=max(1, min(max_files, 1000)))
    committed_env_files: list[str] = []
    secret_findings: list[SecretMatch] = []
    scanned = 0

    for file_path in files:
        rel = file_path.relative_to(repo).as_posix()
        name_lower = file_path.name.lower()
        if name_lower == ".env" or (
            name_lower.startswith(".env.")
            and not name_lower.endswith((".example", ".sample", ".template"))
        ):
            committed_env_files.append(rel)

        if file_path.suffix.lower() in _BINARY_EXTENSIONS:
            continue
        try:
            if file_path.stat().st_size > 512_000:
                continue
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        scanned += 1
        for line_no, line in enumerate(text.splitlines(), start=1):
            lower_line = line.lower()
            if any(marker in lower_line for marker in _PLACEHOLDER_MARKERS):
                continue
            for rule_name, pattern in _SECRET_PATTERNS:
                match = pattern.search(line)
                if match:
                    secret_findings.append(
                        SecretMatch(
                            file=rel,
                            line=line_no,
                            rule=rule_name,
                            redacted_match=_redact_secret(match.group(0)),
                        )
                    )

    if secret_findings or committed_env_files:
        status = "fail"
    elif not license_detected:
        status = "warn"
    else:
        status = "pass"

    report = LicenseSecretsReport(
        repo_path=str(repo),
        license_detected=license_detected,
        spdx_guess=spdx_guess,
        scanned_files=scanned,
        committed_env_files=committed_env_files,
        secret_findings=secret_findings,
        status=status,
    )
    return report.model_dump()


@tool(
    name="generate_release_checklist",
    min_scope="READ_ONLY",
    idempotent=True,
    tags=("triage", "release", "readonly"),
)
def generate_release_checklist(
    repo_path: str = ".",
    version: str = "0.1.0",
    open_issues_json: str = "[]",
) -> dict[str, Any]:
    """Combine repo health, license/secret hygiene, and open issue triage into a GO/CONDITIONAL_GO/NO_GO release checklist."""
    health = RepoHealthReport.model_validate(inspect_repo_health(repo_path=repo_path))
    hygiene = LicenseSecretsReport.model_validate(
        verify_license_and_secrets(repo_path=repo_path)
    )

    try:
        raw_issues = json.loads(open_issues_json) if open_issues_json.strip() else []
    except json.JSONDecodeError as exc:
        raise ValueError(f"open_issues_json must be valid JSON array: {exc}") from exc
    if not isinstance(raw_issues, list):
        raise ValueError("open_issues_json must decode to a JSON array of issues")

    triage_scores: list[IssueTriageScore] = []
    for item in raw_issues:
        if not isinstance(item, dict):
            continue
        scored = score_issue_triage(
            issue_title=str(item.get("title", "")),
            issue_body=str(item.get("body", "")),
            labels=list(item.get("labels") or []),
            has_repro=bool(item.get("has_repro", False)),
            is_security=bool(item.get("is_security", False)),
        )
        triage_scores.append(IssueTriageScore.model_validate(scored))

    blockers: list[str] = []
    warnings: list[str] = []

    if hygiene.secret_findings:
        blockers.append(
            f"Secret hygiene scan detected {len(hygiene.secret_findings)} potential credential leak(s)."
        )
    if hygiene.committed_env_files:
        blockers.append(
            f"Committed environment file(s) found: {', '.join(hygiene.committed_env_files)}."
        )
    if not health.has_tests:
        blockers.append("No automated tests detected in repository.")

    for score in triage_scores:
        if score.priority == "P0":
            blockers.append(
                f"P0 security blocker: {score.issue_title} ({score.recommended_action})."
            )
        elif score.priority == "P1":
            warnings.append(
                f"P1 open bug: {score.issue_title} ({score.recommended_action})."
            )

    if not hygiene.license_detected:
        warnings.append("Missing LICENSE file (SPDX license unknown).")
    if not health.has_ci:
        warnings.append("No CI workflow detected under `.github/workflows/`.")
    if health.git_dirty:
        warnings.append("Repository has uncommitted working-tree changes.")

    if blockers:
        verdict = "NO_GO"
    elif warnings or health.health_score < 80:
        verdict = "CONDITIONAL_GO"
    else:
        verdict = "GO"

    lines = [
        f"# Release Readiness Checklist — v{version}",
        "",
        f"- **Repository:** `{health.repo_path}`",
        f"- **Verdict:** `{verdict}`",
        f"- **Repo Health Score:** `{health.health_score}/100`",
        f"- **License / Secrets Hygiene:** `{hygiene.status}` (SPDX: `{hygiene.spdx_guess}`, scanned: `{hygiene.scanned_files}` files)",
        f"- **Open Issues Scored:** `{len(triage_scores)}`",
        "",
        "## Gate Checks",
        f"- [{'x' if health.has_readme else ' '}] README present",
        f"- [{'x' if hygiene.license_detected else ' '}] License present (`{hygiene.spdx_guess}`)",
        f"- [{'x' if health.has_tests else ' '}] Automated tests present ({health.test_file_count} test files)",
        f"- [{'x' if health.has_ci else ' '}] CI workflow present",
        f"- [{'x' if not hygiene.secret_findings and not hygiene.committed_env_files else ' '}] Zero leaked secrets or committed `.env` files",
        f"- [{'x' if not any(s.priority == 'P0' for s in triage_scores) else ' '}] Zero P0 security blockers",
    ]
    if blockers:
        lines.extend(["", "## Blockers"])
        lines.extend(f"- {b}" for b in blockers)
    if warnings:
        lines.extend(["", "## Warnings"])
        lines.extend(f"- {w}" for w in warnings)
    if triage_scores:
        lines.extend(["", "## Issue Triage Breakdown"])
        for score in triage_scores:
            lines.append(
                f"- **[{score.priority}]** `{score.category}` ({score.effort_tier}, completeness {score.completeness_score}/100) — {score.issue_title} -> `{score.recommended_action}`"
            )

    report = ReleaseReadinessReport(
        repo_path=health.repo_path,
        version=version,
        verdict=verdict,
        health_score=health.health_score,
        license_status=hygiene.status,
        blocker_count=len(blockers),
        warning_count=len(warnings),
        blockers=blockers,
        warnings=warnings,
        triage_scores=triage_scores,
        checklist_markdown="\n".join(lines),
    )
    return report.model_dump()


@tool(
    name="export_triage_report",
    min_scope="WRITE_SAFE",
    idempotent=False,
    tags=("triage", "export", "write"),
)
def export_triage_report(output_path: str, report_markdown: str) -> dict[str, Any]:
    """Write a generated triage Markdown report inside the approved workspace root (policy-gated WRITE_SAFE)."""
    target = _resolve_confined_path(output_path, must_exist=False)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(report_markdown, encoding="utf-8")
    return {
        "written": True,
        "path": str(target),
        "bytes": len(report_markdown.encode("utf-8")),
    }


READONLY_TRIAGE_TOOLS = [
    inspect_repo_health,
    score_issue_triage,
    verify_license_and_secrets,
    generate_release_checklist,
]

ALL_TRIAGE_TOOLS = [
    *READONLY_TRIAGE_TOOLS,
    export_triage_report,
]
