"""Typed Pydantic models for BountyTriage Minion tool outputs and structured Agent replies."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class RepoHealthReport(BaseModel):
    """Structured repository health assessment."""

    repo_path: str
    is_git_repo: bool
    git_branch: str | None = None
    git_dirty: bool | None = None
    has_readme: bool
    has_license: bool
    has_tests: bool
    has_ci: bool
    has_manifest: bool
    has_changelog: bool
    has_security_policy: bool
    source_file_count: int
    test_file_count: int
    health_score: int = Field(ge=0, le=100)
    findings: list[str] = Field(default_factory=list)


class IssueTriageScore(BaseModel):
    """Deterministic triage score for a single issue, PR, or bounty submission."""

    issue_title: str
    priority: Literal["P0", "P1", "P2", "P3"]
    category: Literal["security", "bug", "feature", "docs", "chore"]
    effort_tier: Literal["S", "M", "L", "XL"]
    completeness_score: int = Field(ge=0, le=100)
    recommended_action: Literal[
        "escalate_security", "accept", "needs_info", "backlog"
    ]
    suggested_labels: list[str] = Field(default_factory=list)
    missing_signals: list[str] = Field(default_factory=list)
    rationale: str


class SecretMatch(BaseModel):
    """Redacted secret or credential hygiene finding."""

    file: str
    line: int
    rule: str
    redacted_match: str


class LicenseSecretsReport(BaseModel):
    """License and secret hygiene scan output."""

    repo_path: str
    license_detected: bool
    spdx_guess: str
    scanned_files: int
    committed_env_files: list[str] = Field(default_factory=list)
    secret_findings: list[SecretMatch] = Field(default_factory=list)
    status: Literal["pass", "warn", "fail"]


class ReleaseReadinessReport(BaseModel):
    """Combined release-readiness decision and Markdown checklist."""

    repo_path: str
    version: str
    verdict: Literal["GO", "CONDITIONAL_GO", "NO_GO"]
    health_score: int = Field(ge=0, le=100)
    license_status: Literal["pass", "warn", "fail"]
    blocker_count: int
    warning_count: int
    blockers: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    triage_scores: list[IssueTriageScore] = Field(default_factory=list)
    checklist_markdown: str


class TriageSummary(BaseModel):
    """Structured Pydantic output model for `Agent(..., output_type=TriageSummary)`."""

    verdict: Literal["GO", "CONDITIONAL_GO", "NO_GO"]
    health_score: int = Field(ge=0, le=100)
    blocker_count: int = Field(ge=0)
    summary: str
