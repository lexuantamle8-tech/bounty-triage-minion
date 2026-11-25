---
id: bounty-triage-readonly
name: BountyTriage Readonly Auditor
version: 0.1.0
description: Run repeatable local-first repository health checks, issue triage scoring, license/secret hygiene scans, and release-readiness checklists within a read-only workspace boundary.
tags: [triage, release-readiness, bounty, readonly, github]
tools:
  - inspect_repo_health
  - score_issue_triage
  - verify_license_and_secrets
  - generate_release_checklist
risk: low
verification:
  - All inspection tools execute with READ_ONLY scope inside the approved workspace root.
  - Secret scanner findings are redacted before output or persistence.
  - Release readiness verdict cites concrete repo health, hygiene, and issue blockers.
rollback:
  - Remove the bounty-triage-readonly skill binding or roll back to the prior active version hash via `openminion skill rollback`.
---

# Purpose

Deliver a repeatable, inspectable triage and release-readiness assessment for a local repository and issue queue without modifying repository files or requiring write permissions.

# Procedure

1. Confirm the target repository path is inside the approved workspace root.
2. Call `inspect_repo_health` to collect git state, documentation/test/CI coverage, and baseline health score.
3. Call `verify_license_and_secrets` to confirm SPDX license presence and ensure no committed `.env` files, private keys, or API tokens exist.
4. For each open issue or bounty submission, call `score_issue_triage` to assign priority (`P0`-`P3`), category, effort tier, completeness score, and triage action.
5. Call `generate_release_checklist` with the target version and issue list to compute the `GO`, `CONDITIONAL_GO`, or `NO_GO` release verdict and sign-off checklist.
6. Only if the operator explicitly requests writing a Markdown report to disk, invoke `export_triage_report` and wait for operator confirmation (`allow_once`).

# Checks

1. Every finding references an inspectable local path, line number, or issue title.
2. No raw secret strings appear in logs, tool results, artifacts, or memory bundles.
3. Demo/offline runs explicitly report their execution mode (`demo`/`deterministic-harness` vs live provider).

# Failure & Recovery

1. If a path escapes the workspace root, stop immediately and report the workspace confinement denial.
2. If an external provider returns `ProviderError` or `TurnTimeoutError`, fall back to reporting the exact provider error code and suggest running `openminion doctor --check-turn --json`.
3. If `export_triage_report` is denied by the operator, return the checklist in-memory without writing to disk.
