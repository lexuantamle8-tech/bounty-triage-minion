# BountyTriage Minion

**A repeatable, local-first GitHub Issue & PR Triage / Release Readiness Agent built on the OpenMinion 0.1 Python SDK (`openminion==0.1.24`).**

Built for **Cortensor Hackathon #5** to test OpenMinion 0.1's real runtime building blocks end-to-end under strict local-first, read-only-by-default governance.

---

## Execution & Honesty Boundary

Following OpenMinion's own brand and proof discipline, this repository **never fakes a live LLM run**:

- **What runs locally with zero API keys (verified by `pytest -v` and `bounty-triage audit`):**
  - OpenMinion `0.1.24` real runtime (`APIRuntime`, `Agent`, `ToolRegistry`, `ActionPolicy`, `Skill`, `SqlTaskCtl`, `ArtifactCtl`, `MemoryBundle`, `list_runs`, `runtime_posture`) backed by isolated SQLite databases.
  - All 4 read-only triage tools (`inspect_repo_health`, `score_issue_triage`, `verify_license_and_secrets`, `generate_release_checklist`) and 1 policy-gated write tool (`export_triage_report`) with real workspace confinement and secret redaction.
  - Demo/echo provider turns (`bounty-triage-readonly` profile) that exercise OpenMinion's real ingress, session continuity, run ledger, and `TurnChunk` streaming without external model calls.
- **What requires a live LLM provider credential:**
  - Model-driven tool selection and natural-language synthesis via `bounty-triage run --agent bounty-triage-cortensor` require setting **`CORTENSOR_API_KEY`** (or `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `GEMINI_API_KEY` / local `ollama`).
  - No application code changes are required to switch from `bounty-triage-readonly` (`echo`) to `bounty-triage-cortensor` (`https://api.cortensor.app/v1`, `oss-20b`) or `bounty-triage-ollama`.

---

## Problem & Repeatable Workflow

Open-source maintainers and hackathon/bounty operators run the same high-stakes checklist before every release or bounty payout:

1. **Repo Health Audit** — Are README, LICENSE, automated tests, CI workflows, package manifest, `SECURITY.md`, and `CHANGELOG.md` present? Is the git working tree clean?
2. **License & Secret Hygiene** — Which SPDX license is present? Were any `.env` files, private key headers, AWS keys, GitHub PATs, or API tokens accidentally committed?
3. **Deterministic Issue / Bounty Triage** — Which open issues are `P0` security blockers vs `P1` crashes vs vague reports needing reproduction steps (`needs-info`)?
4. **Inspectable Release Verdict** — Produce a reproducible `GO`, `CONDITIONAL_GO`, or `NO_GO` checklist backed by immutable SHA-256 artifacts, durable task plans, and portable memory bundles—**without** giving an unconstrained agent shell execution or arbitrary filesystem write access.

**BountyTriage Minion** turns that workflow into a single repeatable OpenMinion pipeline with read-only defaults, workspace path confinement, secret redaction, and explicit operator confirmation before any write export.

---

## Architecture

```text
bounty-triage CLI (audit | run | doctor)
        │
        ▼
TriageWorkflowRunner / run_provider_agent (src/bounty_triage_minion/runtime.py)
  ├── OpenMinion APIRuntime + Agent (SQLite sessions, runs, TurnChunk streaming)
  ├── OpenMinion ToolRegistry + @tool (Pydantic extra="forbid" schemas)
  │     ├── [READ_ONLY]  inspect_repo_health        ──► ALLOW (ActionPolicy)
  │     ├── [READ_ONLY]  score_issue_triage         ──► ALLOW (ActionPolicy)
  │     ├── [READ_ONLY]  verify_license_and_secrets ──► ALLOW (ActionPolicy)
  │     ├── [READ_ONLY]  generate_release_checklist ──► ALLOW (ActionPolicy)
  │     └── [WRITE_SAFE] export_triage_report       ──► REQUIRE_CONFIRM (ActionPolicy)
  ├── OpenMinion Skill store (skills/bounty-triage-readonly/SKILL.md: ingest → admit → match)
  ├── OpenMinion SqlTaskCtl (durable multi-step audit plan & step transitions)
  ├── OpenMinion ArtifactCtl (immutable SHA-256 CAS release checklist JSON)
  └── OpenMinion MemoryBundle (portable snapshot export / load / candidate import)
```

### Repository Layout

| Path | Purpose |
| --- | --- |
| `src/bounty_triage_minion/tools.py` | 5 structured OpenMinion `@tool` functions with workspace confinement and secret redaction |
| `src/bounty_triage_minion/models.py` | Pydantic v2 contracts (`RepoHealthReport`, `IssueTriageScore`, `LicenseSecretsReport`, `ReleaseReadinessReport`, `TriageSummary`) |
| `src/bounty_triage_minion/runtime.py` | Real OpenMinion 0.1 subsystem orchestration (`APIRuntime`, `Agent`, `ActionPolicy`, `Skill`, `SqlTaskCtl`, `ArtifactCtl`, `MemoryBundle`) |
| `src/bounty_triage_minion/cli.py` | `bounty-triage` CLI (`audit`, `run`, `doctor`) |
| `AGENT.md` | Agent mission, constraints, tool preferences, and escalation policy |
| `skills/bounty-triage-readonly/SKILL.md` | Verifiable OpenMinion skill ingested, admitted, and matched in SQLite |
| `config/agents.json` | Provider-neutral profiles (`bounty-triage-readonly`, `bounty-triage-cortensor`, `bounty-triage-ollama`) |
| `fixtures/sample_issues.json` | Reproducible issue/bounty queue fixture (P0 security, P1 crash, P2 feature, P3 incomplete) |
| `tests/test_bounty_triage_minion.py` | 11 automated integration & unit tests exercising real OpenMinion 0.1 building blocks |

---

## Quickstart

### 1. Install (with local OpenMinion 0.1 source or PyPI)

```bash
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# macOS / Linux:
# source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -e ../openminion pytest
python -m pip install --no-deps -e .
```

### 2. Check OpenMinion & Provider Readiness

```bash
bounty-triage doctor
```

### 3. Run a Repeatable Local Audit (Dogfooding This Repo)

```bash
# Clean self-audit (100/100 health score -> GO)
bounty-triage audit --repo . --workspace .. --version 0.1.0

# Audit with sample open issues fixture (P0 security issue -> NO_GO)
bounty-triage audit \
  --repo . \
  --workspace .. \
  --issues fixtures/sample_issues.json \
  --version 0.1.0 \
  --export-bundle .bounty-triage-state/triage-memory-bundle.json
```

### 4. Run Provider-Neutral `Agent` Turns (Demo or Live Cortensor / Ollama)

```bash
# Credential-free demo mode (exercises OpenMinion runtime plumbing via echo provider)
bounty-triage run "Summarize repo readiness checklist requirements" --agent bounty-triage-readonly

# Live model-backed turn via Cortensor Portal (requires CORTENSOR_API_KEY)
export CORTENSOR_API_KEY="your-cortensor-key"
bounty-triage run "Inspect this repository and generate a v0.1.0 release checklist" --agent bounty-triage-cortensor
```

### 5. Run the Full Test Suite

```bash
pytest -v
```

Observed result on Windows 11 / Python 3.15.2 / `openminion==0.1.24`:

```text
11 passed in 12.44s
```

---

## Building Blocks Tested (OpenMinion `0.1.24`)

All rows below reflect **real local executions** on Windows 11 (`Python 3.15.2`, `openminion==0.1.24`).

| Building Block | OpenMinion Surfaces Tested | Status | Real Observed Behavior & Friction Notes |
| --- | --- | --- | --- |
| **Execution** | `APIRuntime.from_config_path`, `Agent.run`, `Agent(output_type=TriageSummary)`, `APIRuntime.submit_turn` / `RuntimeTurnHandle.stream()` | **PASS (with friction)** | Turn ingress, typed `TurnChunk` streaming, and Pydantic `output_type` validation work cleanly once `default_channel="console"` is set on every agent profile. Omitting `default_channel` crashes with `inbound authenticity denied (reason=invalid_channel, mode=warn)`. |
| **Tools** | `@tool(min_scope=..., idempotent=...)`, `ToolRegistry`, `build_registrar`, `extra="forbid"` args validation, `openminion tools list` | **PASS (with friction)** | `@tool` Pydantic schema derivation and run-scoped registration/unregistration work smoothly. However, `openminion tools list` took **25.17s** and printed **~460 KB (~6,000+ lines)** of raw JSON schemas to stdout. |
| **Permissions & Policy** | `build_action_policy_service`, `ActionPolicy.check`, `temporary_tool_risks`, `Handoff`, workspace confinement guard | **PASS** | Clean separation: `READ_ONLY` tools resolve to `ALLOW` (`risk_class="read"`), `WRITE_SAFE` (`export_triage_report`) resolves to `REQUIRE_CONFIRM` (`risk_class="write"`), and `shell.exec` resolves to `REQUIRE_CONFIRM` (`risk_class="exec"`). |
| **Sessions** | `Agent(..., session_id=...)`, cross-session isolation, `openminion.api.queries.runs.list_runs` | **PASS** | Multi-turn continuity within `triage-sess-A` and strict isolation from `triage-sess-B` persisted cleanly in SQLite and queried back accurately via `list_runs`. |
| **Memory & Artifacts** | `MemoryBundle`, `export_bundle`, `save_bundle`, `load_bundle`, `import_bundle(trust_mode="candidate")`, `ArtifactCtl.ingest_bytes` | **PASS (with friction)** | `MemoryBundle` round-trip and `ArtifactCtl` SHA-256 content-addressed storage work cleanly, but `ArtifactCtl` does not accept `home_root`/`data_root` args and rejects isolated temp dirs unless `OPENMINION_DATA_ROOT` is mutated in `os.environ`. |
| **Skills** | `Skill`, `ingest_file`, `admit_skill_version`, `SkillIngestAuthority.local_operator`, `match` | **PASS (with friction)** | Full lifecycle (YAML frontmatter parsing → draft ingest → operator admission to `verified` → intent matching with score `13.5`) works end-to-end. Calling `ingest_file(..., trust="trusted_local")` without `authority=` fails with `SKILL_INGEST_AUTHORITY_OVERRIDE_REJECTED`. |
| **Tasks** | `StorageEngine.from_paths`, `SqlTaskCtl`, `create_task`, `attach_plan`, `step_update`, `PlanDraft`, `PlanStepStatus` | **PASS (with friction)** | Durable SQLite task creation, multi-step plan attachment, and step state transitions work reliably. Requires `StorageEngine.from_paths(...).record_store` (`RecordStore` is abstract) and uses mixed method naming (`create_task` / `attach_plan` vs `step_update`). |
| **Diagnostics** | `openminion doctor --check-turn --json`, `openminion setup --list-providers --json`, `runtime.runtime_posture()` | **PASS (with friction)** | `openminion doctor --check-turn --json` completed in **17.94s** with `ok: true, fail: 0, ok: 20, warn: 6`. On Windows NTFS, it raises false-positive `world-writable` warnings recommending Unix `chmod 750`. |

---

## What We Learned — 5 Concrete Alpha Feedback Items for OpenMinion 0.1

Every item below comes directly from real errors, stack traces, and timings observed while building **BountyTriage Minion** on `openminion==0.1.24`:

1. **Default `AgentProfileConfig.default_channel` to `"console"` (or fail at config validation time instead of turn execution):**
   - *Observed:* Creating `AgentProfileConfig(name="...", provider="echo")` in Python or omitting `"default_channel"` in a custom `agents.json` succeeds at config load time, then crashes on the first `Agent.run()` inside `GatewaySecurity.enforce_inbound_authenticity` with `RuntimeError: inbound authenticity denied (reason=invalid_channel, mode=warn)`. Even OpenMinion's own test helper (`tests/_csc_fixtures.py`) has to patch `existing.default_channel = "console"`.
   - *Recommendation:* Default `AgentProfileConfig.default_channel` to `"console"` or raise a clear `ConfigError` during `ConfigManager.load()`.

2. **Make CLI parser registration lazy and default `openminion tools list` to a compact table:**
   - *Observed:* `openminion/cli/parser/base.py:204` (`_register_command_modules`) eagerly imports every CLI command module (`cli/commands/tools.py` → `api/queries/owner.py` → runtime graph) just to build the argparse tree—even for `--help`. On a cold cache this took >5s, and `openminion tools list` took **25.17s** while dumping **~460 KB (~6,000+ lines)** of full JSON parameter schemas to stdout.
   - *Recommendation:* Lazily import subcommand handlers only after dispatch, and make `openminion tools list` print a compact `name | source | enabled | policy_allowed` table by default (keeping full JSON schemas behind `--json --include-schemas`).

3. **Unify `home_root` and `data_root` constructor parameters across runtime modules:**
   - *Observed:* `APIRuntime.from_config_path(..., home_root=..., data_root=...)` accepts both roots; `Skill(..., home_root=...)` accepts only `home_root`; `ArtifactCtl(config)` accepts neither, causing `ConfigError: artifact_blob_root must be under data_root` whenever an app uses isolated per-run temp directories without mutating process-global `os.environ["OPENMINION_DATA_ROOT"]`.
   - *Recommendation:* Accept explicit optional `home_root: Path | None = None, data_root: Path | None = None` on `ArtifactCtl`, `Skill`, and `SqlTaskCtl` (plus a `SqlTaskCtl.from_sqlite_path(...)` factory) so multi-tenant or parallel test callers never need to mutate `os.environ`.

4. **Make `openminion doctor` filesystem permission checks Windows-aware:**
   - *Observed:* Running `openminion doctor --check-turn --json` on Windows 11 flagged freshly created `.openminion/memory` directories with `WARN security.filesystem.memory_permissions: Path is world-writable ... Restrict permissions (for example chmod 750 on dirs, 640 on files)`. Because Python's `os.stat().st_mode` synthesizes `0o777` on Windows NTFS, every Windows developer sees bogus warnings and non-applicable `chmod` advice.
   - *Recommendation:* Gate POSIX mode-bit checks on `os.name != "nt"` (or inspect Windows ACLs / emit an explicit `INFO: POSIX mode checks skipped on Windows` note).

5. **Improve ergonomic discoverability in `Skill.ingest_file` and `SqlTaskCtl`:**
   - *Observed:* (a) Calling `Skill.ingest_file(..., trust="trusted_local")` without `authority=` raises `SKILL_INGEST_AUTHORITY_OVERRIDE_REJECTED: Runtime skill ingest cannot declare trust.` without telling the developer to pass `authority=SkillIngestAuthority.local_operator(...)`. (b) `SqlTaskCtl` exposes `create_task` / `attach_plan` (verb-noun) alongside `step_update` (noun-verb), and `RecordStore(...)` raises `TypeError: RecordStore() takes no arguments` without indicating `StorageEngine.from_paths(...).record_store`.
   - *Recommendation:* Add an actionable hint in the `SKILL_INGEST_AUTHORITY_OVERRIDE_REJECTED` error message, add an `update_step` alias on `SqlTaskCtl`, and export a `SqlTaskCtl.from_sqlite_path(path)` convenience constructor.

---

## License

Apache-2.0 — see [LICENSE](LICENSE).
