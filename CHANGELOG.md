# Changelog

## 0.1.0 — 2026-11-25

- Initial Cortensor Hackathon #5 release built on OpenMinion 0.1 (`openminion==0.1.24`).
- Added five structured OpenMinion `@tool` implementations with workspace confinement and secret redaction.
- Integrated real OpenMinion 0.1 subsystems: `APIRuntime`, `Agent`, `ToolRegistry`, `ActionPolicy`, `Skill`, `SqlTaskCtl`, `ArtifactCtl`, `MemoryBundle`, and runtime posture diagnostics.
- Added `bounty-triage` CLI (`audit`, `run`, `doctor`) and end-to-end `pytest` verification suite.
