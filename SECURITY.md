# Security Policy

## Scope & Safety Posture

BountyTriage Minion operates in a **read-only, workspace-confined** posture by default:

- Inspection tools declare `min_scope="READ_ONLY"` and `idempotent=True`.
- File access is strictly confined inside the operator-approved workspace root (`Path.relative_to()` check).
- The secret scanner immediately redacts matches before returning, logging, or persisting evidence.
- Disk report export (`export_triage_report`) declares `min_scope="WRITE_SAFE"` and triggers `REQUIRE_CONFIRM` under OpenMinion's default `ActionPolicy`.

## Reporting a Vulnerability

Please open a private security advisory or report directly to the maintainers with reproduction steps and affected version. Never commit live API keys or `.env` files to issues or pull requests.
