# Kingdom Manager v3.2.10 — Backup Docker API Transaction Fix

Fixes the `400 invalid JSON: EOF` failure and the next Docker API/runtime issues in the same backup path.

- Sends `/containers/create` with `json=payload`.
- Accepts Docker create HTTP `201`.
- Accepts Docker start/remove HTTP `204`.
- Resolves the host-side source backing Kingdom Manager `/data` before mounting backup output into the helper container.
- Keeps source application mounts read-only in the backup helper.
- Streams SHA-256 verification.
- Marks the resulting archive as a filesystem-level crash-consistent backup.
- Keeps the newest 5 verified backups by default.

Note: filesystem archives protect mounted data, but database-native backup methods remain preferable for applications that require transactional consistency.
