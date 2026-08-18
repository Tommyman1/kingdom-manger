# Kingdom Manager v3.2.8

- Fixes pre-update backup crash: `NameError: re is not defined`.
- Streams SHA-256 calculation for backup archives.
- Returns structured backup errors.
- Gives a clear error if `alpine:3.22` backup helper image is missing.
- Preserves stateful backup/remediation workflow.
