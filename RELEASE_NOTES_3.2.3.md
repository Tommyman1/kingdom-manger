# Kingdom Manager v3.2.3 — Stateful Remediation Safety

- Adds per-container **Allow Stateful Update** policy. Default: OFF.
- Global `KM_UPDATE_ALLOW_STATEFUL` remains supported as an override, but is no longer required for a single trusted stateful service.
- Stateful remediation now checks the effective per-container/global permission before applying.
- Backup readiness is surfaced before apply, including provider, verification time and freshness.
- Security Profile remediation dialog shows a clear DATA SAFETY checklist.
- Fixes vulnerability comparison inflation by de-duplicating findings using CVE + package.
- `Removed`, `Still present`, and `Newly introduced` now use the same unique finding model as the displayed comparison.
- Current/candidate severity counts in remediation comparison are also de-duplicated.
- Portainer/Compose source-of-truth rollback remains unchanged.
