# Kingdom Manager v3.2.6 — Regression Recovery

v3.2.5 accidentally removed adjacent dashboard JavaScript functions while replacing `kmDialog`.
v3.2.6 is rebuilt from the known-good v3.2.4 base and applies the HTML modal fix surgically.

## Restored
- `renderWarmScore`
- container lifecycle `act`
- Trivy `scan`
- Security Profile `openDrawer`
- all existing dashboard/remediation functions from v3.2.4

## Modal fix
- Existing modal DOM is preserved.
- `kmDialog()` now accepts `html:` without blanking the dialog body.
- Existing `text:` and `input:` workflows remain compatible.
- `wide:true` expands only the existing modal card.
- Escape/Enter behavior is preserved.

No backend sensor-health code was changed.
