# Kingdom Manager v3.2.11 — Risk-Reduction Apply State Fix

Fixes a state-machine bug where an explicitly approved risk-reducing update was stored as
`verified-risk-reduction` but `/api/updates/{id}/apply` only accepted the normal `verified`
state and returned HTTP 409 `Update plan is not ready`.

After explicit operator approval, both states are now valid:
- `verified`
- `verified-risk-reduction`

This patch does not weaken the Trivy gate or remove the explicit approval requirement.
