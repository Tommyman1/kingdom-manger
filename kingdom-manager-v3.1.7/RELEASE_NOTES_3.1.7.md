# Kingdom Manager v3.1.7 — Per-Container Remediation

Security Profile is now a remediation command center, not just a read-only detail view.

- Adds a **Remediation** section to every container Security Profile.
- Failed/never-run Trivy verification offers **Retry Scan / Scan Now**.
- Critical/high vulnerability results offer **Review Safe Update**, using the existing verified update + rollback pipeline.
- Active incidents offer **Investigate**, opening the existing evidence/response playbook.
- Elevated risk without an incident offers **Refresh Verification**.
- Healthy profiles explicitly show that no immediate remediation is recommended.
- Destructive recovery remains operator/approval gated.
- Mobile remediation actions expand to full-width controls.
- Fixes the v3.1.6 recommendation fallback so it opens the actual container profile when a container is available instead of referencing an undefined JavaScript variable.
