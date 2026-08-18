# Kingdom Manager v3.1.1 — Reliability & UI Audit

This patch targets the intermittent login timeout, Docker inventory fan-out, Trivy execution isolation, and inconsistent UI action behavior found during v3.1 LTS testing.

## Reliability
- Auth verification is independent from the rest of the dashboard.
- Docker GET requests reuse keep-alive connections and retry one transient connect/pool failure.
- Container lists are cached for 12 seconds with a 5-minute last-good fallback.
- Core security sensor probes are cached for 15 seconds.
- Security score output is cached for 10 seconds so Explain Score can reuse the same evaluation.
- Dashboard secondary panels fail soft instead of preventing core security state from rendering.

## Trivy
- The general Docker API stays `EXEC=0`.
- A dedicated `trivy-exec-proxy` exposes only the Docker exec capability required to run the scanner container.
- Trivy health/scan actions use `TRIVY_EXEC_DOCKER_HOST`.

## Incident/UI actions
- Scan, evidence, playbook, resolve, lifecycle and policy actions guard against duplicate submissions.
- Long-running scans/playbooks use appropriate client timeouts.
- Investigating an incident no longer initiates an unnecessary nested full-dashboard load.
- Buttons now share consistent sizing, hover/disabled/loading behavior and semantic primary/success/danger styling.
- HTML/non-JSON reverse-proxy errors produce a human-readable Kingdom API error.

## Compatibility
- Database schema remains v15.
- Existing data/cache volumes are retained.
