# Kingdom Manager v1.2

Adds direct Falco -> Kingdom Manager event ingestion over the existing `security` Docker network.

## Changes
- Falco webhook is protected by `FALCO_WEBHOOK_SECRET`.
- Dashboard reports Falco `ok`, `stale`, or `waiting` based on actual received events.
- Dashboard shows Falco 24-hour severity counts and recent detections.
- Dockerfile fixes `/data` ownership automatically at startup before dropping privileges.

## Important
Keep the same secret in both `compose.yaml` (`FALCO_WEBHOOK_SECRET`) and `falco-compose.yaml` (`token=` in the HTTP output URL).
Preserve your existing CrowdSec bouncer key when updating the Kingdom Manager compose.


## Trivy integration (v1.2)

Kingdom Manager now treats Trivy as a real security engine instead of a placeholder. A dedicated read-only Docker socket proxy gives the Trivy runner image-read access without lifecycle/write access. Scans prefer local Docker images and fall back to registries, persist normalized CVE findings, show 24-hour Critical/High/Medium counts, and feed update recommendations into the Decision Engine. Trivy findings never auto-isolate a running container because a vulnerable image is not evidence of an active compromise.

The first scan can take longer while Trivy downloads its vulnerability database into the persistent `trivy-cache` volume.
