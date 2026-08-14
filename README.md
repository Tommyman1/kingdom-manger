# Kingdom Manager v1.3

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


## Correlation Decision Engine (v1.3)

The Decision Engine now scores independent security sources instead of reacting to raw alert count. Repeated Falco warnings from one rule do not stack into a fake multi-engine compromise.

Default response model:
- Falco informational/notice only: record.
- Falco high/critical: investigate unless corroborated.
- Trivy vulnerabilities: recommend/update investigation; never isolate by themselves.
- ClamAV malware signal alone: quarantine evidence / high-risk investigation.
- Strong evidence from two or more independent active sources: recommend isolation.
- Automatic isolation occurs only when the target container has Auto-Isolate enabled and is not Protected.
- Destructive rebuild remains gated and is never triggered by this engine automatically.

Correlation defaults: 15-minute active-event window, 2-minute decision debounce, and 7-day Trivy vulnerability context. All are configurable with `KM_DECISION_*` / `KM_TRIVY_CONTEXT_SECONDS`.
