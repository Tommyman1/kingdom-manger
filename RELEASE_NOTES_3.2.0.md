# Kingdom Manager v3.2.0 — Local Build Awareness

- Adds a per-container **Local Build** policy toggle.
- Local Build prevents registry pull/update attempts for locally-created images.
- Auto Update never acts on Local Build containers.
- Container list replaces `Update` with `⌂ Local` when enabled.
- Security Profile provides a **Local Fix Path** for vulnerabilities.
- Vulnerability remediation explicitly requires updating the Dockerfile base image and/or dependencies before rebuilding.
- Rebuilding unchanged source is not treated as a vulnerability fix.
- Schema v16 adds `policies.local_build` safely with default OFF.
