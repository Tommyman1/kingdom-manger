# Kingdom Manager v3.1.4 — Final Automation Safety Patch

- Enables the global update auto-apply engine in the packaged Compose.
- **No container auto-updates unless its per-container `Auto-Update` policy is explicitly enabled.**
- Rings 3–4 remain manual even when Auto-Update is enabled.
- Protected containers remain blocked.
- Stateful/mounted containers remain blocked while `KM_UPDATE_ALLOW_STATEFUL=false`.
- Trivy verification remains mandatory when configured.
- Adds rollback preflight: the saved Docker config and previous immutable image must both exist before an update can apply.
- Failed post-update health observation automatically restores the previous image/configuration.
- Adds `/api/updates/automation/status` for auditing which containers are actually eligible for automatic application.
- Existing rollback retention remains 10 snapshots by default.

Recommended workflow: enable `Auto-Update` only on low-risk stateless containers first. Leave databases, security services, reverse proxy, Portainer, and Kingdom Manager protected/manual.
