# Kingdom Manager v3.1.3 — Warm Start & Scheduler Staggering

- Persists the last successful Kingdom security score to `/data/dashboard_snapshot.json`.
- Adds `/api/dashboard/bootstrap`, a fast endpoint that never waits for Docker or security engines.
- Shows the last verified score immediately after authentication while live intelligence refreshes.
- Adds a background score warmer so primary dashboard state remains hot.
- Staggers monitor, score-history, Trivy, Drift, and sensor-watch startup offsets to prevent synchronized heavy jobs.
- Increases authentication verification timeout to 15 seconds and safely retries once for transient timeout/502/503/504 conditions.
- Preserves v3.1.2 reliability, caching, isolated Trivy exec proxy, and UI improvements.
