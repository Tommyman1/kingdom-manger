# Kingdom Manager v3.2.15 — Falco Quiet ≠ Down

- `OK`: direct Falco health listener reachable.
- `QUIET`: direct probe unavailable, but webhook delivery was seen recently.
- `DOWN`: direct probe fails and webhook delivery is also stale.
- Quiet periods no longer become false outages.
- Preserves fast webhook acknowledgement and durable heartbeat tracking.
