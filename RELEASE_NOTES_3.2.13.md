# Kingdom Manager v3.2.13 — Falco Heartbeat Health

- Every authenticated Falco webhook updates a durable heartbeat.
- Falco health now treats fresh webhook delivery as proof of liveness even if the TCP health probe fails.
- Incident creation no longer determines whether the Falco sensor appears UP/DOWN.
- Falco summary exposes webhook timestamp/age/connectivity.
- Dashboard shows recent webhook delivery instead of stale incident-derived time.
- Keeps the v3.2.12 fast-ack webhook path.
