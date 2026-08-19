# Kingdom Manager v3.2.14 — Falco Webhook 500 Fix

Fixes the Falco webhook returning an `asyncio.Task` object to FastAPI.

Previous behavior:
- Event stored
- Heartbeat stored
- Background task created
- Task object returned to FastAPI
- FastAPI failed to serialize it and returned HTTP 500

New behavior:
- Event stored
- Heartbeat stored
- Background analysis scheduled
- Normal JSON acknowledgement returned immediately

Expected Falco response:
`{"ok":true,"accepted":true,"sensor":"falco",...}`

This preserves both v3.2.12 fast acknowledgements and v3.2.13 heartbeat health tracking.
