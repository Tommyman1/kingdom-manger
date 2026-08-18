# Kingdom Manager v3.2.12 — Falco Fast-Ack Webhook

Fixes Falco HTTP output timeouts caused by Kingdom performing heavy correlation before
responding to Falco's webhook.

## New behavior
1. Authenticate Falco webhook.
2. Parse/store the Falco event.
3. Schedule Decision Engine / correlation work in the background.
4. Return HTTP success immediately.

This prevents Falco's HTTP output queue from blocking on Kingdom analysis while preserving
the same downstream decision logic.

No Falco timeout increase is required for the intended architecture.
