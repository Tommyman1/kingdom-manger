# Kingdom Manager v3.2.5 — Modal Renderer Fix

- Fixes blank remediation/stateful safety dialogs introduced by structured `html:` content.
- `kmDialog()` now supports both:
  - `text:` for plain text dialogs
  - `html:` for structured remediation panels
- Adds `wide:true` support for Current vs Candidate remediation layouts.
- Dialog content scrolls independently while action buttons remain visible.
- Preserves Escape, Enter, backdrop-close, Cancel, and primary-action behavior.
- Mobile dialog sizing improved.
- No backend, security-engine, or database changes.
