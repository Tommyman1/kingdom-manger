# Kingdom Manager v3.1.2 — Unified UI Patch

This release keeps the v3.1.1 reliability and performance work intact and focuses on visual consistency and action clarity.

## Changes

- Rebuilt the global button system with consistent height, spacing, radius, hover, focus, disabled and loading states.
- Standardized primary, secondary, success, destructive, ghost and compact action styles.
- Redesigned Incident Center rows so status badges no longer stretch vertically and actions read as a single coherent control group.
- Reworked Incident Center navigation controls into compact, consistent pills.
- Redesigned Kingdom Baseline Learning entries as structured cards with clean metadata, status chips and separate Review / Mark Expected actions.
- Improved responsive behavior for incident actions, navigation controls and baseline cards.
- Added an animated busy indicator to guarded actions while preserving duplicate-action protection from v3.1.1.
- Standardized container toolbar controls and policy chips.
- Increased Baseline drawer width slightly for better information density on desktop while preserving mobile behavior.

## Preserved from v3.1.1

- Lightweight authentication verification.
- Cached Docker inventory and last-known-good fallback.
- Hardened non-JSON API handling.
- Request deduplication / action guards.
- Dedicated Trivy exec proxy architecture.
- Existing v3.1 update, recovery, drift, validation, Discord, playbook and scoring features.
