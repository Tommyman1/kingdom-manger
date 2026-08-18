# Kingdom Manager v3.1.5 — Scan Truth & Falco Clarity

- Fixes Docker exec raw-stream parsing for Trivy JSON output.
- Scan lifecycle is explicit: RUNNING, SUCCESS, ERROR, STALE, NEVER_SCANNED.
- Failed scans never count as clean 0/0/0 results.
- Successful rescans automatically remove retry recommendations.
- Failed recommendations show the real error and last successful CVE counts.
- Trivy dashboard totals count successful scans only and separately show failed/running scans.
- Falco card separates raw Falco priority hits from effective Kingdom incidents.
- Falco card shows known-good hits attenuated by scoped approvals.
- No destructive database migration.
