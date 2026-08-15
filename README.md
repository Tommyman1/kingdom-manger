# 👑 Kingdom Manager v1.11.2

This release merges the v1.10.1 corroboration fix with the v1.11 adaptive-intelligence roadmap. It keeps the v1.10 incident/Trivy flow and adds baseline-aware scoring that is deliberately advisory: learned behavior can reduce Falco-only score impact when corroborating scanners are clean, but it never auto-suppresses rules or authorizes recovery.

## What changed

### Automatic database migrations
Kingdom Manager now maintains a schema version in SQLite and automatically repairs the legacy `events` table shape that caused the `ts` / `source NOT NULL` upgrade failures. Before a destructive table migration it creates a SQLite backup in `/data` and preserves the old events table under a versioned `events_legacy_*` name.

You should not need to manually run `ALTER TABLE` for this upgrade.

### Incident workflow
- Incident Center has **Investigate**, **Capture Evidence**, and **Resolve** actions.
- Medium incidents are explicitly shown as needing review even when nothing qualifies as immediate/urgent attention.
- Evidence capture keeps the Docker snapshot + on-demand Trivy evidence flow from v1.6.

### Container Security Drawer
Click a container in the leaderboard or container list to open a focused security drawer showing:
- current container security score and exact risk factors
- trust/risk profile
- networks and mounts
- latest Trivy result
- recent security evidence
- Approved Rebuild / Auto-Isolate / Auto-Restart / Protected controls
- Scan Now, Restart, Isolate, and one-hour Maintenance Mode
- **Mark Expected** for individual Falco rule + container combinations

### Explain My Score
Containers only lose points when the backend can state a real source of the deduction. Correlation deductions now state the Decision Engine risk score and contributing engines instead of saying `No active correlated risk` while subtracting points.

### Trivy status
The card distinguishes the runner from the scheduler. During coverage it can show `SCANNING`, `ERROR`, or the underlying healthy state and displays the scheduler target/error.

### Activity feed
Raw database records are translated into a compact timeline with event-specific icons and summaries.

### Score history
A background sampler records Kingdom Security Score, monitoring confidence, and severity counters. The dashboard includes a 7-day score chart. History is retained for 90 days.

### Security recommendations
Kingdom Manager now generates prioritized recommendations for:
- unavailable core security engines
- running containers that have never been scanned by Trivy
- critical Trivy CVEs
- noisy Falco containers that may need a scoped known-good suppression
- open incidents that require review

### Discord + n8n reporting
Existing Discord and n8n outputs are now first-class notification/reporting channels.

Default behavior:
- live notifications are filtered below `KM_NOTIFY_MIN_SEVERITY` (`high` by default)
- a daily report is generated at 08:00 local time
- a weekly report is generated Monday at 09:00 local time
- manual **Send Daily** and **Send Weekly** buttons are available on the dashboard
- notification/report delivery results are stored in SQLite

No Discord or n8n endpoint is required; both remain optional.

## New environment values

```yaml
KM_NOTIFY_MIN_SEVERITY: "high"
KM_DAILY_REPORT_ENABLED: "true"
KM_DAILY_REPORT_HOUR: "8"
KM_WEEKLY_REPORT_WEEKDAY: "0"
KM_WEEKLY_REPORT_HOUR: "9"
KM_SCORE_HISTORY_INTERVAL_SECONDS: "900"
```

`KM_WEEKLY_REPORT_WEEKDAY` uses Python weekday numbering: Monday `0` through Sunday `6`.

## Safety

Controlled recovery remains approval-gated. `Approved Rebuild` does **not** perform an automatic rebuild by itself. Protected Kingdom core components remain hard-blocked from self-recovery.

Preserve the existing `kingdom-manager-data` and `kingdom-manager-trivy-cache` volumes. Replace the CrowdSec placeholder in `compose.yaml` with your current bouncer key before deployment; do not paste that secret into chat.

## Upgrade verification

After deployment:

```bash
docker ps --filter name=kingdom-manager \
  --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}'

docker logs kingdom-manager --since 5m 2>&1 | \
  grep -iE 'migration|error|exception|traceback|trivy|report'
```

The footer should show **v1.11.2**. Trivy may continue the scan already in progress or choose the next oldest/unscanned running container after restart.


## v1.9 Intelligence + Controlled Recovery

v1.9 combines the investigation and recovery roadmap into one approval-gated release.

### Incident Intelligence
- **Investigate** opens a case view that groups Falco rules, counts repetitions, shows first/last observation, Trivy context, ClamAV/CrowdSec corroboration, and a Kingdom assessment.
- Assessments are labeled `likely-expected`, `unverified`, `suspicious`, or `high-confidence-threat` with an explicit confidence percentage and factors.
- **Mark Expected** creates a narrow suppression for *that container + that Falco rule* and dismisses the incident. It does not disable the Falco rule globally.
- The normal activity feed hides routine idle telemetry by default so incident/recovery/security actions remain visible.

### Controlled Recovery
Recovery remains opt-in. A container must have **Approved Rebuild** enabled and **Protected** disabled. Kingdom core containers are hard-blocked.

Approved recovery performs:
1. Evidence capture and current configuration snapshot.
2. Isolation from service networks.
3. Pull of the configured image.
4. Removal of the old container only after approval.
5. Creation of a replacement candidate on the private quarantine network **without published ports**.
6. Trivy verification while the candidate remains quarantined.
7. If `KM_RECOVERY_BLOCK_ON_CRITICAL_CVE=true` and critical CVEs are found, recovery stops safely and leaves the candidate quarantined.
8. Recreate the final container with captured host configuration and original networks.
9. Observe runtime/health for `KM_RECOVERY_OBSERVATION_SECONDS`.
10. On failed observation, Kingdom Manager attempts to isolate the replacement again and marks the plan failed.
11. On success, the incident is resolved and the full recovery audit trail is retained.

This is **not autonomous self-healing by default**: recovery still requires an operator-created plan and a second approval within the configured approval window.

### Additional recovery guardrail
Database containers are blocked from automated rebuild by default (`KM_RECOVERY_ALLOW_DATABASES=false`) even if Approved Rebuild is toggled. This is intentional because database recovery should be backup-aware.

## v1.11.0 Adaptive Intelligence + Baseline-Aware Risk

- Auditable confidence math for incident assessments, including deltas from the prior assessment.
- Clear Falco scope: incident-matching events are shown separately from Kingdom-wide Falco totals.
- Clean Trivy scans can strengthen a likely-expected assessment without erasing runtime anomalies.
- Suppression impact preview before approval, exact container+rule scope, global suppression blocked by API, and optional expirations.
- Kingdom Intelligence plain-language incident summary with suggested operator action.
- Representative Falco process/executable/user/image/command samples remain grouped under each rule.
- Baseline Learning analyzes recurring container+rule behavior over up to 7 days and only suggests known-good candidates; it never auto-applies suppressions.
- Incident API supports status, severity, container, text query, and age filters.
- Incident assessment history stores confidence and security-score snapshots for auditability.
- Existing recovery controls remain approval-gated and protected/database safeguards remain unchanged.

## Adaptive baseline tuning

Defaults are intentionally conservative:

```yaml
KM_BASELINE_DAYS: "7"
KM_BASELINE_STABLE_MIN_EVENTS: "100"
KM_BASELINE_STABLE_MIN_HOURS: "12"
KM_BASELINE_STABLE_ATTENUATION: "20"
KM_BASELINE_LEARNING_ATTENUATION: "8"
```

A behavior is only considered **stable** after both enough repetitions and enough elapsed time. A short burst of thousands of alerts is treated as noise/novelty, not a trustworthy baseline. Stable/learning baselines can attenuate *Falco-only* risk only when a recent Trivy scan is clean. ClamAV or CrowdSec corroboration, critical/high Trivy findings, or multi-engine evidence bypass this attenuation.

Baseline learning never creates suppressions automatically. `Mark Expected` remains an explicit operator action scoped to an exact container + Falco rule.


## v1.11.2 Trust Diagnostics + Scoring Consistency

This patch is a correctness/safety review of the v1.11 adaptive-intelligence path.

### Known-good scoring is now immediate and suppression-aware
- Security score evaluation re-checks active suppressions at read time, so an older unsuppressed correlation run cannot keep penalizing a rule after an operator approves it.
- Exact `container + source + rule` suppressions can attenuate the stored correlation score down to a small configurable residual risk instead of silently erasing the evidence.
- Score explanations show the original correlation score, the known-good adjustment, and the resulting effective score.
- Expired suppressions stop affecting risk automatically.
- Multi-engine evidence is recalculated from unsuppressed signals; a known-good Falco rule does not suppress independent ClamAV/CrowdSec/Trivy context.

Defaults:
```yaml
KM_KNOWN_GOOD_RESIDUAL_RISK: "5"
KM_KNOWN_GOOD_MAX_ATTENUATION: "45"
```

### Trivy error-state hardening
- A failed Trivy attempt is shown as **SCAN ERROR**, never as a clean `0 critical / 0 high / 0 medium` result.
- Container profiles expose **Latest scan attempt** separately from **Last successful scan**.
- Adaptive baseline confidence uses only a successful Trivy result.
- Recommendations explicitly request a retry after a failed scan.
- Reports count successful Trivy scans separately and expose an error count.
- Controlled recovery now blocks and leaves the replacement quarantined if Trivy verification itself fails. A scan error can never be interpreted as permission to restore service networks.

### Expected-evidence UX
- Recent Falco evidence now shows `EXPECTED` with expiry instead of continuing to offer `Mark Expected`.
- Baseline Learning shows approved scopes as `EXPECTED` and displays the effective adjustment.
- Incident investigation recognizes an approved exact rule, raises the expected-confidence path, and presents the operator approval in the confidence explanation.

### Upgrade
No manual database operation is required. The schema marker advances to v8; existing volumes remain unchanged.


## v1.11.2 Trust Diagnostics + Scoring Consistency

- Exact suppression matching is normalized for Falco formatting differences while remaining container+rule scoped.
- Legacy/pre-approval correlation rows resolve the original Falco rule from the nearest stored event.
- Dashboard known-good count now reports actual matching events, not only newly-created `action=suppressed` correlation rows.
- New **Trust** diagnostics drawer shows active approvals, matching events, matching correlation rows, points removed, expiry, and the precise blocker when attenuation cannot apply.
- Security score, leaderboard, severity counters, and Explain My Score all share the same suppression-aware effective-risk path.
- Existing Trivy error-state hardening and controlled-recovery safety remain enabled.
