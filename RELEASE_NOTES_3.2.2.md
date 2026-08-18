# Kingdom Manager v3.2.2 — Remediation Center

Kingdom now tries to reduce vulnerability risk instead of stopping at “verification blocked”.

- **Fix What Kingdom Can** performs a current-vs-candidate immutable-image Trivy comparison.
- **View All Issues** lists every stored CVE, package, installed version, fixed version and exact remediation text.
- Shows findings removed, still present and newly introduced by an upstream candidate.
- A candidate with remaining Critical/High CVEs can be offered when it is measurably safer than the running image.
- Such risk-reducing updates always require explicit operator approval.
- Auto-Update can discover them but cannot silently approve them.
- Local Build findings point to source/base/dependency rebuilds.
- No-upstream-image findings are explicitly marked as unavailable for safe automatic repair.
- Stateful containers surface the backup/stateful-update gate before application instead of failing late.
- Portainer source-of-truth deployment and automatic rollback remain intact.
