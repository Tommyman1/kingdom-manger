# Kingdom Manager v3.1.0 LTS validation report

## Offline/package validation performed

- Python bytecode compilation: PASS
- Fresh schema v15 creation: PASS
- SQLite `quick_check`: PASS
- New tables (`config_baselines`, `backup_status`, `validation_runs`): PASS
- Existing update/rollback/recovery tables preserved: PASS
- `compose.yaml` YAML parse: PASS
- `falco-compose.yaml` YAML parse: PASS
- Dashboard JavaScript `node --check`: PASS
- Configuration drift baseline -> clean comparison: PASS
- Secret-like environment key detection without exposing value in Drift output: PASS
- Dependency map generation with shared network/volume fixtures: PASS
- Non-destructive rollback snapshot validation: PASS
- Simulation endpoint performs no real actions: PASS
- System validation fixture: 12/13 checks passed; the only intentionally optional failure was Discord not configured in the isolated test environment
- Archive integrity: PASS

## Safety review

- Automatic playbooks are de-duplicated for active incidents.
- Safe playbook steps may run automatically; isolation/recovery defaults remain OFF.
- Global maintenance pauses lifecycle restart and update scheduler automation.
- Auto-update remains explicit per container.
- Automatic update application remains globally OFF by default.
- Stateful auto-update remains globally OFF by default.
- When stateful auto-update is explicitly enabled and policy requires a backup, a recent verified backup record is required.
- Rollback uses immutable prior image ID plus captured Docker configuration.
- Rollback dry-run does not modify live containers.
- Drift baselines store environment variable names, not values; label values are hashed in the drift baseline.
- Core/security services remain protected by default inference.

## Runtime validation still required on the real server

Offline tests cannot prove behavior against the user's actual Docker daemon, registry, Portainer instance, container healthchecks, persistent application data migrations, Discord webhook, backup provider, or network topology.

After deployment perform:

1. `/ready`.
2. `/api/system/validate`.
3. Discord test.
4. ClamAV diagnostics/protocol check.
5. One disposable Ring-1 staged update.
6. Manual rollback of that disposable container.
7. Disaster Recovery dry-run for its snapshot.
8. Drift baseline approval, followed by a harmless controlled config-change test if desired.
9. Confirm stateful applications have independent restorable backups before enabling stateful auto-update.
