# Kingdom Manager v3.2.7
Adds explicit **Enable + Back Up** / **Back Up Now** actions for stateful remediation.
Kingdom archives detected persistent bind mounts and named volumes read-only into `/data/preupdate-backups/<container>/`, verifies a non-empty archive, records SHA-256/size/mount metadata, and marks the backup fresh. Default retention is 5 backups/container. The image update remains a separate approval step.
