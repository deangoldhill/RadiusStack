# RadiusStack 6.2.1 — source candidate

This candidate contains the complete deployable 6.2.0 source plus the changes below. It is staged for Dean to publish manually; the temporary packaging tag is not a project or GitHub tag.

## Changes since 6.2.0

- HA Log Reconcile now replaces the secondary's Authlog (`radpostauth`), Auditlog (`admin_audit_log`), accounting (`radacct`), and linked plan PoD enforcement outcomes (`plan_pod_enforcements`) from one primary snapshot. Secondary-only rows are discarded, including records that had been deleted on the primary. It backs up and stages only the current run, temporarily fences secondary API log writes and stops secondary RADIUS, verifies the four replacement tables in the transaction, restarts RADIUS, and drains a bounded post-snapshot primary queue. A failed transfer or content check does not report success. This deliberately does **not** trigger a whole-database Full Sync: that operation upserts rows and does not remove secondary-only records. The new additive schema migration and fresh-init schema include the enforcement transfer count.
- The HA pause now waits for the active primary accounting scanner and prevents it from starting a new scan while paused. Log reconciliation allows a finite nonempty durable queue, pre-drains it, and retains later entries for ordinary delivery. The secondary API log-writer fence tracks connection lifetime, not just individual queries; it blocks `INSERT IGNORE` enforcement claims and drains in-flight PoD sends before replacement. A stuck transaction or PoD worker fails closed after a bounded wait.
- A marked secondary RADIUS stop is retried during startup before the API accepts traffic. Reconciliation controls and API documentation state the destructive replacement policy and brief secondary RADIUS interruption.
- Secondary EAP certificate Generate/Upload is permitted for the node-local certificate only under the Settings write/Global super-admin gate. Other secondary settings remain read-only. Certificate sync avoids replacing node-local EAP material.
- HA Settings offers Reset HA Sync Stats for the current node only, without clearing its queue or cursors. Auth Log Maintenance uses the same accordion styling as neighboring cards, and the Reply Attribute Catalogue no longer displays the redundant “Non-VLAN” badge.
- API image moves to Node 24 Alpine; upgrade preflight refreshes images explicitly. The existing source-archive upgrader and `.env`-free Bash fresh-install wizard remain available.

## Deployment and limitations

**Do not assume lossless HA replication.** The nontransactional RADIUS polling scanner, connection-based API write capture, and queue-ID/commit-order gap described in 6.2.0 remain. Reconciliation cannot recover rows absent from the primary snapshot. A lost acknowledgement or failure after secondary finalization can still require operator review. Long replacement transactions need capacity and timeout testing at production scale. HA must remain disabled on unvalidated pairs.

The source archive contains `.env.example` and `setup_env.sh`, **not `.env`**. For a fresh install, extract the verified asset, run `bash setup_env.sh`, validate Compose, then build/start the stack. Upgrades preserve private `.env`, Compose overrides, database and certificate state; the additive migration does not roll back if a later step fails. Do **not** run `./upgrade.sh --to 6.2.1` in remote-download mode until Dean publishes the exact GitHub tag/asset and verifies its `sha256:` digest. The local staged archive is not a GitHub download source. See `UPGRADE.md`.

This is a source candidate, not proof of a live two-node HA fix. See the accompanying BUILD_INFO for executed tests and unperformed rehearsals.
