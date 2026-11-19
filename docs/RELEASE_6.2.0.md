# RadiusStack 6.2.0 — source candidate

This candidate includes all changes from the 6.1.2 and 6.1.3 source archives. It has **not** been published as a GitHub Release. The local 192.168.4.37 installation was marked 6.1.1 before this build. Dean publishes GitHub tags and assets manually.

## Changes since 6.1.3

- NAS Clients: clickable IP addresses open a tenant-scoped, read-only statistics panel. Recorded authentication outcomes, accounting sessions and traffic, average/peak authentication rates, and trends are available over Hour, Day, Week, Month and Year. Manual Refresh and optional 30-second Auto-refresh are included. Counts are local log/accounting records, not all network packets; history is limited by log retention.
- Tenant Settings: the Auto-Purge Auth Logs checkbox, retention days and interval now persist per tenant. The background worker uses each tenant's policy and scoped rows. With tenancy enabled, Global retention deletes Global-owned rows only; existing single-tenant Global behavior remains unchanged.
- Tenant switching: the current page stays open if permitted in the destination context. A switch redirects to Dashboard only when that page would be denied there; direct unauthorized visits still show the access-denied page.
- HA receiver: terminal partial/completed reconciliations allow secondary reverse-log replay again, while active maintenance returns a conflict response. Pre-snapshot primary queue delivery and post-snapshot catch-up use bounded queue-ID fences; pre-peer failures are marked retryable.
- HA reconciliation: after final verification, the secondary attempts run-scoped deletion of that run's backup and staging tables, with a same-run retry for a lost acknowledgement. Historical/orphan tables are not swept by upgrade. The backup table `ha_backup_admin_audit_log_<run-id>` is created by reconciliation, not the upgrade script.
- HA API standalone pool writes: transactional source-write/queue capture replaces the previous post-commit enqueue for `pool.query` and `pool.execute` calls.
- Local-archive upgrade mode: `upgrade.sh --to 6.2.0 --archive /absolute/path/radiusstack-source.tar.gz` checks the adjacent `SHA256SUMS` and validates the archive before stopping writers. The existing published GitHub Release mode remains supported.

## Critical HA limitation — do not enable on unvalidated pairs

**This candidate does not guarantee lossless, ordered HA replication.** Connection-based API writes still enqueue outside their source transaction and may lose queue inserts; direct FreeRADIUS writes rely on a non-atomic polling scanner. Queue auto-increment IDs do not prove commit order, so a late lower-ID commit can be skipped after a higher-ID acknowledgement. A crash/lost acknowledgement around peer finalization, catch-up or cleanup can strand reconciliation without automatic recovery. A `partial` reconciliation now also removes its per-run backup/staging tables after final verification; unmatched secondary-only rows or conflicts may then be unrecoverable. Keep `HA_ENABLED=false` unless a separate two-node validation and risk acceptance have been completed. This limitation is a known code risk, not just missing test coverage.

## Installation and upgrade

The archive contains `.env.example` and `setup_env.sh`, but **no `.env`**. Fresh installs run `bash setup_env.sh` to create a private `.env` (mode 0600), validate `docker compose config -q`, and then build/start the stack. Preserve a primary's shared HA keys/token when provisioning a peer.

The 192.168.4.37 installed source was 6.1.1 and had local modifications. The local-archive updater makes a source backup and whole-database dump before overlay and migrations; it retains `.env`, Compose overrides, database and generated certificate state. **Database migrations are not rolled back by source rollback.** Do not use `./upgrade.sh --to 6.2.0` alone until Dean publishes the exact GitHub Release asset with its `sha256:` digest. The staged folder is not a GitHub download source. See `UPGRADE.md`.

## Verification disclosure

Selected source-level API/UI regressions passed before packaging. The full fresh-install, populated upgrade, HA two-peer, and authenticated-browser rehearsals were not performed at Dean's request. Package integrity, image build, live backup and service health require separate checks before any successful-deployment claim.
