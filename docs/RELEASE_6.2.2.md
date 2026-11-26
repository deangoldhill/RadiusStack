# RadiusStack 6.2.2

Complete server source package for fresh installation and upgrade. This local declaration is not a published GitHub tag or Release; Dean publishes manually. Android remains a separate project.

## Changes since 6.2.1

- Automated local JSON backup jobs in Platform Settings: independent schedules and retention, stored-backup inventory, manual run, download, and selected restore. Primary-only jobs use a dedicated persistent backup volume. Full/partial exports use a consistent database transaction and a 50 MiB cap. Failed jobs retain older successful backups. See [LOCAL_JSON_BACKUPS.md](LOCAL_JSON_BACKUPS.md).
- Usage-cycle corrections: tenant-scoped SQL baseline/reset handling and a primary-side catch-up worker reset overdue plan cycles before PoD enforcement.
- Active Sessions Edit User opens the exact tenant-scoped Users or MAC Auth record rather than the generic list.
- Users and MAC Auth Last Online and 30-day metric sorting is applied across the complete paginated query, not only the visible page.
- MAC Auth audit entries use the device name for edits, deletion and limit resets. Existing records resolve the current device name where available without rewriting historical audit records.

The complete source retains 6.2.1's primary-authoritative HA log reconciliation, local secondary EAP certificate handling, HA statistics reset, and Node 24 API image, plus preceding vendor, downstream-statistics, theme, notification, disabled-identity and UI security changes.

## Installation and upgrade

The archive includes all initialization SQL and versioned migrations, `.env.example`, and the Bash `setup_env.sh` wizard. It intentionally contains no `.env`, runtime-generated RADIUS configuration, secrets, backups, Android project, or development tests.

Fresh install: verify SHA256SUMS, extract, enter `radiusstack-6.2.2`, run `bash setup_env.sh`, validate `docker compose config -q`, and run `docker compose up -d --build`. Configure real identity/ports and private credentials; on an HA secondary reuse the primary's shared keys. See [UPGRADE.md](UPGRADE.md).

Upgrade: independently back up and preserve the existing private `.env`, Compose overrides, database, generated RADIUS dictionary, certificates and backups. The additive local-backup migration creates `backup_jobs` and `local_backups`; initialization schema includes the same tables. Compose adds the persistent `backups_volume` mount at `/backups`. Older migrations remain packaged. Source rollback does not roll back database DDL. Local JSON backups are node-local, contain sensitive data, and do not replace off-host recovery backups.

**Do not run GitHub-download upgrade mode until the exact 6.2.2 tag, source asset and trusted digest have been published.** For an unpublished local rehearsal use an updater that supports `--archive` and an adjacent verified SHA256SUMS. An older installed updater cannot acquire fixes from the new archive before it starts; use the verified bundled updater from the existing installation directory if required. Never replace the existing private `.env` with the example.

## Validation scope

See the adjacent BUILD_INFO.txt for actual package verification and disposable test results. Publication/download-mode validation and production-sized, lossless two-member HA validation are separate checks and are not implied by this declaration. Existing HA ordering/restart limitations described in RELEASE_6.2.0.md and RELEASE_6.2.1.md remain relevant.
