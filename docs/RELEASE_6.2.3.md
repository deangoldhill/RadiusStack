# RadiusStack 6.2.3

Complete server source for fresh installations and upgrades. Changelog baseline: **6.2.2**. This is a manually staged source candidate; declaring it does not publish a GitHub tag/Release or deploy an existing installation.

## Backup and restore

- Manual JSON upload restores now accept **700 MB (700,000,000 bytes)**. Uploads are staged in private temporary files instead of RAM. Accounting, authentication and audit arrays are parsed incrementally and staged on disk, avoiding whole-file JavaScript string limits. Full-file syntax and relevant tenant references are checked before database mutations.
- Scheduled full and accounting-inclusive backups no longer fail at the separate 50 MiB save limit. Configuration and bounded primary-key pages of selected logs are read from one consistent snapshot, written/checksummed incrementally and capped at the same 700 MB ceiling. BIGINT pagination cursors retain their precision.
- Stored downloads and restores stream checksum-verified files rather than buffering the entire artifact. Failed/oversized exports clean up temporary files and do not remove previous successful backups. Restore/upload staging is removed on handled completion/failure.
- Nginx grants uploaded restore enough body space for multipart overhead without duplicate request buffering. Node/Nginx deadlines are extended for uploads, job execution and stored restore/download. The UI rejects an oversized selected file before sending it.
- Scheduled job failures expose sanitized useful reasons, including storage capacity/permissions, size limits and accounting-table read errors, in both the API and persisted job status.
- The existing Upload & Restore flow, JSON format, tenant identity checks, transaction and merge/overwrite semantics remain. The older manual export-generation endpoint is unchanged; these streaming export improvements apply to scheduled/local backups. An external proxy may impose additional limits.

## Audit coverage and corrections

- Automatic MAC creation emits one system event only after a genuinely new device commits, with explicit tenant/Global scope and device/profile/plan identifiers. Existing/ignored devices and rolled-back creations do not produce creation-success events.
- All HA operator commands are audited: pause/resume, full sync, log reconciliation, promote/demote, statistics reset, manual sync and RadSec certificate sync. HA authorization now supplies the trusted administrator identity for attribution. Full sync is recorded as queued; reconciliation records start and separate completed/partial/failed outcome. This is audit coverage, not an HA replication algorithm change.
- Added events for EAP certificate/private-key exports, tenant/trust CA and tokenized RadSec artifact downloads, notification/syslog tests, own-account theme changes, background backup outcomes, actual automatic plan-cycle changes and downstream changes saved before failed activation.
- Container restart requests are audited before Docker invocation, including API self-restart; available completion/failure callbacks retain their events. Notification tests returning HTTP 200 with ok:false are recorded as failed tests.
- Added explicit denials for rejected tenant selection, forbidden Global-context operations and Global-only controls. Corrected missing tenant attribution on administrator key/MFA actions, accounting deletion, password change and TOTP events without changing authorization gates.
- Audit metadata excludes raw attribute values, unrestricted query objects, restore database warning/error values, download tokens, credentials and key material. Ordinary polling/internal replication is not blanket-audited, and existing successful CRUD events are not duplicated.

## Settings UI

- Radius Stats Maintenance uses the same heading size and bold weight as neighboring sections.
- Backup controls and job/artifact lists use Backup & Restore, Full Backup, Partial Backup and Automated local backups wording.
- Removed the redundant automated-backup explanatory/warning paragraphs while retaining real .json filename references and the 700 MB upload check.

## Installation and upgrade

- Fixed updater file coverage: Nginx configuration, documentation, README, setup wizard and public environment template are backed up, deployed and restored with application code. Private `.env` and Compose overrides remain untouched; symlinked newly managed paths are refused.
- **The first upgrade from 6.2.2 or earlier must invoke the verified 6.2.3 bundled updater from a separate extracted path, with the existing installation as the working directory.** The older installed updater does not copy Nginx configuration and therefore cannot activate the larger restore limit by itself. See the prominent safe procedure in [UPGRADE.md](UPGRADE.md).

The archive includes `setup_env.sh`, `.env.example`, initialization SQL and every existing versioned migration; it contains **no .env**. Fresh installs run `bash setup_env.sh`, review the private mode-0600 configuration and validate Compose before building/starting. Upgrades preserve private .env, overrides, data, generated RADIUS configuration, certificate and backup volumes. There are no new SQL migration files relative to 6.2.2; existing migrations and their checksums are retained.

**Before publication, do not use `./upgrade.sh --to 6.2.3` in GitHub-download mode.** Verify the adjacent SHA256SUMS and invoke the verified bundled 6.2.3 updater from a separate extracted path, with the existing installation as the working directory; see [UPGRADE.md](UPGRADE.md). Dean publishes the exact asset/tag and trusted digest manually. Consult the adjacent BUILD_INFO.txt for checks executed for this package versus prior source-change tests.

## Existing limitations

- Existing HA ordering/scanner/recovery risks remain: this release does not guarantee lossless two-node replication. Keep HA disabled on unvalidated pairs; see earlier release notes.
- JSON restore retains existing INSERT IGNORE and importer behavior; successful row-attempt totals are not an exact database-replacement guarantee. Source rollback does not undo database DDL. Keep an independent recovery backup.
- Large-file paths target log-heavy backups; non-log configuration still resides in memory. Allow disk capacity for upload/staging and database growth/undo/indexes. A process/host crash may leave staging directories behind.
- Auditing uses the existing best-effort database/syslog writer; database outages or abrupt process death can still prevent persistence.
- The existing global radcheck username/attribute uniqueness constraint is unchanged; duplicate identities across tenants are not introduced by this release.
