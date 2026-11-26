# Automated local JSON backups

The **Platform Settings → Database Backup & Restore** section supports multiple local backup jobs in addition to its existing manual JSON export and import. These are the application's normal JSON backups: configuration, accounts, RADIUS objects, and optionally accounting/authentication/audit logs. They are **not** a MariaDB dump, a code archive, or the upgrade script's pre-upgrade snapshot.

Each job has a name, a schedule, a backup type (`full` or `partial`), an enabled state, and a count of successful backups to retain. A full JSON backup includes accounting, authentication, and audit logs. A partial JSON backup uses separate switches for those log categories. The page shows jobs, their status and next/last run times, and stored backups. A global super-admin with settings write permission can run a job manually, download a stored JSON file, or select one for restore. Restoring can overwrite existing application records and requires explicit confirmation. The existing manual upload/download controls remain available.

## Storage and scope

- Backups are local to the node's dedicated persistent backup volume. They are **not synchronized to the HA peer**. Copy the downloaded JSON to another protected location if host loss is in scope; retention alone is not disaster recovery.
- Only the primary runs jobs and permits job edits/restores. After promotion, review the node-local backup inventory before relying on its history.
- The files contain sensitive material, potentially including administrator credentials/API keys, RADIUS/NAS secrets, and log data. Restrict host and volume access and handle downloaded files as secrets.
- Retention is per job and counts successful saved backups; lowering a job's retention takes effect after its next successful backup. A failed backup must not cause older backups to be deleted. Deleting a job preserves existing files as unassigned backups, which can still be downloaded/restored.
- Scheduled exports read their tables from one consistent MariaDB transaction; the older manual JSON export still reads tables separately. Scheduled files are capped at 50 MiB, matching the existing manual JSON upload limit; an oversized job fails visibly without replacing older backups. Existing JSON restore semantics still apply. These files do not replace the upgrade script's database-and-code safety backup or a tested off-host recovery plan.

## Operational validation before deployment

Check fresh-install and existing-install schema migrations; verify the API backup volume survives an image rebuild/recreate; create multiple jobs and check independent retention; simulate a failed export and confirm the previous backups remain; download and parse a saved file; restore a selected disposable snapshot and compare with the ordinary JSON import result; confirm a secondary neither runs jobs nor accepts writes; and test authorized/unauthorized requests to all new routes. Do not test restores against production data without a separate recovery plan.
