# Large JSON upload restores

The existing **Platform Settings → Database Backup & Restore → Upload & Restore** workflow accepts one JSON file up to **700 MB (700,000,000 bytes)**. The page stays in its existing Restoring state until the request completes. This is not a background job, resumable upload or new backup format.

- The API writes the upload into a private temporary directory instead of buffering it in memory.
- JSON is fully parsed and log tenant references checked before opening the restore transaction. Accounting, authentication and audit rows are staged privately on disk and inserted in the existing 50/100-row batches, avoiding a whole-file JavaScript string and whole-log arrays.
- Existing tenant identity checks, permissions, overwrite/merge rules, transaction and warnings remain. In particular, duplicate log IDs retain the existing INSERT IGNORE behaviour; this change does not make restore an exact database replacement.
- Uploaded and staged temporary files are removed on handled completion/failure. An abrupt process/host crash may leave temporary directories behind; inspect and remove abandoned `radiusstack-upload-*` and reader staging directories only when no restore is running.
- Nginx grants only the restore-upload endpoint a larger body limit with multipart headroom and disables duplicate proxy request buffering. Upload/API response deadlines are extended to one hour. An external reverse proxy may impose a separate size or timeout limit.
- Keep the browser open and avoid concurrent restores. A client timeout or browser close is not proof that a transaction stopped; check the audit log and resulting data before retrying.

## Capacity and scope

Provide space for both the uploaded file and staged logs (roughly twice the JSON size for a log-heavy input), plus database growth, indexes and transaction/undo/redo overhead. Do not assume 1.4 GB of free disk is sufficient for a 700 MB restore. Non-log configuration arrays are still retained in memory; the large-file path targets log-heavy backups, not arbitrarily large individual fields or configuration-only files.

The older manual export-generation endpoint remains unchanged. Scheduled local backups now stream their selected log tables from a consistent snapshot and save/checksum incrementally, up to the same **700 MB** ceiling; stored downloads/restores are streamed too. General JSON-body limits and non-backup Nginx body limits are unchanged. No existing instance or previously staged release asset is patched by these source changes.
