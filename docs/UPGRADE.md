# RadiusStack 6.0.2 source release and upgrade

This is a prepared **source** release, not a GitHub Release. Dean commits the reviewed source, tags `6.0.2` (no `v`), creates the GitHub Release, and uploads the **exact** verified `radiusstack-source.tar.gz` manually. Tag CI validates and retains an artifact but does not publish. The installed updater downloads the release by tag and insists on an API-provided SHA-256 digest; do not invoke it before the asset and digest are published.

## Fix and contents

6.0.1 hard-coded `/opt/native-radius-venv/lib/python3.12/site-packages` in the Radius image `PYTHONPATH` and both `rlm_python3` modules. Alpine can install Python 3.14 into a fresh build, hiding `pyrad` from embedded Python and preventing FreeRADIUS startup. 6.0.2 installs pinned `pyrad` and `PyMySQL` (plus dependencies) into `/opt/native-radius-deps`, a version-independent path used by the image and both auth/accounting module configurations. Do not install dependencies into a running container as a persistent fix. **No new SQL migration** is needed; all historical migrations, including the HA seed and downstream proxy migration, remain in the full source release. It retains the 6.0.1 downstream proxy and NAS behavior.

## Fresh installation

The extracted `radiusstack-6.0.2` contains `.env` with intentionally **public, insecure defaults** matching `.env.example`. Change passwords, encryption keys, and the RadSec hostname for production; do not reuse someone else's `.env`. From the extracted folder, once intended ports and DNS are verified:

```sh
docker compose config -q
docker compose up -d --build
```

Verify migrations completed, all intended services are running, the web UI loads, and the Radius log reaches `Ready to process requests`. On a Python 3.14 build, verify the container's **system interpreter** imports both `pyrad` and `downstream_helper` (not only the venv Python). Exercise a real NAS PAP authentication and accounting request before production use.

## Upgrade from an installed 6.0.1

**First** confirm that a GitHub Release under tag `6.0.2` exists, with exactly one asset named `radiusstack-source.tar.gz`, and that its published SHA-256 matches the reviewed archive digest. Take an independent off-host database backup, schedule downtime, and keep a copy of the current `.env` and Compose overrides privately. The installed **6.0.1 updater**, not the new release's updater, performs this transition; it validates the tag, digest, archive and image builds before stopping writers. From the installed directory, after publication:

```sh
./upgrade.sh --to 6.0.2
```

It preserves the customized `.env`, Compose overrides, generated RADIUS files and named volumes. It applies tracked migrations idempotently and keeps a restricted backup/debug log under `upgrade-backups/`. Logs and SQL dumps may contain sensitive customer data. A failed deployment may restore old **code** without rolling back database DDL or restarting old writers; inspect the log and backup before further action. The update does not orchestrate traffic failover.

For HA, back up both nodes; upgrade and verify the **secondary first**, then the primary. Do not clear the HA queue or reseed cursors by hand. After both nodes are running, confirm queue health and test downstream PAP/accounting against a real NAS, including local plan-usage updates. If 6.0.1 Radius is currently down from the Python import error, the downloaded 6.0.2 code should remove that specific startup blocker, but do not assume other service or credential problems are fixed.

For installations older than 6.0.1, rehearse the exact installed updater and data in a disposable copy or follow its documented supported upgrade/bootstrap path. New 6.0.2 code cannot fix an older updater's pre-copy behavior.

## Publishing boundary

The tag must reference the exact reviewed commit with `VERSION=6.0.2` and a root `.env` byte-identical to `.env.example`; never commit a running installation's private `.env`. Upload this package as the Release asset and independently read back the published SHA-256. Do not publish a different tree or replace the asset without repeating the archive/extraction and upgrade checks.
