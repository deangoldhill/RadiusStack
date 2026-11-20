# RadiusStack 6.2.1 source candidate

**Not yet published.** This is a manually staged source candidate. Do not use the remote-download upgrade command until Dean publishes the exact 6.2.1 GitHub tag, asset, and verifiable digest. HA remains unvalidated for lossless two-node operation; see [RELEASE_6.2.1.md](RELEASE_6.2.1.md).

Fresh install: verify and extract `radiusstack-source.tar.gz`, run `bash setup_env.sh` to create a private `.env`, then validate with `docker compose config -q` and build the migrator, RADIUS and API images before starting services. The initialization schema includes `expected_plan_pod_enforcements` on the HA reconcile state table.

Upgrade: retain the existing private `.env`, Compose overrides, database and certificates. The 6.2.1 migration adds `expected_plan_pod_enforcements` without deleting existing data. The bundled updater supports `--to 6.2.1 --archive /absolute/path/radiusstack-source.tar.gz` with an adjacent matching `SHA256SUMS`; run it only on a **disposable copy** first, after confirming the already-installed updater supports `--archive`. A source rollback does not undo database migrations. Never substitute the staged candidate path for a published GitHub Release asset.

---

# RadiusStack 6.2.0 source candidate

**Known HA data-integrity risk:** do not enable HA on unvalidated pairs. See [RELEASE_6.2.0.md](RELEASE_6.2.0.md) for the committed-write ordering, scanner, and restart limitations. The local 192.168.4.37 installation was marked 6.1.1; preserve its full source and database before replacing files. This source candidate has not been published to GitHub.

Fresh installation: extract the verified `radiusstack-source.tar.gz`, run `bash setup_env.sh` to generate a private `.env`, then from that directory validate, refresh images and build explicitly:

```sh
docker compose config -q
docker compose pull --ignore-buildable mariadb web_ui phpmyadmin
docker compose build --pull db-migrate radius api
docker compose up -d
```

The source archive must include all `db-init` and `db-migrations` SQL and must not contain `.env`. `--pull` checks for newer patched images within the selected tag; it does not change a runtime major version or update an already-running container on its own. During an upgrade, this **new** updater checks fresh bases and pulls registry-hosted images **before downtime**, but an existing installation executes its **already-installed older updater first**; the new behavior takes effect only after that updater has been installed for subsequent upgrades. For the first upgrade using an older updater, release engineering must separately preflight `docker build --pull` and the staged images without changing production containers. The registry-hosted image pull uses the existing Compose configuration; if a release changes an image tag, independently pre-pull and validate that new tag before downtime. Refresh and test the pinned major/minor lines at every release, including Node, FreeRADIUS, MariaDB, Python, Nginx and phpMyAdmin; do not use an untested `latest` runtime tag. The Node API now targets Node 24 LTS instead of end-of-life Node 18. Rehearse container builds and application/RADIUS behavior on a disposable copy before deploying this candidate; a fresh base or major runtime can break dependencies/configuration. A failed registry pull stops the upgrade preflight rather than silently using a cached base. Node dependencies are installed by `npm install` (no lockfile), so image refresh alone does not guarantee reproducible dependency versions or fix dependency-level vulnerabilities. Existing installations remain unchanged until rebuilt/recreated from a verified release. The updater does **not** recreate MariaDB automatically: a fresh pull alone leaves the currently running database image untouched; update it separately with a database backup, MariaDB version-compatibility review and a verified restart.

Before GitHub publication, the installed updater's remote-download mode will not find 6.2.0. The bundled updater also supports `--to 6.2.0 --archive /absolute/path/radiusstack-source.tar.gz`; it requires an adjacent, matching `SHA256SUMS` and checks the archive before downtime. Use that bundled script from the installation directory, **not** an older installed updater that has no `--archive` option. It backs up code and dumps the whole database, then applies pending migrations and starts services. It does not roll back database DDL if a later step fails. Preserve `.env`, Compose overrides and certificate volumes. For published upgrades, use `./upgrade.sh --to 6.2.0` only after the exact GitHub asset and `sha256:` Release digest have been published and verified.

---

# RadiusStack 6.1.3 source candidate

This candidate is not yet a published GitHub Release or project tag. The installed updater is `upgrade.sh` (not `update.sh`). It fetches the named `radiusstack-source.tar.gz` asset from the GitHub Release tagged `6.1.3` and requires its published SHA-256 digest. The local release directory is not its download source. **Do not run `./upgrade.sh --to 6.1.3` before Dean publishes and verifies that exact asset.** Rehearse on a copy of the installation and preserve the private `.env`, database, certificates, Compose overrides, and generated RADIUS configuration.

## Changes since 6.1.2

The downstream destination modal has Hour, Day, Week, Month and Year totals, per-second rates, a seven-unit chart, manual Refresh and default-on Auto-refresh. Names are bold and clickable. See [RELEASE_6.1.3.md](RELEASE_6.1.3.md). The complete archive retains the 6.1.2 vendor feature and all earlier migrations.

## Fresh installation (after publication)

Extract `radiusstack-6.1.3/` and run `bash setup_env.sh` (or copy `.env.example` to a mode-0600 private `.env` and configure it), then validate Compose. The initialization schema includes both `mac_auth_devices.vendor_name` and `downstream_proxy_stats_minutes`.

## Upgrade from 6.1.1 or 6.1.2 (after publication)

From the **existing installation**, run `./upgrade.sh --to 6.1.3` only after the GitHub Release asset and digest have been published and verified. The migration runner applies pending vendor and downstream-statistics migrations in order, preserving existing data; an existing instance already on 6.1.2 receives only the new statistics table. The currently installed updater runs first; a fixed updater inside the new archive cannot repair an older updater before it starts. Schema changes are not rolled back with source.

## Historical 6.1.2 guidance

# RadiusStack 6.1.2 source candidate

This is a declared **candidate**, not a published GitHub Release or a project tag. **Do not run `./upgrade.sh --to 6.1.2` until Dean has published the exact `6.1.2` tag and `radiusstack-source.tar.gz`, independently verified its SHA-256 digest, and rehearsed the upgrade on a copy of the installation.** The installed 6.1.1 updater is the script that runs first; do not assume a fixed script inside this archive can repair an earlier updater before it starts. Preserve the existing private `.env`, database, certificates, generated configuration, and Compose overrides. The archive contains `.env.example` and `setup_env.sh`, but no `.env`.

## Changes since 6.1.1

MAC-auth vendor names are resolved locally at creation (including auto-create), stored, and backfilled in bounded batches. The per-tenant display checkbox defaults on; unknown vendors show `(Unknown Device Vendor)`. Settings cards have the requested RadSec/Notifications/Reply Attribute Catalogue visual changes, TOTP expiry is in General Settings, and Profile shows the authenticated administrator role below the version. See [RELEASE_6.1.2.md](RELEASE_6.1.2.md) for details. The complete archive retains all 6.1.1 files and earlier migrations.

## Fresh installation (after publication)

Extract the verified `radiusstack-6.1.2/` archive and run `bash setup_env.sh`, or copy `.env.example` to `.env`, set private values, and restrict mode to 0600. For HA secondaries, reuse shared keys and token from the primary. Validate with `docker compose config -q` before starting the stack. The initialization schema already includes `mac_auth_devices.vendor_name`.

## Upgrade from 6.1.1 (after publication and rehearsal)

The migration adds one nullable `vendor_name` column to `mac_auth_devices`; the API performs a bounded backfill of existing rows after startup. A rollback of source does not roll back database DDL. Do not run the command below before the published asset's digest and the previous installation's updater path have been verified:

```sh
./upgrade.sh --to 6.1.2
```

## Historical 6.1.1 guidance

### RadiusStack 6.1.1 source release

This document describes the **declared source version**, not a published GitHub Release. The `6.1.1` tag and release asset do not exist merely because `VERSION` changes. **Do not run an asset-based upgrade until Dean publishes the exact tag and source asset, verifies their digest, and rehearses the upgrade on a copy of the installation.** This archive has `.env.example` and `setup_env.sh` but **no `.env`**. Keep the existing installation's private `.env`, Compose overrides, database volumes, certificates and backups.

## Changes since 6.1.0

- Users and MAC-auth devices can be disabled/re-enabled in their edit forms; disabled identities appear red. The API uses tenant-scoped `Auth-Type := Reject` for local authentication; proxy-only downstream accepts intentionally remain valid. No schema migration is required.
- Disabling another admin's MFA now requires Admins read-write permission.
- Unused user/executive and failed-auth PDF exports are removed, with their Chromium/Puppeteer runtime dependency. JSON reports remain; clients calling PDF endpoints need to migrate.
- Browser-rendered RADIUS/admin data is escaped in affected pages to prevent HTML and inline-handler injection.
- Fresh-install setup gains the Bash `setup_env.sh` wizard, and the release archive omits `.env` entirely. See [RELEASE_6.1.1.md](RELEASE_6.1.1.md) for details and [RELEASE_6.1.0.md](RELEASE_6.1.0.md) for the preceding release's features.

## Fresh installation

After obtaining and verifying the published archive, extract it and enter `radiusstack-6.1.1`. Run `bash setup_env.sh` to create a private mode-0600 `.env` (choose HA Y or N, then answer the setup prompts), **or** run `cp .env.example .env && chmod 600 .env` and replace every public default secret before exposing the service. On an HA secondary, reuse the primary's shared HA token and encryption/session keys rather than generating independent values. Set the actual host IP/DNS, ports and peer address for your installation. Then:

```sh
docker compose -f docker-compose.yml config -q
docker compose -f docker-compose.yml up -d --build
```

Verify migrations and the API, web and Radius listeners on a disposable environment before production use. Test both members of an HA pair before relying on failover.

## Upgrade from 6.1.0

**Do not run this command until the 6.1.1 GitHub Release asset is actually published and its metadata exposes the correct `sha256:` digest.** Back up independently and rehearse the exact published asset on a copy of the installation first. Run the installed upgrader from the existing installation directory, not a script extracted from the new archive:

```sh
./upgrade.sh --to 6.1.1
```

The installed updater requires an existing `.env` and preserves it; a fresh archive has no `.env`. Do not replace the private file with `.env.example`. If the old installation's updater cannot process the published archive, stop: a corrected updater inside the new archive cannot repair the old updater before it starts. Use only a separately verified bootstrap path. These changes do not require a new schema migration, but older migrations remain packaged for upgrades from earlier versions. The exact published-asset upgrade and two-member failover have **not** been rehearsed by this declaration. Database DDL from any migration is not rolled back by a source rollback.

## Release identity

Planned Git tag: `6.1.1` (no `v`). Planned asset: `radiusstack-source.tar.gz`, rooted at `radiusstack-6.1.1/`. The local candidate is not a published release. After Dean publishes it, verify the downloaded asset digest against the Release metadata and both extracted version markers before using an updater on a customer system.
