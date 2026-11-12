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
