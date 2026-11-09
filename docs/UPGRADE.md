# RadiusStack 6.1.1 source release

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
