# RadiusStack 6.1.0 source release

This document describes the **declared source version**. The `6.1.0` GitHub tag and release asset are not created by changing `VERSION`; follow the upgrade procedure only after Dean publishes and verifies them. This archive contains the complete application source, the public `.env.example`, and an identical mode-0600 `.env` for **fresh installations only**. It does not contain the dev server's private environment. Existing installations must preserve their own `.env`, Compose overrides, database volumes, and operational backup files.

## Changes since 6.0.6

- Settings cards are collapsible, with scope-specific expanded defaults and irrelevant Global controls removed. Tenant certificate settings are labeled RadSec.
- Global Active Sessions aggregates tenant sessions and identifies their tenant, while remaining read-only. Tenant session actions remain tenant-scoped.
- Pushbullet notifications have scoped configuration, optional recipient email, and an authorized test message with safe delivery diagnostics.
- See [RELEASE_6.1.0.md](RELEASE_6.1.0.md) for concise release notes. Features and migrations from 6.0.6 remain included; see [RELEASE_6.0.6.md](RELEASE_6.0.6.md) for those earlier changes.

## Fresh installation

Review `.env.example`; replace public default secrets with unique credentials and set host ports, DNS and HA member values for your installation. Do not use the template credentials on a reachable service. After the 6.1.0 source asset is published and verified, from `radiusstack-6.1.0`:

```sh
docker compose -f docker-compose.yml config -q
docker compose -f docker-compose.yml up -d --build
```

Verify migration completion, the API and web listener, and Radius readiness. For HA, set distinct `HA_DB_OFFSET` values (1 and 2), appropriate `HA_ROLE` and actual peer addresses. Test both members before relying on replication or failover.

## Upgrade from 6.0.6

**Do not run this command until the 6.1.0 GitHub Release asset is actually published and its metadata exposes the correct `sha256:` digest.** Back up the database independently and rehearse the exact published asset on a copy of the real installation. From the existing installation directory, use the **installed** updater so its rollback, private `.env`, and Compose override behavior apply:

```sh
./upgrade.sh --to 6.1.0
```

This version's Settings and session-visibility changes do not require a new schema migration. Existing migrations remain in the source release and must still run on older installations. The upgrade from the published asset has **not yet been rehearsed**; declaring the version on the dev host is not an upgrade test. On an HA pair, back up and plan an ordered upgrade of both members with compatible schemas and controlled replay. A live two-member transfer/failover was not demonstrated for this declaration.

For older installations, rehearse the exact source version and populated schema before production. A failed upgrade can restore managed source files but **cannot roll back database DDL**. Inspect the restricted upgrade log and database compatibility before restarting an older writer.

## Release identity and verification

Planned Git tag: `6.1.0` (no `v`). Planned asset: `radiusstack-source.tar.gz`, rooted at `radiusstack-6.1.0/`. Neither the tag nor asset is created by this declaration. After publication, verify the downloaded asset digest against GitHub Release metadata and its extracted version markers before upgrading a customer system. Production deployment is separate from this development declaration.
