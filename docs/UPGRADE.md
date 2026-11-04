# RadiusStack 6.0.6 source release

This archive contains the complete application source, the public `.env.example`, and an identical mode-0600 `.env` for **fresh installations only**. It does not contain the dev server's private environment. Existing installations must preserve their own `.env`, Compose overrides, database volumes, and operational backup files.

## Changes since published 6.0.5

- **Auth Logs processing server:** newly written `radpostauth` rows record `origin_node` from the processing member's database auto-increment offset (1 or 2). The new Server column displays Server 1/2, unchanged through HA replay. Existing rows remain NULL/Unknown; neither HA role nor ID parity is used to guess their origin. A fresh-install schema update and idempotent `20261103_authlog_origin_node` migration provide the column.
- **Plans:** tenant-scoped Depleted Users counts with numeric sorting, and corrected selected-tenant plan-detail statistics. Global and tenant contexts remain distinct.
- **Documentation:** expanded operator documentation and API catalogue, including Global versus selected-tenant routes, downstream destination examples, and internal HA peer-route descriptions without interactive tester calls.
- **Tenant 2FA authorization:** enforce-2FA by tenant ID now checks a tenant administrator's authorized membership and selected/assigned tenant before loading the target; a Global super-admin retains the ability to target by ID. This is an authorization fix, not merely a documentation change.
- All functionality in the published 6.0.5 source release remains included, including HA reverse authentication/accounting replay and secondary destination activation.

## Fresh installation

Review `.env.example`; replace public default secrets with unique credentials and set host ports, DNS and HA member values for your installation. Do not use the template credentials on a reachable service. From `radiusstack-6.0.6`:

```sh
docker compose -f docker-compose.yml config -q
docker compose -f docker-compose.yml up -d --build
```

Verify migration completion, the API and web listener, and Radius readiness. For HA, set distinct `HA_DB_OFFSET` values (1 and 2), appropriate `HA_ROLE` and actual peer addresses. Test both members before relying on replication or failover.

## Upgrade from published 6.0.5

**Do not run this command until the 6.0.6 GitHub Release asset is actually published and its metadata exposes the correct `sha256:` digest.** Back up the database independently and rehearse the upgrade on a copy of the real installation. From the existing installation directory, use the **installed** updater so its rollback, private `.env`, and Compose override behavior apply:

```sh
./upgrade.sh --to 6.0.6
```

The upgrade adds nullable `radpostauth.origin_node`; it does not backfill old logs. The migration is repeatable. On an HA pair, migrate the receiving primary before upgrading the secondary writer to emit new-origin rows, then upgrade the secondary; both peers must have the new schema before such rows replicate. Verify each writer records its own offset and replay preserves it. Pause or control HA replay during a staggered upgrade if needed. This dev release was checked on a single member; **a live two-member transfer/failover was not demonstrated**.

For older installations, rehearse the exact source version and populated schema before production. A failed upgrade can restore managed source files but **cannot roll back database DDL**. Inspect the restricted upgrade log and database compatibility before restarting an older writer.

## Release identity and verification

Git tag: `6.0.6` (no `v`). Asset: `radiusstack-source.tar.gz`, rooted at `radiusstack-6.0.6/`. Verify the downloaded asset digest against GitHub Release metadata and its extracted version markers before upgrading a customer system. Production deployment is separate from this release.
