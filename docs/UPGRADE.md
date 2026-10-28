# RadiusStack 6.0.1 source release and upgrade

This is a source release. The prepared folder and `radiusstack-source.tar.gz` are **not** a published GitHub Release. Dean commits, tags `6.0.1` (without `v`), creates the Release and uploads the exact verified archive manually. The CI tag workflow validates the source and retains an artifact; it does **not** publish a Release.

## What's included

- HA accounting/authentication scan cursor repair: `20261026_ha_sync_state_seed.sql` inserts missing `radacct` and `radpostauth` cursor rows without resetting existing progress. The API prevents overlapping scans and fails instead of repeatedly enqueueing when a cursor is missing or fails to advance.
- Additive `20261027_downstream_radius.sql` schema for tenant-owned downstream destinations and NAS/profile routes. Native FreeRADIUS policy selects a known user's profile route before the packet-source NAS route. Proxy-only and duplicate modes, optional validated duplicate responses, destination activation, and the destination/NAS/profile UI are included.
- Proxy-only accounting validates the downstream Accounting-Response before the main RADIUS container performs local SQL accounting. Future accounting packets contribute to local plan usage; past packets absent from the local accounting table are **not** backfilled. Proxy-only authentication still uses the downstream decision. NAS edits preserve the shared secret when the password field is blank; a nonempty value explicitly replaces it. NAS list responses do not disclose stored secrets.
- HA replay batching and other unreleased source changes accumulated since the 5.5.7 package are part of this complete source snapshot. Review the source diff and migrations before using it on another installation.

## Fresh installation

The extracted `radiusstack-6.0.1` directory contains `.env` with intentionally **public, insecure defaults**, copied byte-for-byte from `.env.example`. Change passwords and encryption keys and set a reachable `RADSEC_SERVER_DNS` before exposing a production service. Never copy the development server's private `.env`. Ensure the published ports are free, then run from the extracted directory:

```sh
docker compose config -q
docker compose up -d --build
```

Fresh initialization and the ordered migrations must succeed before authenticating clients. Confirm all services are running, the web page renders and FreeRADIUS logs `Ready to process requests`. Test PAP and Accounting-Start from a configured NAS before putting it into service.

## Upgrade from a published 5.5.7 installation

**Do not run this command until the 6.0.1 GitHub Release asset is published, its API metadata exposes a `sha256:` digest, and the source has been reviewed.** Take an independent off-host database backup first; schedule downtime. If HA is enabled, upgrade and validate the **secondary first**, then the primary; coordinate failover and traffic separately. Do not clear the HA queue or manually reset cursor rows.

From the existing installation directory, preserve its customized `.env` and Compose overrides and use its *installed* updater:

```sh
./upgrade.sh --to 6.0.1
```

The updater verifies the exact tag, asset URL and published digest, rejects unsafe archive members, builds new images before downtime, then stops local writers, backs up code and MariaDB, overlays managed source, applies tracked migrations and checks service readiness. It leaves `.env`, generated RADIUS material, Compose overrides and named volumes unchanged. It retains a restricted detailed log and backup under `upgrade-backups/`. The SQL dump and logs may contain customer data or credentials; protect and copy them off-host. The script does not orchestrate a cluster-wide HA upgrade.

After the secondary returns healthy, verify its HA and RADIUS state before upgrading the primary. After both nodes are updated, confirm the HA queue drains rather than growing from repeat scans, and test tenant-scoped proxy auth/accounting with a real NAS. Verify that a new accounting update increases local plan usage and a NAS edit with a blank shared-secret field leaves the client working. These are operational checks, not claims made by packaging tests.

For versions older than 5.5.7, use the verified historical upgrade/bootstrap path to 5.5.7 first or rehearse a direct upgrade on a disposable copy of that exact version and data. The oldest installed updater may have a self-overwrite/readiness bug; the new archive cannot fix an old updater before it downloads the new code. Do not guess a direct path.

If an upgrade fails after writers stop, the updater restores old managed **code** but **does not roll back database DDL or restart old writers**. Inspect its backup and detailed log, assess schema compatibility, and restore the database only after explicitly deciding what newer data would be lost.

## Publishing boundary

The Git tag must point to the exact reviewed source containing `VERSION=6.0.1`. Upload the prepared `radiusstack-source.tar.gz` asset to the manually created Release under tag `6.0.1`, then independently compare the published asset SHA-256 with the local digest. Do not tag a different tree or replace the asset without rebuilding and re-verifying its digest and upgrade path.
