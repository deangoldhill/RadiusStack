# RadiusStack 6.0.5 source release candidate

This folder and `radiusstack-source.tar.gz` are a prepared **source candidate**, not a published GitHub tag or Release. Dean reviews, commits and publishes releases manually. The archive contains public `.env.example` defaults as a mode-0600 `.env` solely for a **fresh installation**; on upgrades the existing private `.env` must be preserved and never copied into the release.

## Changes since the prepared 6.0.4 source candidate

- Downstream destination saves activate the primary Radius container using the corrected API dependency wiring. The feature-specific dashboard widget was removed; destination configuration remains in its own navigation page.
- On an HA secondary, replayed downstream-destination changes commit before one coalesced Radius restart. NAS/profile routing changes do not require that restart.
- Secondary-generated `radacct` and `radpostauth` records are scanned, queued and delivered back to a primary-only encrypted HA endpoint. Acknowledgment and transactional cursor replay make network retries idempotent. Only the peer's HA-owned row IDs and exact parameterized accounting/auth-log upserts are accepted. Reverse replay respects HA pause and log reconciliation.
- If an accounting session's unique key conflicts with a different row ID, reverse replay fails closed and retains the batch rather than changing a primary row's identity. Resolve the conflict through reviewed reconciliation; later queued rows remain pending behind it.
- The 6.0.4 migration-runner correction for upgrades from a populated 6.0.2 database remains included. No new SQL migration is introduced by 6.0.5.

## Fresh installation

Review `.env.example` and configure unique secrets, host/port and HA node identity as appropriate. The prepared `.env` is an exact copy of the public defaults, **not** the dev instance's private runtime file. From the extracted `radiusstack-6.0.5` folder:

```sh
docker compose -f docker-compose.yml config -q
docker compose -f docker-compose.yml up -d --build
```

Confirm migration completion, API/web listeners and `Ready to process requests` in Radius logs. HA requires distinct `HA_DB_OFFSET` values (1 and 2), the same strong `HA_API_TOKEN`, each node's actual `HA_PEER_IP`, and the appropriate `HA_ROLE`. Test auth/accounting on both nodes and verify counts and representative IDs on both databases before treating failover as validated.

## Upgrade from 6.0.4

**Do not run `./upgrade.sh --to 6.0.5` until the exact archive is uploaded to the 6.0.5 GitHub Release and GitHub API metadata exposes its `sha256:` digest.** The installed updater downloads and verifies that published asset; this local candidate is not sufficient. Take an independent off-host database backup and rehearse on a copy of the actual installation before production. Run the installed updater from the existing installation directory, preserving its private `.env` and Compose overrides:

```sh
./upgrade.sh --to 6.0.5
```

For an HA pair, upgrade the receiving primary before enabling reverse delivery from the secondary. Then upgrade the secondary; both nodes need 6.0.5 code. Allow the queue to drain and verify secondary-generated auth and accounting rows appear on the primary without overwriting primary-owned rows. If a conflict is reported, stop and reconcile instead of deleting queued messages.

For older installations, rehearse the exact source version and populated schema. The published 6.0.3 archive had a migration-runner defect on an existing 6.0.2 downstream-destination table; do not retry the unchanged 6.0.3 asset. A failed upgrade restores managed code but **does not roll back database DDL**. Inspect the restricted backup/debug log and database compatibility before restarting old writers.

## Publication boundary

Tag **`6.0.5`** (without `v`) on the exact reviewed source represented by this candidate, create the Release, and upload `radiusstack-source.tar.gz` unchanged. Independently compare the published asset SHA-256 with the locally verified digest before telling customers the upgrade command is usable. This candidate does not claim a live HA pair/failover test or an upgrade of any production instance.
