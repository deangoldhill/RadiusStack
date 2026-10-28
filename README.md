# RadiusStack

A complete, modern, containerized RADIUS authentication stack designed for ease of deployment, security, and extensive API-driven management. RadiusStack bundles FreeRADIUS, MariaDB, and a custom Node.js REST API inside a streamlined Docker Compose environment, paired with a sleek, responsive Web UI.

Useful for managing Wi-Fi access points, remote access, or network appliance logins, RadiusStack provides full control over users, usage plans, profile attributes, and feature riich monitoring and analytics.
Designed for security and simplicity. 

**Try the demo:**
https://demo.radius-stack.com  
admin account:  admin / demo123  
Reports account:  reports / demo123  

## Key Features
* **Modern Web Interface:** WebUI frontend for managing NAS clients, users, profiles, plans etc. Also view logs for all containers within the webui.
* **Full REST API:** The managment application is an API server. The Webui only interacts with the API and therefore doesn't have access to the backend database.
* **Advanced Security:** Supports Time-Based One-Time Passwords (TOTP) for radius users and Webui administrators
* **Intelligent Backups:** Export and safely restore JSON-based database configurations across version upgrades.
* **Automated Certificate Generation:** One-click custom SSL/EAP certificate generation or direct file uploads.
* **Live Analytics:** Monitor active sessions, view authentication/accounting logs, and detailed administration audit log.
* **High Availability:** Full config, object and session sync between members. See the wiki for more details. 

HA sync uses the configured peer's API (`HA_PEER_IP`) with AES-256-GCM encrypted payloads. A public IPv4 peer is accepted, but the existing HA transport is **plain HTTP**, not end-to-end TLS, and the published API port may expose unrelated endpoints. Prefer a private tunnel/VPN and firewall the API to the peer; do not expose database, phpMyAdmin, or the general API broadly. Source-address pinning checks the actual socket address, not `X-Forwarded-For`, so NAT/proxy paths need verification. Leave `HA_ENABLED=false` until both nodes and the shared `HA_API_TOKEN` are configured and tested. `HA_DB_OFFSET` and `auto_increment_increment=2` partition some **new** auto-generated IDs; they do not reconcile existing data. Do not bootstrap HA by enabling both populated nodes and pressing Full Sync: the current endpoint queues unbounded upserts, does not delete stale secondary rows, and acknowledges some duplicate conflicts without resolving them. Back up both databases, designate one authoritative primary, prepare a clean/verified secondary copy, isolate secondary writers, check schema/offsets/queue and row counts, then rehearse sync and failover on disposable clones before production use. The primary automatically reconciles its RadSec and shared certificate files to the HA secondary before replaying RadSec-dependent database writes, retries failed transfers, and rechecks unchanged files every five minutes to recover a replaced peer volume. The secondary installs each file by atomic rename and restarts Radius only when files changed, Radius is down, or a RadSec enable setting is replayed. Enable/proxy-enrollment provisions the tenant CA before publishing `radsec_enabled`; `/api/ha/status` exposes `certificateSync.pending`, `lastSuccess`, and `lastError`. Both HA members must run this code for automatic recovery. Each member needs its own `RADSEC_SERVER_DNS`; the bundle shares the CA/tenant trust but **never** the primary's hostname-specific server leaf. Certificate transfer is automatic, not a manual enrollment step. Back up both databases and certificate volumes before upgrading, and test TLS/RADIUS failover on the actual pair before routing production traffic to the secondary.

HA queue replay sends ordered encrypted batches of up to 200 rows and 1 MiB each, and starts up to 20 batches per worker pass while its 20-second budget remains, instead of one HTTP request and delete per row. The secondary stores a transactional replay cursor in `ha_replay_state` and confirms the final batch ID; a lost acknowledgement leaves primary rows queued and retries without double-applying committed SQL. Both members must have the new API code and the `20261020_ha_replay_state` migration applied before the primary uses batch replay: an old peer rejects `/api/sync/batch` and the queue deliberately remains pending. The legacy `/api/sync/execute` route remains for an older primary during staged upgrades; do not switch the primary to batch mode before the secondary is ready. Track `/api/ha/status.queueLength` and `stats` during a representative load test; batching improves transport overhead but does not guarantee unlimited capacity.

## Fresh installation

Extract the versioned source asset on the new machine. It contains a grouped `.env` with working **public defaults**, copied from `.env.example`, and needs no first-run script. From that directory run `docker compose up -d --build` (provided its published ports are free). Review `RADSEC_SERVER_DNS` before using RadSec. **Change the shared default passwords and encryption key before exposing a production installation**, and keep the customized `.env` private and unchanged during upgrades. Never copy an existing machine's private `.env` into public source.

## Release upgrades

**Version 6.0.2** fixes the downstream RADIUS Python module import on newer Alpine/Python base images (including Python 3.14). It installs `pyrad` and `PyMySQL` into a version-independent directory used by both authentication and accounting callbacks. No SQL migration is added beyond those already in 6.0.1; the full source archive retains all previous migrations. For an installed 6.0.1, run its installed `./upgrade.sh --to 6.0.2` only after the matching 6.0.2 GitHub Release asset and SHA-256 digest are published. See the [6.0.2 upgrade guide](docs/UPGRADE.md). This prepared archive is not a published Release; Dean commits and publishes it manually.

**Version 6.0.1** includes the HA cursor-seeding/overlap fix for repeated accounting queueing and the complete tenant-scoped downstream RADIUS destination, NAS and profile route feature. The main FreeRADIUS container handles proxy-only and duplicate modes; proxy-only accounting validates the downstream reply and also records local plan usage for future accounting packets. A blank shared-secret field on NAS edit retains the existing value. The release includes the additive HA seed and downstream-routing migrations. For HA, upgrade the secondary and verify it before the primary. The 6.0.1 source package is affected by the Python-path issue fixed in 6.0.2 when built on newer Alpine/Python images.

**Version 5.5.6** fixes HA full sync and replay for the `admins.permissions` JSON field, including admin rows already queued by an older primary. Keep the HA queue intact; upgrade the secondary first and verify delivery after both peers are updated. It also adds a nonblocking GitHub release check below the sidebar version, with a one-hour browser cache and an honest fallback when GitHub is unavailable. There is no new SQL migration. Use the [5.5.6 upgrade guide](docs/UPGRADE.md) only after its matching GitHub Release asset and digest are published; publishing is a separate manual step.

**Version 5.5.5** hides the tenant-specific depleted-allocations widget in Global context (and skips its requests), while retaining it within selected tenants. The Global RADIUS Container Health widget now shows `healthy` when all five RadiusStack containers are running and `Degraded` if any is stopped or missing, rather than interpreting the absence of optional Docker healthchecks as `unknown`. This is a running-state indicator, not an application-level health probe. It retains the 5.5.4 updater and HA peer improvements; there is no new SQL migration. Use the [5.5.5 upgrade guide](docs/UPGRADE.md) only after its matching GitHub Release asset and SHA-256 digest are published. Installed 5.5.2 needs the verified bootstrap; 5.5.3 and 5.5.4 can use their installed updater.

**Version 5.5.4** accepts a configured usable public IPv4 HA peer (as well as a private IPv4 peer) while rejecting loopback, link-local, multicast and malformed addresses. The updater runs a private copy of itself, preventing Bash from reading replacement bytes when `upgrade.sh` is updated. Its restricted debug log retains all file, migration and Docker details; the terminal shows concise progress or failure milestones and the log location instead of dumping the transcript. HA remains plain HTTP: protect the transport with a private tunnel/VPN and firewall; this fix does not make direct Internet API exposure safe. No new database migration is added. **5.5.2 installations must run the digest-verified 5.5.4 bootstrap** in the upgrade guide, not their installed updater; 5.5.3 installations can run their installed updater directly after the 5.5.4 Release asset and digest are verified.

**Version 5.5.3** fixes automatic RadSec proxy enrolment so its client, credential set, and NAS assignment are created together, with unenrolment revoking the linked set. A single RadSec client with a missing/mismatched credential-set/NAS link now emits an actionable warning rather than stopping upgrades for every tenant; missing database schema or failed SQL remains fatal. The upgrader adds a restricted, detailed per-attempt debug transcript of release verification, file copies, Docker commands/results, migration operations and readiness/rollback steps, plus private container-log snapshots on failure. It also atomically replaces its own script at completion. There is **no new database migration** in this release; required historical SQL remains included.

**Version 5.5.2** adds bulk Reset Usage on Users and MAC Auth; depleted-allocation details on the Dashboard, Reports and executive report/PDF; a full-width User-Specific Executive Report with reject analysis below; date-only Last Online columns; and a date-only Last Login column for administrators. Completed password-only and successful 2FA logins persist a per-administrator timestamp. The additive `20261011_admin_last_login.sql` migration backfills existing accounts from completed-login audit events; failed 2FA and password-only attempts are excluded. No real usage records need resetting for this release.

**Version 5.5.1** displays the installed source version in General Configuration, the Profile popup and the sidebar under Network Auth. The value comes from the installed `VERSION` file mounted read-only into the web UI, so it is not hard-coded into the pages. No database schema change is required for 5.5→5.5.1.

**Version 5.5** adds correctly tenant-attributed login audit entries and a cross-tenant Global audit view; default-on dashboard auto-refresh; administrator-specific colour preferences with a platform default; updated Syslog/SIEM event fields, destination validation and a persistent auth-forwarding cursor; Docker-backed Global Server Health; refreshed guide and API routes; and Called-Station-ID capture/filtering. Fresh installs include the schema, while upgrades from 5.4 apply additive, tracked migrations that retain existing records.

For an installation already on **published 6.0.1**, use its installed `./upgrade.sh --to 6.0.2` only after the 6.0.2 GitHub Release asset and SHA-256 digest are published. For older installations, follow the historical upgrade/bootstrap path or rehearse a direct upgrade on a disposable copy; an old self-overwriting updater is not repaired by packaging a new one. `VERSION`, the Git tag and the Release must all say `6.0.2` without a `v` prefix. The updater preserves a customized `.env`, generated RADIUS files, Compose overrides and named volumes, but database DDL cannot be automatically rolled back. Dean manually commits, tags, creates the Release and uploads its asset; the tag CI only validates and retains an artifact.

## Documentation

For full installation instructions, feature breakdowns, and management guides, please visit the **[RadiusStack Wiki](https://github.com/deangoldhill/RadiusStack/wiki)**.

---

<img width="1888" height="962" alt="image" src="https://github.com/user-attachments/assets/14cebbd2-aaed-418a-afa7-97c7669fe869" />
<img width="1700" height="688" alt="image" src="https://github.com/user-attachments/assets/58238fa6-dbcd-4f00-9848-3a1b7f977b02" />
<img width="1685" height="323" alt="image" src="https://github.com/user-attachments/assets/f0b15a8b-02dc-4c73-808f-14fdeb20eafa" />
<img width="1689" height="464" alt="image" src="https://github.com/user-attachments/assets/5ff147ed-9e6d-4bda-bd51-8bcb9209d36f" />
<img width="1665" height="517" alt="image" src="https://github.com/user-attachments/assets/c788d08b-84ff-425b-92f6-1523e35312bb" />
<img width="1688" height="923" alt="image" src="https://github.com/user-attachments/assets/e404f667-894f-4ed5-816a-1bf66eff2447" />
<img width="1691" height="681" alt="image" src="https://github.com/user-attachments/assets/b12d2c6f-e188-4994-9f1b-e940083abcca" />
<img width="1699" height="906" alt="image" src="https://github.com/user-attachments/assets/7e5a2d5a-9a82-4cf4-a19c-950fd99c7556" />


















## RadSec credential sets and UniFi
For a UniFi network, create one credential set and assign it to every AP/NAS in that network; upload the same client fullchain/key/password and server trust CA to the UniFi RADIUS profile. This simplifies lifecycle and is distinct from the AP TLS-close issue. Evidence: server verifies forced TLS 1.2 and TLS 1.3 mTLS locally; U6-LR firmware 6.7.57 still closes before ClientHello. This is not a firmware claim. Keep classic RADIUS as the safe fallback while feature work proceeds.
