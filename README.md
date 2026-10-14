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

HA sync uses the configured peer's API (`HA_PEER_IP`) with AES-256-GCM encrypted payloads. Leave `HA_ENABLED=false` until both nodes and the shared `HA_API_TOKEN` are configured and tested.

## Fresh installation

Extract the versioned source asset on the new machine. It contains a grouped `.env` with working **public defaults** and needs no first-run script. From that directory run `docker compose up -d --build` (provided its published ports are free). Review `RADSEC_SERVER_DNS` before using RadSec. **Change the shared default passwords and encryption key before exposing a production installation**, and keep the customized `.env` private and unchanged during upgrades. The deployable source folder includes the public-default `.env` but not `.env.example`; customize `.env` before exposing the new installation, and never copy the primary machine's private `.env` into public source.

## Release upgrades

**Version 5.5.3** fixes automatic RadSec proxy enrolment so its client, credential set, and NAS assignment are created together, with unenrolment revoking the linked set. A single RadSec client with a missing/mismatched credential-set/NAS link now emits an actionable warning rather than stopping upgrades for every tenant; missing database schema or failed SQL remains fatal. The upgrader adds a restricted, detailed per-attempt debug transcript of release verification, file copies, Docker commands/results, migration operations and readiness/rollback steps, plus private container-log snapshots on failure. It also atomically replaces its own script at completion. There is **no new database migration** in this release; required historical SQL remains included.

**Version 5.5.2** adds bulk Reset Usage on Users and MAC Auth; depleted-allocation details on the Dashboard, Reports and executive report/PDF; a full-width User-Specific Executive Report with reject analysis below; date-only Last Online columns; and a date-only Last Login column for administrators. Completed password-only and successful 2FA logins persist a per-administrator timestamp. The additive `20261011_admin_last_login.sql` migration backfills existing accounts from completed-login audit events; failed 2FA and password-only attempts are excluded. No real usage records need resetting for this release.

**Version 5.5.1** displays the installed source version in General Configuration, the Profile popup and the sidebar under Network Auth. The value comes from the installed `VERSION` file mounted read-only into the web UI, so it is not hard-coded into the pages. No database schema change is required for 5.5→5.5.1.

**Version 5.5** adds correctly tenant-attributed login audit entries and a cross-tenant Global audit view; default-on dashboard auto-refresh; administrator-specific colour preferences with a platform default; updated Syslog/SIEM event fields, destination validation and a persistent auth-forwarding cursor; Docker-backed Global Server Health; refreshed guide and API routes; and Called-Station-ID capture/filtering. Fresh installs include the schema, while upgrades from 5.4 apply additive, tracked migrations that retain existing records.

For an existing **published 5.5.2 installation**, use the [digest-verified 5.5.3 bootstrap](docs/UPGRADE.md) **after** its Release asset is published; do not invoke the installed 5.5.2 `./upgrade.sh` directly because it overwrites itself while running. For an existing **published 5.5.1 installation**, first upgrade to the published 5.5.2 asset using the 5.5.1 runbook, then use the 5.5.3 bootstrap from the installed 5.5.2 directory. For an existing **published 5.4 installation**, follow [the historical upgrade runbook](docs/UPGRADE.md) for the digest-verified 5.5 bootstrap first. The old 5.4 upgrader has a cold-start readiness race. `VERSION` is the committed source version; the Git tag and GitHub Release must use that exact number, without a `v` prefix (for example, `5.5.3`). The upgrader downloads the named GitHub Release asset, verifies its published SHA-256, builds new images locally, backs up MariaDB and managed code, applies tracked migrations, then starts and checks services. It preserves `.env`, generated RADIUS files, Compose overrides and named volumes. Dean manually commits the code, creates the Release and attaches the tarball; committing the archive alone does not make it a Release asset.

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
