# RadiusStack

RadiusStack is a self-hosted RADIUS platform for Wi-Fi, VPN, and network access. It brings FreeRADIUS, MariaDB, a REST API, and a web dashboard together in Docker Compose.

## Features

- Manage users, MAC devices, NAS clients, profiles, and usage plans in the web UI.
- Monitor live sessions, authentication and accounting logs, reports, and administrator activity.
- Use administrator and user TOTP, RadSec, certificates, backups, and API integrations.
- Organize customers with tenant isolation; high availability is available for multi-server setups.

## Install

1. Download and extract the [latest source release](https://github.com/deangoldhill/RadiusStack/releases) on a host with Docker and Docker Compose v2.
2. In the extracted directory, use the included `.env` (or copy `.env.example` to `.env` if needed). **Change `DB_ROOT_PASSWORD`, `DB_PASSWORD`, `JWT_SECRET`, and `RADSEC_PASSPHRASE_ENCRYPTION_KEY`** from their public defaults. Set `RADSEC_SERVER_DNS` to the hostname your RadSec clients will use. Change the published port values if they conflict with other services; leave `HA_ENABLED=false` for a single server.
3. Start the stack:

   ```sh
   docker compose up -d --build
   ```

Open `http://<your-server>:<WEB_UI_PORT>` (port 80 by default). Keep your customized `.env` for future upgrades.

## Upgrade

Download the target release from [Releases](https://github.com/deangoldhill/RadiusStack/releases), then run the **installed** updater from your existing installation directory, replacing `X.Y.Z` with that release number:

```sh
./upgrade.sh --to X.Y.Z
```

The updater keeps your installation settings and data. For older installations or multi-server HA upgrades, check the release's [upgrade notes](docs/UPGRADE.md) first.

## Help and support

See the [RadiusStack Wiki](https://github.com/deangoldhill/RadiusStack/wiki) for setup and feature guides. To report a problem or request a feature, [open a support ticket on GitHub Issues](https://github.com/deangoldhill/RadiusStack/issues/new) and include your RadiusStack version, what you expected, what happened, and relevant logs (without passwords or keys).
