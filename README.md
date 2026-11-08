# RadiusStack

RadiusStack is a full stack containerized Radius platform built on FreeRadius focussed on ease of use with a wide range is use cases.<br/>
Useful for network access control, permission assignment, network visibility and volume tracking & enforcment.<br/>
Manage WIFI network access, Dot1X authentication, VPN authenitcation and many other authentication use cases.<br/>
It includes advanced Radius features such as EAP tunneled authentication protocol (WPA-Enterprise), RadSec (Radius over TLS) and Multi-factor authentication.<br/>
A highly secure NodeJS API server at the core with a modern WebUI.<br/>
High-availability with 2-way sessions sync, Multi-tenancy and granular role based access control.

## Features

- Advanced security features - RadSec (Radius over TLS), EAP, MFA (TOTP).
- Policy enforcment - assign profiles with NAS restrictions, reply attributes, Usage limits and dynamic authorisation. Change of Authorisation (COA), packet of disconnect (POD).
- Visibility - Monitor active sessions, authentication and accounting logs, reports, and administrator activity.
- Granular administration - Multi-tenancy, role based access control, API integration.
- Operational effeciency - High-availability, debug logging, Syslog/SIEM, notifications.

## Install

1. On a host with Git, Docker, and Docker Compose, clone the repository:

   ```sh
   git clone https://github.com/deangoldhill/RadiusStack.git
   cd RadiusStack
   cp .env.example .env
   ```
You can either run the interactive 'setup_env.sh' script which will guide you through and generate strong random keys and passwords, or you can manually edit the .env file. Using the script is highly recommended to ensure strong security.

2. Edit `.env`: **change `DB_ROOT_PASSWORD`, `DB_PASSWORD`, `JWT_SECRET`, and `RADSEC_PASSPHRASE_ENCRYPTION_KEY`** from their public defaults. You can change published ports if they conflict with other services, this will change the docker port mappings.
3. Start the stack:

   ```sh
   docker compose up -d --build
   ```

Open `http://<your-server>:<WEB_UI_PORT>` (port 80 by default). Keep your customized `.env` for future upgrades.

## Upgrade

From your existing installation directory, make the updater executable and run it with the version you want (replace `X.Y.Z`):

```sh
chmod +x upgrade.sh
./upgrade.sh --to X.Y.Z
```

The script downloads and verifies the release automatically and keeps your `.env` and data. For older installations, check the [upgrade notes](docs/UPGRADE.md).

## Running in HA

Install RadiusStack on two separate servers. In each server's `.env`, set:

- `HA_ENABLED=true` on both.
- `HA_ROLE=primary` on one and `HA_ROLE=secondary` on the other.
- `HA_DB_OFFSET=1` on the first server and `HA_DB_OFFSET=2` on the second; keep each offset with its server even if roles change.
- `HA_PEER_IP` to the **other** server's reachable IPv4 address on each node.
- `HA_API_TOKEN` to the same unique value of at least 32 characters on both nodes.
- Keep `API_PORT=3000` on both and allow the servers to reach each other on that port.

Start both stacks with `docker compose up -d --build`, then check **Settings → High Availability Status** in Global. Configuration syncs from primary to secondary; use the HA controls to review sync and manage roles. For upgrades, follow the HA ordering in the [upgrade notes](docs/UPGRADE.md).

## Help and support

See the [RadiusStack Wiki](https://github.com/deangoldhill/RadiusStack/wiki) for setup and feature guides. To report a problem or request a feature, [open a support ticket on GitHub Issues](https://github.com/deangoldhill/RadiusStack/issues/new) and include your RadiusStack version, what you expected, what happened, and relevant logs (without passwords or keys).
