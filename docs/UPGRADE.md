# Customer upgrade (source-release workflow)

The source version is in `VERSION`, currently `5.5`. **Commit before tagging** the exact 5.5 source commit, then create and push the tag `5.5` (no `v`). `.github/workflows/release.yml` tests and builds from that tag, packages a deployment-only `radiusstack-source.tar.gz`, and creates the GitHub Release with that asset. Do not also manually create the Release: a pre-existing Release makes the workflow's create step fail. The archive contains `.radiusstack-version`, a grouped ready-to-use `.env` with **public shared defaults**, runtime source, initialization SQL and ordered database migrations; tests, CI files and disposable development artifacts are omitted. The published defaults let `docker compose up -d --build` run without a setup script, but they are not safe credentials for a production-facing service: change all passwords and keys before exposure, keep the changed `.env` private and preserve it across upgrades. GitHub's release API must expose the asset's `sha256:<64 hex>` digest; the command rejects missing digests or a different URL. Images are built locally, not via GHCR. Until the tag workflow succeeds and its asset is verified, this is not a published upgrade.

## Before using on a customer installation

Run from the installation directory as a user with Docker Compose v2 access, Python 3 (tarfile `filter='data'`, Python >=3.12), Bash, and curl. Keep `docker-compose.yml` and `.env` present. Review the release, its migrations, and any customer-specific customizations first; take an independent off-host database backup and schedule downtime. For HA, coordinate peer failover/traffic separately: this script stops only the local Compose writers and does not orchestrate a cluster-wide upgrade. The release archive must contain the expected tree; do not run an unreviewed release. Test with `python3 -m unittest tests.test_upgrade_script -v` using offline mocks.

## Upgrade from 5.4 to 5.5

Install 5.5 only after the exact `5.5` GitHub Release and its named source asset have been published and verified. On an existing 5.4 installation, retain its customized `.env`, named volumes, and any local Compose override. The published 5.4 upgrader checks the API immediately after Compose reports a container start; on a cold host that may fail before the API is listening and leave the writers stopped. **Do not run `./upgrade.sh --to 5.5` directly from an unmodified published 5.4 asset.** Instead, from the 5.4 installation directory, run the **digest-verified 5.5 upgrader** from the released archive without replacing the old script first:

```sh
python3 - <<'PY'
from pathlib import Path
import hashlib, json, re, subprocess, tarfile, tempfile

installed = Path.cwd()
if (installed / '.radiusstack-version').read_text().strip() != '5.4' or not (installed / '.env').is_file():
    raise SystemExit('Expected an installed 5.4 source asset with its private .env')
version = '5.5'
api = f'https://api.github.com/repos/deangoldhill/RadiusStack/releases/tags/{version}'
url = f'https://github.com/deangoldhill/RadiusStack/releases/download/{version}/radiusstack-source.tar.gz'
with tempfile.TemporaryDirectory(prefix='radiusstack-55-upgrade-') as tmp:
    work = Path(tmp)
    response, archive = work / 'release.json', work / 'source.tar.gz'
    subprocess.run(['curl', '-fsSL', '-o', str(response), api], check=True)
    release = json.loads(response.read_text())
    assets = [a for a in release.get('assets', []) if a.get('name') == 'radiusstack-source.tar.gz']
    if release.get('tag_name') != version or release.get('draft') is True or len(assets) != 1:
        raise SystemExit('Missing published 5.5 source release')
    asset = assets[0]
    if asset.get('browser_download_url') != url or not re.fullmatch(r'sha256:[0-9a-fA-F]{64}', asset.get('digest') or ''):
        raise SystemExit('Missing trusted source asset digest or unexpected URL')
    subprocess.run(['curl', '-fsSL', '-o', str(archive), url], check=True)
    if hashlib.file_digest(archive.open('rb'), 'sha256').hexdigest() != asset['digest'][7:].lower():
        raise SystemExit('Release archive SHA-256 mismatch')
    with tarfile.open(archive, 'r:gz') as tar:
        root = 'radiusstack-5.5/'
        for marker in ('VERSION', '.radiusstack-version'):
            member = tar.getmember(root + marker)
            if not member.isfile() or tar.extractfile(member).read() != b'5.5\n':
                raise SystemExit('Incorrect release version marker')
        member = tar.getmember(root + 'upgrade.sh')
        if not member.isfile() or member.size > 65536:
            raise SystemExit('Missing or oversized upgrader')
        upgrader = work / 'upgrade.sh'
        upgrader.write_bytes(tar.extractfile(member).read())
    subprocess.run(['bash', str(upgrader), '--to', version], cwd=installed, check=True)
PY
```

This bootstrap trusts only the expected GitHub release URL and its API-published digest. The 5.5 upgrader then repeats those checks, takes the backup, applies migrations and waits for its smoke checks to become ready. Do not execute an archive from an unpublished tag. If you have already upgraded the installed script to the 5.5 implementation, `./upgrade.sh --to 5.5` is equivalent. For HA installations, coordinate both peers and traffic separately.

The 5.5 source includes additive migrations for the administrator's personal colour preference, `radpostauth.calledstationid`, and the Syslog auth-delivery checkpoint. Existing authentication records remain; the new called-station field on old rows is empty rather than invented. Old audit entries with no tenant assignment are not rewritten. The installer retains the old code and database snapshot before applying migrations, and refuses same-version or downgrade requests when a valid installed marker exists.

The script verifies the exact release tag, expected archive URL and GitHub-published SHA-256, validates and stages the archive before stopping writers, saves old code under `upgrade-backups/5.5-*/code`, stops local `radius`, `api`, `web_ui` and (if present) `phpmyadmin`, then dumps MariaDB to the backup directory using the existing container's `MYSQL_ROOT_PASSWORD` environment variable (not a CLI password argument or log). It overlays release-managed source, runs `docker compose run --rm --no-deps db-migrate` once, rebuilds and starts the three application services, and checks container responsiveness. Preserve `upgrade-backups/` securely: the SQL contains customer data. Back up these local backups off host. No registry or production DB is touched by the offline tests.

For a new 5.5 machine, install **from the published 5.5 asset**, not a later working tree. The asset contains `.radiusstack-version` and a grouped `.env` with working public defaults. From the extracted directory, `docker compose up -d --build` starts the stack without another initialization command, provided the host ports are available. The default `RADSEC_SERVER_DNS=radius-stack.example.com` is an example hostname: set it to a resolvable hostname clients use before enabling RadSec. `RADSEC_SERVER_IP` is commented out and defaults to `127.0.0.1`. **Every copy shares the published default passwords and encryption key until changed.** Do not expose the default web, API, database, or phpMyAdmin ports to untrusted networks; change secrets and review ports before production use. Git checkout includes a public-default `.env` as well as `.env.example`; customize the former before exposure, never replace it with the primary server's configured `.env`. A Git checkout has no `.radiusstack-version` unless it came from the published archive. Keep the same `COMPOSE_FILE` value for future upgrades if using an override.

The script does not overwrite `.env`, `compose.production.yaml`, `web_ui/nginx.conf`, `radius/generated`, named Docker volumes, or unrelated custom files. It uses **only `docker-compose.yml` by default**, matching the ordinary install; if your deployment uses `COMPOSE_FILE`, export the exact same value for the upgrade. A merely present `compose.production.yaml` is not automatically activated. It **does** overlay files under `api`, `radius` (except `radius/generated`), `web_ui/public`, `db-migrations`, `db-init`, and `docker-compose.yml`; move customer edits to other paths or merge them deliberately before upgrading. Old files removed by a release may remain after overlay; review the source diff/compatibility.

If backup, migration, build, or health checking fails after writers stop, the script stops app services and restores old managed code from the backup. **It never automatically rolls back database changes or restarts old applications**: DDL may be nontransactional and old code may not work against a partially migrated schema. Investigate the migration and verify database compatibility before manually restarting. If a database restore is required, do it only after an operator has reviewed the SQL snapshot and consequences of discarding newer data. The smoke checks are process/API/web responsiveness, not full RADIUS authentication or workload checks; perform operational validation before reopening traffic.
