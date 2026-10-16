# Customer upgrade (source-release workflow)

The source version is in `VERSION`, currently `5.5.5`. The maintainer manually commits the exact source, creates a matching `5.5.5` Git tag and GitHub Release (no `v`), and attaches the verified `radiusstack-source.tar.gz` from the release folder as a **Release asset**; a tarball committed only to the repository is not an asset. The archive contains `.radiusstack-version`, a ready-to-use `.env` with **public shared defaults**, runtime source, initialization SQL and ordered database migrations; tests, CI files and disposable development artifacts are omitted. The published defaults are not safe credentials for a production-facing service: change all passwords and keys before exposure, keep the changed `.env` private and preserve it across upgrades. Confirm GitHub's release API exposes the asset's `sha256:<64 hex>` digest and that the downloaded asset matches the staged archive before upgrading. Images are built locally, not via GHCR. Until the Release asset and digest are verified, this is not a published upgrade.

## Before using on a customer installation

Run from the installation directory as a user with Docker Compose v2 access, Python 3.8 or newer, Bash, and curl. Keep `docker-compose.yml` and `.env` present. Review the release, its migrations, and any customer-specific customizations first; take an independent off-host database backup and schedule downtime. For HA, coordinate peer failover/traffic separately: this script stops only the local Compose writers and does not orchestrate a cluster-wide upgrade. The release archive must contain the expected tree; do not run an unreviewed release. Test with `python3 -m unittest tests.test_upgrade_script -v` using offline mocks.

## Upgrade to 5.5.5 from 5.5.2, 5.5.3 or 5.5.4

Do not use the installed **5.5.2** `./upgrade.sh` for this upgrade: it overwrites the Bash script it is reading. Copying only the new script manually is possible, but a digest-verified bootstrap is safer because it validates the published archive and executes the new script from a temporary location without replacing local files first. Back up the database independently off-host, coordinate any HA peer downtime, and run from the installed **5.5.2** directory:

```sh
python3 - <<'PY'
from pathlib import Path
import hashlib, json, re, subprocess, tarfile, tempfile

installed = Path.cwd()
if (installed / '.radiusstack-version').read_text().strip() != '5.5.2' or not (installed / '.env').is_file():
    raise SystemExit('Expected an installed 5.5.2 directory with its private .env')
version = '5.5.5'
api = 'https://api.github.com/repos/deangoldhill/RadiusStack/releases/tags/' + version
url = 'https://github.com/deangoldhill/RadiusStack/releases/download/' + version + '/radiusstack-source.tar.gz'
with tempfile.TemporaryDirectory(prefix='radiusstack-555-upgrade-') as tmp:
    work = Path(tmp)
    response, archive = work / 'release.json', work / 'source.tar.gz'
    subprocess.run(['curl', '-fsSL', '-o', str(response), api], check=True)
    release = json.loads(response.read_text())
    assets = [a for a in release.get('assets', []) if a.get('name') == 'radiusstack-source.tar.gz']
    if release.get('tag_name') != version or release.get('draft') is True or len(assets) != 1:
        raise SystemExit('Missing published 5.5.5 source release')
    asset = assets[0]
    if asset.get('browser_download_url') != url or not re.fullmatch(r'sha256:[0-9a-fA-F]{64}', asset.get('digest') or ''):
        raise SystemExit('Missing trusted source asset digest or unexpected URL')
    subprocess.run(['curl', '-fsSL', '-o', str(archive), url], check=True)
    digest = hashlib.sha256()
    with archive.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    if digest.hexdigest() != asset['digest'][7:].lower():
        raise SystemExit('Release archive SHA-256 mismatch')
    with tarfile.open(archive, 'r:gz') as tar:
        root = 'radiusstack-' + version + '/'
        for marker in ('VERSION', '.radiusstack-version'):
            members = [m for m in tar.getmembers() if m.name == root + marker]
            if len(members) != 1 or not members[0].isfile() or tar.extractfile(members[0]).read() != (version + '\n').encode():
                raise SystemExit('Incorrect release version marker: ' + marker)
        members = [m for m in tar.getmembers() if m.name == root + 'upgrade.sh']
        if len(members) != 1 or not members[0].isfile() or not 0 < members[0].size <= 131072:
            raise SystemExit('Missing or oversized upgrader')
        upgrader = work / 'upgrade.sh'
        upgrader.write_bytes(tar.extractfile(members[0]).read())
    subprocess.run(['bash', str(upgrader), '--to', version], cwd=installed, check=True)
PY
```

For an installed **5.5.3** or **5.5.4** directory, the existing script atomically replaces itself only after the upgrade checks complete, so after verifying the exact published 5.5.5 asset and taking an off-host backup, run:

```sh
./upgrade.sh --to 5.5.5
```

Version 5.5.5 hides the depleted-allocations widget in Global context and reports aggregate running-state health for the five RadiusStack containers; `healthy` means all are running, not that they have passed application-level checks. A missing or stopped container yields `Degraded`. The 5.5.5 updater writes exhaustive detail to a mode-0600 per-attempt `upgrade-backups/<version>-debug-*/upgrade-debug.log`, while the terminal shows only progress milestones, a success summary, or a failure stage with log and backup paths. Do not paste the full log publicly: captured container diagnostics can contain secrets. Version 5.5.5 adds no SQL migration. Code rollback does not reverse previously committed database migrations. The HA public-peer IPv4 fix only changes validation: HA transport still uses plain HTTP and enabling it between populated or Internet-exposed nodes is unsafe without isolation and a tested data-reconciliation plan.

## Upgrade to 5.5.4 from 5.5.2 or 5.5.3

Do not use the installed **5.5.2** `./upgrade.sh` for this upgrade: it overwrites the Bash script it is reading. Copying only the new script manually is possible, but a digest-verified bootstrap is safer because it validates the published archive and executes the new script from a temporary location without replacing local files first. Back up the database independently off-host, coordinate any HA peer downtime, and run from the installed **5.5.2** directory:

```sh
python3 - <<'PY'
from pathlib import Path
import hashlib, json, re, subprocess, tarfile, tempfile

installed = Path.cwd()
if (installed / '.radiusstack-version').read_text().strip() != '5.5.2' or not (installed / '.env').is_file():
    raise SystemExit('Expected an installed 5.5.2 directory with its private .env')
version = '5.5.4'
api = 'https://api.github.com/repos/deangoldhill/RadiusStack/releases/tags/' + version
url = 'https://github.com/deangoldhill/RadiusStack/releases/download/' + version + '/radiusstack-source.tar.gz'
with tempfile.TemporaryDirectory(prefix='radiusstack-554-upgrade-') as tmp:
    work = Path(tmp)
    response, archive = work / 'release.json', work / 'source.tar.gz'
    subprocess.run(['curl', '-fsSL', '-o', str(response), api], check=True)
    release = json.loads(response.read_text())
    assets = [a for a in release.get('assets', []) if a.get('name') == 'radiusstack-source.tar.gz']
    if release.get('tag_name') != version or release.get('draft') is True or len(assets) != 1:
        raise SystemExit('Missing published 5.5.4 source release')
    asset = assets[0]
    if asset.get('browser_download_url') != url or not re.fullmatch(r'sha256:[0-9a-fA-F]{64}', asset.get('digest') or ''):
        raise SystemExit('Missing trusted source asset digest or unexpected URL')
    subprocess.run(['curl', '-fsSL', '-o', str(archive), url], check=True)
    digest = hashlib.sha256()
    with archive.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    if digest.hexdigest() != asset['digest'][7:].lower():
        raise SystemExit('Release archive SHA-256 mismatch')
    with tarfile.open(archive, 'r:gz') as tar:
        root = 'radiusstack-' + version + '/'
        for marker in ('VERSION', '.radiusstack-version'):
            members = [m for m in tar.getmembers() if m.name == root + marker]
            if len(members) != 1 or not members[0].isfile() or tar.extractfile(members[0]).read() != (version + '\n').encode():
                raise SystemExit('Incorrect release version marker: ' + marker)
        members = [m for m in tar.getmembers() if m.name == root + 'upgrade.sh']
        if len(members) != 1 or not members[0].isfile() or not 0 < members[0].size <= 131072:
            raise SystemExit('Missing or oversized upgrader')
        upgrader = work / 'upgrade.sh'
        upgrader.write_bytes(tar.extractfile(members[0]).read())
    subprocess.run(['bash', str(upgrader), '--to', version], cwd=installed, check=True)
PY
```

For an installed **5.5.3** directory, the existing script atomically replaces itself only after the upgrade checks complete, so after verifying the exact published 5.5.4 asset and taking an off-host backup, run:

```sh
./upgrade.sh --to 5.5.4
```

The 5.5.4 updater writes exhaustive detail to a mode-0600 per-attempt `upgrade-backups/<version>-debug-*/upgrade-debug.log`, while the terminal shows only progress milestones, a success summary, or a failure stage with log and backup paths. Do not paste the full log publicly: captured container diagnostics can contain secrets. Version 5.5.4 adds no SQL migration. Code rollback does not reverse previously committed database migrations. The HA public-peer IPv4 fix only changes validation: HA transport still uses plain HTTP and enabling it between populated or Internet-exposed nodes is unsafe without isolation and a tested data-reconciliation plan.

## Upgrade from 5.5.2 to 5.5.3 (historical)

**Do not run the installed 5.5.2 `./upgrade.sh --to 5.5.3` directly.** That published script can overwrite the Bash file it is reading, fail during overlay, and leave writers stopped. After the exact `5.5.3` GitHub Release has one `radiusstack-source.tar.gz` asset with a published SHA-256 digest, take an independent off-host database backup. From the **installed 5.5.2 directory** (where `.radiusstack-version` reads `5.5.2`), run this digest-verified bootstrap to execute the 5.5.3 updater from a separate temporary path:

```sh
python3 - <<'PY'
from pathlib import Path
import hashlib, json, re, subprocess, tarfile, tempfile

installed = Path.cwd()
if (installed / '.radiusstack-version').read_text().strip() != '5.5.2' or not (installed / '.env').is_file():
    raise SystemExit('Expected an installed 5.5.2 directory with its private .env')
version = '5.5.3'
api = 'https://api.github.com/repos/deangoldhill/RadiusStack/releases/tags/' + version
url = 'https://github.com/deangoldhill/RadiusStack/releases/download/' + version + '/radiusstack-source.tar.gz'
with tempfile.TemporaryDirectory(prefix='radiusstack-553-upgrade-') as tmp:
    work = Path(tmp)
    response, archive = work / 'release.json', work / 'source.tar.gz'
    subprocess.run(['curl', '-fsSL', '-o', str(response), api], check=True)
    release = json.loads(response.read_text())
    assets = [a for a in release.get('assets', []) if a.get('name') == 'radiusstack-source.tar.gz']
    if release.get('tag_name') != version or release.get('draft') is True or len(assets) != 1:
        raise SystemExit('Missing published 5.5.3 source release')
    asset = assets[0]
    if asset.get('browser_download_url') != url or not re.fullmatch(r'sha256:[0-9a-fA-F]{64}', asset.get('digest') or ''):
        raise SystemExit('Missing trusted source asset digest or unexpected URL')
    subprocess.run(['curl', '-fsSL', '-o', str(archive), url], check=True)
    digest = hashlib.sha256()
    with archive.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    if digest.hexdigest() != asset['digest'][7:].lower():
        raise SystemExit('Release archive SHA-256 mismatch')
    with tarfile.open(archive, 'r:gz') as tar:
        root = 'radiusstack-' + version + '/'
        for marker in ('VERSION', '.radiusstack-version'):
            members = [m for m in tar.getmembers() if m.name == root + marker]
            if len(members) != 1 or not members[0].isfile() or tar.extractfile(members[0]).read() != (version + '\n').encode():
                raise SystemExit('Incorrect release version marker: ' + marker)
        members = [m for m in tar.getmembers() if m.name == root + 'upgrade.sh']
        if len(members) != 1 or not members[0].isfile() or not 0 < members[0].size <= 131072:
            raise SystemExit('Missing or oversized upgrader')
        upgrader = work / 'upgrade.sh'
        upgrader.write_bytes(tar.extractfile(members[0]).read())
    subprocess.run(['bash', str(upgrader), '--to', version], cwd=installed, check=True)
PY
```

The 5.5.3 script independently repeats the release/digest verification and preflight, then backs up managed code and MariaDB, applies tracked migrations, and checks readiness. A 5.5.2 installation's first upgrade may not record the new debug detail if you bypass this bootstrap; the command above invokes the 5.5.3 logger from the outset. Version 5.5.3 introduces no new SQL migration; it retains every historical migration for fresh and upgraded installations. A malformed single-client RadSec credential link becomes an actionable warning without deleting or repairing it, while structural schema, ledger, and SQL errors remain fatal. Code rollback does **not** reverse database migrations; inspect backup/debug artifacts before restarting after failure.

## Upgrade from 5.5.1 to 5.5.2

After the exact `5.5.2` GitHub Release has one `radiusstack-source.tar.gz` Release asset with a published SHA-256 digest, take an independent off-host database backup. From the **installed 5.5.1 directory** (where `.radiusstack-version` reads `5.5.1`), run:

```sh
./upgrade.sh --to 5.5.2
```

The corrected 5.5.1 upgrader verifies the exact published asset and its digest, stages/builds before stopping writers, then backs up code and MariaDB, applies migrations and checks readiness. It preserves the customized `.env`, generated RADIUS data, Compose overrides and named volumes. Version 5.5.2 adds `db-migrations/20261011_admin_last_login.sql`: a nullable per-administrator timestamp is populated from historical successful `Login completed` and `2FA verification` audit entries, not a password-validated attempt. Later sign-ins update it by administrator ID after completion. Administrators with no completed sign-in history show `—`. The other 5.5.2 changes are described in the README. The same corrected upgrader on a published 5.5 installation can target 5.5.2 directly; the additive, tracked migrations apply in order. Do not run this command before the **GitHub Release asset** and digest exist; the folder prepared by the maintainer is not itself a published Release.

## Upgrade from 5.5 to 5.5.1

After the exact `5.5.1` GitHub Release has one asset named `radiusstack-source.tar.gz` with a published SHA-256 digest, take an independent off-host database backup. From the **existing 5.5 installation directory** (where `.radiusstack-version` reads `5.5`), run:

```sh
./upgrade.sh --to 5.5.1
```

The installed, corrected 5.5 upgrader supports Python 3.8+, verifies the GitHub asset digest, stages and builds the release before downtime, backs up code and MariaDB, runs the tracked migrations, recreates the application containers and checks readiness. It preserves your configured `.env`, generated RADIUS data, Compose overrides and named volumes. The new web UI has a read-only `VERSION` bind mount; keep the `VERSION` file beside `docker-compose.yml`. The version is displayed in General Configuration, the Profile popup, and between Network Auth and the username in the sidebar. This release adds no new database migration. Do not run this command until the **Release asset**, not just a repository file, is available and verified.

## Upgrade from 5.4 to 5.5 (historical bootstrap)

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
    digest = hashlib.sha256()
    with archive.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    if digest.hexdigest() != asset['digest'][7:].lower():
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

For a new 5.5.3 machine, install **from the published 5.5.3 asset**, not a later working tree. The asset contains `.radiusstack-version` and a grouped `.env` with working public defaults. From the extracted directory, `docker compose up -d --build` starts the stack without another initialization command, provided the host ports are available. The default `RADSEC_SERVER_DNS=radius-stack.example.com` is an example hostname: set it to a resolvable hostname clients use before enabling RadSec. `RADSEC_SERVER_IP` is commented out and defaults to `127.0.0.1`. **Every copy shares the published default passwords and encryption key until changed.** Do not expose the default web, API, database, or phpMyAdmin ports to untrusted networks; change secrets and review ports before production use. The deployable archive includes a public-default `.env`; a development checkout may additionally contain `.env.example`. Customize `.env` before exposing a new installation, and never copy the primary server's configured `.env` into public source. A Git checkout has no `.radiusstack-version` unless it came from the published archive. Keep the same `COMPOSE_FILE` value for future upgrades if using an override.

The script does not overwrite `.env`, `compose.production.yaml`, `web_ui/nginx.conf`, `radius/generated`, named Docker volumes, or unrelated custom files. It uses **only `docker-compose.yml` by default**, matching the ordinary install; if your deployment uses `COMPOSE_FILE`, export the exact same value for the upgrade. A merely present `compose.production.yaml` is not automatically activated. It **does** overlay files under `api`, `radius` (except `radius/generated`), `web_ui/public`, `db-migrations`, `db-init`, and `docker-compose.yml`; move customer edits to other paths or merge them deliberately before upgrading. Old files removed by a release may remain after overlay; review the source diff/compatibility.

The updater keeps a restricted, per-attempt transcript at `upgrade-backups/<target>-debug-*/upgrade-debug.log` (mode 0600, directory mode 0700), including failures before downtime. It timestamps preflight results, release metadata/archive integrity and each extracted file, file backup/overlay inventories and hashes, Docker build/Compose commands and results, database dump size/hash, migration decisions and per-result-set affected-row counts, each readiness retry, and code rollback. On failure after writers stop it additionally saves the last 150 lines of each application/migrator container under `*-container.log` in the same private directory **before** stopping them; this captures restart-loop causes. The migrator reports SQL operation type and SHA-256/part number/affected rows rather than interpolated SQL literals or bound values. These artifacts are **sensitive**: Docker/build/container error output can itself contain customer values or credentials despite the upgrader's deliberate omission of `.env` contents and SQL values. Do not publish or paste raw logs; review/redact before sharing. If the log cannot initially be created, preflight stops; as with any streamed log, a disk-full or I/O failure while writing it mid-upgrade requires operator attention and is not guaranteed to abort the running upgrade. Existing published installers do not acquire these improvements retroactively; they are included in the staged 5.5.3 source and take effect only when that script is installed and invoked.

If backup, migration, build, or health checking fails after writers stop, the script stops app services and restores old managed code from the backup. **It never automatically rolls back database changes or restarts old applications**: DDL may be nontransactional and old code may not work against a partially migrated schema. Investigate the migration and verify database compatibility before manually restarting. If a database restore is required, do it only after an operator has reviewed the SQL snapshot and consequences of discarding newer data. The smoke checks are process/API/web responsiveness, not full RADIUS authentication or workload checks; perform operational validation before reopening traffic.
