# RadiusStack 6.0.3 source release and upgrade

This is a prepared **source** package, not a published GitHub Release. Dean reviews/commits the source, tags `6.0.3` (no `v`), creates the GitHub Release, and uploads the verified `radiusstack-source.tar.gz` manually. Do not run the updater until the Release asset and its API-provided SHA-256 digest are published and match this package.

## Changes from 6.0.2

- Removed `DOWNSTREAM_DENY_IPS` from Compose, native config generation, and downstream validation. Usable non-local IPv4 hosts are no longer rejected by a host-specific list. Loopback, special/non-unicast and container-local addresses remain invalid. **Do not configure a downstream destination that is actually this same RADIUS host**: a Docker container cannot reliably discover every published LAN address of its host, so that creates a forwarding loop. Use the other server's address and verify it from that node.
- Added `proxy_traffic` to each downstream destination: `auth`, `accounting`, or `both`. Existing records default to `both` via an additive migration; NAS/profile routes still select the destination. A disabled traffic type stays on the existing local path. Saving a destination that persists but fails to activate Radius now closes the editor, refreshes the list, and leaves a visible activation warning rather than suggesting nothing was saved. Resolve the activation failure before sending traffic.
- Added durable HA delivery pause/resume and an operator-triggered online log reconciliation for `radacct`, `radpostauth`, and `admin_audit_log`. The primary takes a consistent snapshot, sends bounded chunks, and the secondary finalizes in bounded transactional CAS pages. Concurrent secondary RADIUS writes, including open accounting sessions, continue; altered rows and new sessions are preserved. A differing secondary yields `partial` with counts, not an exact mirror. Secondary backup tables are retained. Pause the HA delivery after the queue has drained to zero; review conflicts and backups before promotion or resumption. Ordinary Full Sync is **not** a substitute for this workflow, and HA API transport is plain HTTP unless separately protected.
- Fresh schema and migrations include HA control/reconciliation state and downstream traffic selection. Do **not** manually clear the HA queue or drop retained backup tables without review.

## Fresh install

The extracted `radiusstack-6.0.3` contains `.env` matching `.env.example` with intentionally public, insecure defaults. Change passwords, tokens, and encryption keys, and verify your published ports and RadSec DNS before exposing the stack. From the extracted directory, run `docker compose up -d --build` only on the intended host. No first-run script is needed. Keep the customized `.env` private.

## Upgrade from an installed 6.0.2

1. Independently back up both HA databases and keep the installed `.env`, Compose overrides, certificate volumes, and current source privately. Record existing downstream destinations and HA queue state. Never run a new source updater against a still-unpublished release.
2. Publish the exact reviewed archive under tag `6.0.3` and verify the Release asset and API SHA-256 digest. Use the **installed 6.0.2** `upgrade.sh` to upgrade the **secondary first**; verify the migration, API/Radius readiness, then upgrade the primary. Rehearse on disposable copies first if production data or installed updater behavior differs.
3. On each 6.0.2 node, after publication: `./upgrade.sh --to 6.0.3`. The updater retains private `.env` and named volumes; SQL DDL cannot be undone by swapping source files. Monitor migrations and readiness. Verify old destinations remain `both`, new Auth-only and Accounting-only routes, a saved destination's activation status, HA queue drain and pause/resume controls. Do not initiate reconciliation during the rolling upgrade; both peers need 6.0.3.
4. For installations older than 6.0.2, rehearse the exact installed updater and data in a disposable copy or follow the documented historical/bootstrap path. An old self-overwriting updater is not repaired by packaging a new one.

## Release verification

`VERSION`, the Git tag, and the published Release must all say `6.0.3`. Confirm the archive extracts into `radiusstack-6.0.3/`, includes root `.env` byte-identical to `.env.example`, and includes the full source and all migrations. Compare the published asset digest against the reviewed archive; do not substitute a rebuilt/different archive after verification.

---

# Historical 5.4→5.5 bootstrap (for that exact release only)

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
