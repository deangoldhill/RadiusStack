#!/usr/bin/env bash
# Run from the installation directory. Requires bash, Python 3, curl and Docker Compose v2.
set -Eeuo pipefail
umask 077
if [[ $# != 2 || $1 != --to || ! $2 =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]]; then
  echo 'Usage: ./upgrade.sh --to x.y[.z] (invalid version)' >&2
  exit 2
fi
version=$2
[[ -f docker-compose.yml && -f .env ]] || { echo 'Run from an installation with docker-compose.yml and .env' >&2; exit 1; }
if [[ -f .radiusstack-version ]]; then
  python3 - "$version" <<'PY'
from pathlib import Path
import re, sys
current = Path('.radiusstack-version').read_text().strip()
target = sys.argv[1]
if not re.fullmatch(r'[0-9]+\.[0-9]+(?:\.[0-9]+)?', current):
    raise SystemExit('Invalid installed version; refusing unsafe upgrade')
def parts(v):
    return tuple(map(int, (v + '.0' if v.count('.') == 1 else v).split('.')))
if parts(target) <= parts(current):
    raise SystemExit('Refusing same-version install or downgrade')
PY
fi
for cmd in python3 curl docker; do command -v "$cmd" >/dev/null || { echo "Missing $cmd" >&2; exit 1; }; done
# Never interpolate secrets from .env: Compose injects MYSQL_ROOT_PASSWORD into mariadb.
# Match the actual deployment; a merely present optional override is not active.
compose=(docker compose -f docker-compose.yml)
if [[ -n ${COMPOSE_FILE:-} ]]; then compose=(docker compose); fi
"${compose[@]}" config -q
work=$(mktemp -d)
backup=''
changed=0
complete=0
cleanup() {
  status=$?
  trap - EXIT
  if (( status != 0 && changed == 1 && complete == 0 )); then
    echo "Upgrade failed. Stopping new services and restoring old code from $backup; database is NOT rolled back." >&2
    "${compose[@]}" stop radius api web_ui phpmyadmin >/dev/null 2>&1 || true
    for path in VERSION docker-compose.yml api radius web_ui/public db-migrations db-init upgrade.sh; do
      rm -rf -- "$path"
      if [[ -e "$backup/code/$path" ]]; then
        mkdir -p "$(dirname "$path")"
        cp -a -- "$backup/code/$path" "$path"
      fi
    done
    echo "Writers remain stopped. Inspect database compatibility before manually restarting old services. Backup: $backup" >&2
  fi
  rm -rf -- "$work"
  exit "$status"
}
trap cleanup EXIT
curl -fsSL -o "$work/release.json" "https://api.github.com/repos/deangoldhill/RadiusStack/releases/tags/$version"
# Require exactly one named release asset with a GitHub-published SHA-256 digest.
python3 - "$work/release.json" "$version" > "$work/asset" <<'PY'
import json, re, sys
obj = json.load(open(sys.argv[1]))
v = sys.argv[2]
assets = [a for a in obj.get('assets', []) if a.get('name') == 'radiusstack-source.tar.gz']
if obj.get('tag_name') != v or len(assets) != 1:
    raise SystemExit('Release tag or source asset mismatch')
a = assets[0]
url = f'https://github.com/deangoldhill/RadiusStack/releases/download/{v}/radiusstack-source.tar.gz'
if a.get('browser_download_url') != url or not re.fullmatch(r'sha256:[0-9a-fA-F]{64}', a.get('digest') or ''):
    raise SystemExit('Missing trusted release asset digest or unexpected URL')
print(a['digest'][7:].lower())
PY
curl -fsSL -o "$work/source.tar.gz" "https://github.com/deangoldhill/RadiusStack/releases/download/$version/radiusstack-source.tar.gz"
python3 - "$work/source.tar.gz" "$work/asset" "$work/stage" "$version" <<'PY'
import hashlib, pathlib, sys, tarfile
archive, expected_file, destination, version = sys.argv[1:]
expected = pathlib.Path(expected_file).read_text().strip()
if hashlib.file_digest(open(archive, 'rb'), 'sha256').hexdigest() != expected:
    raise SystemExit('Release archive SHA-256 mismatch')
root = f'radiusstack-{version}'
with tarfile.open(archive, 'r:gz') as tar:
    members = tar.getmembers()
    if not members or any(m.issym() or m.islnk() or m.isdev() or m.isfifo() or
       not (m.isfile() or m.isdir()) or
       pathlib.PurePosixPath(m.name).is_absolute() or '..' in pathlib.PurePosixPath(m.name).parts or
       pathlib.PurePosixPath(m.name).parts[0] != root for m in members):
        raise SystemExit('Unsafe release archive')
    tar.extractall(destination, filter='data')
p = pathlib.Path(destination) / root
for required in ('VERSION', '.radiusstack-version', 'docker-compose.yml', 'db-migrations/runner.py', 'db-migrations/Dockerfile.migrator', 'radius/Dockerfile', 'api/Dockerfile', 'web_ui/public/index.html', 'upgrade.sh'):
    if not (p / required).is_file():
        raise SystemExit(f'Incomplete release bundle: {required}')
if (p / 'VERSION').read_text().strip() != version or (p / '.radiusstack-version').read_text().strip() != version:
    raise SystemExit('Release bundle version mismatch')
PY
stage="$work/stage/radiusstack-$version"
# Build all new code before downtime or touching the database.
docker build -q -t "radiusstack-preflight-api:$version" "$stage/api" >/dev/null
docker build -q -t "radiusstack-preflight-radius:$version" "$stage/radius" >/dev/null
docker build -q -t "radiusstack-preflight-migrator:$version" -f "$stage/db-migrations/Dockerfile.migrator" "$stage/db-migrations" >/dev/null
# Runtime-generated RADIUS dictionary is a customer-owned bind mount.
rm -rf -- "$stage/radius/generated"
# Source release bundles are built locally; there is no assumed image registry.
mkdir -p upgrade-backups
backup=$(mktemp -d -p upgrade-backups "${version}-XXXXXXXX")
mkdir -p "$backup/code"
for path in VERSION docker-compose.yml api radius web_ui/public db-migrations db-init upgrade.sh; do
  if [[ -e "$path" ]]; then
    mkdir -p "$backup/code/$(dirname "$path")"
    cp -a -- "$path" "$backup/code/$path"
  fi
done
# Do not allow new transactions while taking the logical database snapshot.
phpmyadmin_running=$("${compose[@]}" ps -q --status running phpmyadmin)
changed=1
"${compose[@]}" stop radius api web_ui phpmyadmin
"${compose[@]}" exec -T mariadb sh -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mariadb-dump --single-transaction --routines --triggers --events --databases radius -uroot' > "$backup/database.sql"
[[ -s "$backup/database.sql" ]] || { echo 'Empty database backup; refusing upgrade' >&2; exit 1; }
for path in VERSION docker-compose.yml api radius web_ui/public db-migrations db-init; do
  if [[ -e "$stage/$path" ]]; then
    mkdir -p "$(dirname "$path")"
    if [[ -d "$stage/$path" ]]; then
      mkdir -p "$path"
      cp -a -- "$stage/$path/." "$path/"
    else
      cp -a -- "$stage/$path" "$path"
    fi
  fi
done
# Compose must be valid with the installed local override before any migration.
"${compose[@]}" config -q
"${compose[@]}" build db-migrate radius api
# Explicit one-shot migration; never let `up` implicitly retry a failed migration.
"${compose[@]}" run --rm --no-deps db-migrate
"${compose[@]}" up -d --no-deps radius api web_ui
"${compose[@]}" exec -T radius sh -c 'kill -0 1'
"${compose[@]}" exec -T api node -e "require('http').get('http://127.0.0.1:3000/', r => process.exit(r.statusCode < 500 ? 0 : 1)).on('error', () => process.exit(1))"
"${compose[@]}" exec -T web_ui wget -q -O /dev/null http://127.0.0.1/
if [[ -n "$phpmyadmin_running" ]]; then "${compose[@]}" up -d --no-deps phpmyadmin; fi
# Replace the running script only after all commands have finished reading it.
cp -a -- "$stage/upgrade.sh" upgrade.sh
printf '%s\n' "$version" > .radiusstack-version
complete=1
printf 'Upgrade v%s complete. Database and old code backup: %s\n' "$version" "$backup"
