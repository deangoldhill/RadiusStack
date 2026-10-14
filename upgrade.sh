#!/usr/bin/env bash
# Run from the installation directory. Requires bash, Python 3, curl and Docker Compose v2.
set -Eeuo pipefail
umask 077
if [[ $# != 2 || $1 != --to || ! $2 =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]]; then
  echo 'Usage: ./upgrade.sh --to x.y[.z] (invalid version)' >&2
  exit 2
fi
version=$2
# Keep the transcript outside release-managed paths; never print .env or SQL row values.
mkdir -p upgrade-backups
debug_dir=$(mktemp -d -p upgrade-backups "${version}-debug-XXXXXXXX")
debug_log="$debug_dir/upgrade-debug.log"
: > "$debug_log"
chmod 600 "$debug_log"
exec > >(tee -a "$debug_log") 2> >(tee -a "$debug_log" >&2)
log() { printf '[%s] %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*"; }
log "upgrade preflight target=$version cwd=$PWD log=$debug_log pid=$$"
trap 'status=$?; if ((status)); then log "FAILED exit=$status before upgrade rollback; inspect $debug_log"; fi' EXIT
log 'check required installation files: docker-compose.yml .env (contents withheld)'
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
for cmd in python3 curl docker; do log "check command available: $cmd"; command -v "$cmd" >/dev/null || { echo "Missing $cmd" >&2; exit 1; }; done
# Never interpolate secrets from .env: Compose injects MYSQL_ROOT_PASSWORD into mariadb.
# Match the actual deployment; a merely present optional override is not active.
compose=(docker compose -f docker-compose.yml)
if [[ -n ${COMPOSE_FILE:-} ]]; then compose=(docker compose); log 'Compose override supplied via COMPOSE_FILE (value withheld)'; fi
log "check Docker Compose configuration: ${compose[*]} config -q"
"${compose[@]}" config -q
log 'Docker Compose configuration valid'
compose_run() {
  log "docker command: ${compose[*]} $*"
  local status=0
  "${compose[@]}" "$@" || status=$?
  log "docker result exit=$status command=${compose[*]} $*"
  return "$status"
}
work=$(mktemp -d)
log "temporary staging directory: $work"
backup=''
changed=0
complete=0
cleanup() {
  status=$?
  trap - EXIT
  log "upgrade exit=$status changed=$changed complete=$complete backup=$backup"
  if (( status != 0 && changed == 1 && complete == 0 )); then
    echo "Upgrade failed. Stopping new services and restoring old code from $backup; database is NOT rolled back." >&2
    log "FAILED: stopping writers and restoring old code from $backup; database is NOT rolled back"
    for service in radius api web_ui db-migrate; do
      diagnostic="$debug_dir/$service-container.log"
      log "container diagnostics service=$service command=${compose[*]} logs --no-color --tail=150 $service output=$diagnostic (restricted; may contain secrets)"
      if "${compose[@]}" logs --no-color --tail=150 "$service" > "$diagnostic" 2>&1; then
        log "container diagnostics service=$service result=collected bytes=$(wc -c < "$diagnostic")"
      else
        log "container diagnostics service=$service result=command_failed bytes=$(wc -c < "$diagnostic")"
      fi
      chmod 600 "$diagnostic"
    done
    compose_run stop radius api web_ui phpmyadmin || true
    for path in VERSION docker-compose.yml api radius web_ui/public db-migrations db-init upgrade.sh; do
      log "rollback file=$path backed_up=$([[ -e "$backup/code/$path" ]] && printf yes || printf no)"
      rm -rf -- "$path"
      if [[ -e "$backup/code/$path" ]]; then
        mkdir -p "$(dirname "$path")"
        cp -a -- "$backup/code/$path" "$path"
      fi
    done
    log 'rollback code complete; database unchanged; writers remain stopped'
    echo "Writers remain stopped. Inspect database compatibility before manually restarting old services. Backup: $backup" >&2
  fi
  log "remove temporary stage=$work; permanent debug log=$debug_log"
  rm -rf -- "$work"
  exit "$status"
}
trap cleanup EXIT
log "download release metadata: https://api.github.com/repos/deangoldhill/RadiusStack/releases/tags/$version -> $work/release.json"
curl -fsSL -o "$work/release.json" "https://api.github.com/repos/deangoldhill/RadiusStack/releases/tags/$version"
log "downloaded release metadata bytes=$(wc -c < "$work/release.json") sha256=$(sha256sum "$work/release.json" | cut -d' ' -f1)"
# Require exactly one named release asset with a GitHub-published SHA-256 digest.
python3 - "$work/release.json" "$version" > "$work/asset" <<'PY'
import json, re, sys
obj = json.load(open(sys.argv[1]))
v = sys.argv[2]
assets = [a for a in obj.get('assets', []) if a.get('name') == 'radiusstack-source.tar.gz']
if obj.get('tag_name') != v or len(assets) != 1:
    raise SystemExit('Release tag or source asset mismatch')
print(f'[release] tag={obj.get("tag_name")} matching_assets={len(assets)}', file=sys.stderr)
a = assets[0]
url = f'https://github.com/deangoldhill/RadiusStack/releases/download/{v}/radiusstack-source.tar.gz'
if a.get('browser_download_url') != url or not re.fullmatch(r'sha256:[0-9a-fA-F]{64}', a.get('digest') or ''):
    raise SystemExit('Missing trusted release asset digest or unexpected URL')
print(a['digest'][7:].lower())
PY
log "download release archive: https://github.com/deangoldhill/RadiusStack/releases/download/$version/radiusstack-source.tar.gz -> $work/source.tar.gz expected_sha256=$(<"$work/asset")"
curl -fsSL -o "$work/source.tar.gz" "https://github.com/deangoldhill/RadiusStack/releases/download/$version/radiusstack-source.tar.gz"
log "downloaded archive bytes=$(wc -c < "$work/source.tar.gz") sha256=$(sha256sum "$work/source.tar.gz" | cut -d' ' -f1)"
python3 - "$work/source.tar.gz" "$work/asset" "$work/stage" "$version" <<'PY'
import hashlib, pathlib, shutil, sys, tarfile
archive, expected_file, destination, version = sys.argv[1:]
expected = pathlib.Path(expected_file).read_text().strip()
hasher = hashlib.sha256()
with open(archive, 'rb') as stream:
    for chunk in iter(lambda: stream.read(1024 * 1024), b''):
        hasher.update(chunk)
if hasher.hexdigest() != expected:
    raise SystemExit('Release archive SHA-256 mismatch')
root = f'radiusstack-{version}'
with tarfile.open(archive, 'r:gz') as tar:
    members = tar.getmembers()
    names = [member.name for member in members]
    if not members or len(names) != len(set(names)) or any(
        member.issym() or member.islnk() or member.isdev() or member.isfifo() or
        not (member.isfile() or member.isdir()) or
        not (member.name.startswith(root + '/') or (member.name == root and member.isdir())) or
        any(part in ('', '.', '..') for part in member.name.split('/')[1:]) or
        pathlib.PurePosixPath(member.name).is_absolute() or
        '..' in pathlib.PurePosixPath(member.name).parts
        for member in members
    ):
        raise SystemExit('Unsafe release archive')
    target = pathlib.Path(destination)
    target.mkdir(parents=True, exist_ok=True)
    for member in members:
        path = target.joinpath(*member.name.split('/'))
        print(f'[archive] check member={member.name!r} type={"directory" if member.isdir() else "file"} bytes={member.size} mode={member.mode:o}', flush=True)
        if member.isdir():
            path.mkdir(parents=True, exist_ok=True)
            path.chmod(0o755)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            with tar.extractfile(member) as source, path.open('xb') as output:
                shutil.copyfileobj(source, output)
            path.chmod(0o600 if member.name == root + '/.env' else
                       (0o755 if member.mode & 0o111 else 0o644))
            print(f'[archive] extracted member={member.name!r} sha256={hashlib.sha256(path.read_bytes()).hexdigest()}', flush=True)
p = pathlib.Path(destination) / root
for required in ('VERSION', '.radiusstack-version', 'docker-compose.yml', 'db-migrations/runner.py', 'db-migrations/Dockerfile.migrator', 'radius/Dockerfile', 'api/Dockerfile', 'web_ui/public/index.html', 'upgrade.sh'):
    print(f'[archive] required file check={required}', flush=True)
    if not (p / required).is_file():
        raise SystemExit(f'Incomplete release bundle: {required}')
print(f'[archive] version markers VERSION={p.joinpath("VERSION").read_text().strip()} installed={p.joinpath(".radiusstack-version").read_text().strip()}', flush=True)
if (p / 'VERSION').read_text().strip() != version or (p / '.radiusstack-version').read_text().strip() != version:
    raise SystemExit('Release bundle version mismatch')
PY
stage="$work/stage/radiusstack-$version"
log 'archive validated: all members extracted and required files checked'
# Build all new code before downtime or touching the database.
for service in api radius migrator; do
  case "$service" in
    api) build=(docker build -q -t "radiusstack-preflight-api:$version" "$stage/api") ;;
    radius) build=(docker build -q -t "radiusstack-preflight-radius:$version" "$stage/radius") ;;
    migrator) build=(docker build -q -t "radiusstack-preflight-migrator:$version" -f "$stage/db-migrations/Dockerfile.migrator" "$stage/db-migrations") ;;
  esac
  log "preflight docker command: ${build[*]}"
  "${build[@]}"
  log "preflight image built service=$service"
done
# Runtime-generated RADIUS dictionary is a customer-owned bind mount.
rm -rf -- "$stage/radius/generated"
# Source release bundles are built locally; there is no assumed image registry.
log_tree() {
  python3 - "$1" <<'PY'
from pathlib import Path
import hashlib, sys
root = Path(sys.argv[1])
for p in ([root] if root.is_file() or root.is_symlink() else sorted(root.rglob('*'))):
    if p.is_symlink():
        print(f'[file] symlink path={p} (content not followed)', flush=True)
    elif p.is_file():
        h = hashlib.sha256()
        with p.open('rb') as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                h.update(block)
        print(f'[file] path={p} bytes={p.stat().st_size} sha256={h.hexdigest()}', flush=True)
    else:
        print(f'[file] directory path={p}', flush=True)
PY
}
mkdir -p upgrade-backups
backup=$(mktemp -d -p upgrade-backups "${version}-XXXXXXXX")
log "persistent backup directory=$backup separate debug transcript=$debug_log"
mkdir -p "$backup/code"
for path in VERSION docker-compose.yml api radius web_ui/public db-migrations db-init upgrade.sh; do
  if [[ -e "$path" ]]; then
    log "backup source path=$path"
    log_tree "$path"
    mkdir -p "$backup/code/$(dirname "$path")"
    cp -a -- "$path" "$backup/code/$path"
    log "backup copy complete path=$path"
  else
    log "backup source absent path=$path"
  fi
done
# Do not allow new transactions while taking the logical database snapshot.
log "docker command (capture only): ${compose[*]} ps -q --status running phpmyadmin"
phpmyadmin_running=$("${compose[@]}" ps -q --status running phpmyadmin)
log "phpmyadmin previously running=$([[ -n "$phpmyadmin_running" ]] && printf yes || printf no)"
changed=1
log 'DOWNTIME START: stopping writers'
compose_run stop radius api web_ui phpmyadmin
log "docker command: ${compose[*]} exec -T mariadb [credential via container env] mariadb-dump --single-transaction --routines --triggers --events --databases radius -uroot -> $backup/database.sql"
"${compose[@]}" exec -T mariadb sh -c 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mariadb-dump --single-transaction --routines --triggers --events --databases radius -uroot' > "$backup/database.sql"
log "database dump bytes=$(wc -c < "$backup/database.sql") sha256=$(sha256sum "$backup/database.sql" | cut -d' ' -f1)"
[[ -s "$backup/database.sql" ]] || { echo 'Empty database backup; refusing upgrade' >&2; exit 1; }
for path in VERSION docker-compose.yml api radius web_ui/public db-migrations db-init; do
  if [[ -e "$stage/$path" ]]; then
    log "overlay release path=$path"
    log_tree "$stage/$path"
    mkdir -p "$(dirname "$path")"
    if [[ -d "$stage/$path" ]]; then
      mkdir -p "$path"
      cp -a -- "$stage/$path/." "$path/"
    else
      cp -a -- "$stage/$path" "$path"
    fi
    log "overlay complete path=$path"
  else
    log "release path absent; preserving local path=$path"
  fi
done
# Python's tarfile extraction under umask 077 can stage directories as 0700;
# cp -a preserves that mode on the existing public web root. Static assets must
# remain traversable/readable by the unprivileged Nginx worker, not just root.
log 'set public web asset read/traverse permissions'
chmod -R a+rX web_ui/public
# Compose must be valid with the installed local override before any migration.
compose_run config -q
log 'post-overlay Compose configuration valid'
compose_run build db-migrate radius api
# Explicit one-shot migration; never let `up` implicitly retry a failed migration.
log 'migration START: detailed SQL operation metadata enabled; SQL literals/parameters withheld'
compose_run run --rm --no-deps -e RADIUS_MIGRATION_DEBUG=1 db-migrate
log 'migration SUCCESS'
compose_run up -d --no-deps radius api web_ui
# Compose reports containers started before their listeners are necessarily ready.
# Retry transient cold-start refusals, but retain the existing rollback on a persistent failure.
wait_until_ready() {
  local service=$1 attempt
  shift
  log "readiness check service=$service command=$* max_attempts=30"
  for (( attempt=1; attempt<=30; attempt++ )); do
    log "readiness attempt service=$service number=$attempt"
    if compose_run exec -T "$service" "$@"; then
      log "readiness PASS service=$service attempt=$attempt"
      return 0
    fi
    log "readiness retry service=$service attempt=$attempt result=failed"
    if (( attempt < 30 )); then sleep 1; fi
  done
  log "readiness FAILED service=$service attempts=30; inspect state without printing container environment"
  compose_run ps -a || true
  echo "$service did not become ready after 30 checks" >&2
  return 1
}
wait_until_ready radius sh -c 'kill -0 1'
wait_until_ready api node -e "require('http').get('http://127.0.0.1:3000/', r => process.exit(r.statusCode < 500 ? 0 : 1)).on('error', () => process.exit(1))"
wait_until_ready web_ui wget -q -O /dev/null http://127.0.0.1/
if [[ -n "$phpmyadmin_running" ]]; then compose_run up -d --no-deps phpmyadmin; else log 'phpmyadmin was not running; no restart'; fi
# Preserve the running script's inode until Bash has finished reading it.
log "stage new upgrade.sh from $stage/upgrade.sh for atomic replacement"
cp -a -- "$stage/upgrade.sh" "$work/upgrade.sh.next"
printf '%s\n' "$version" > .radiusstack-version
log "installed version marker=$version; backup=$backup debug_log=$debug_log"
log "atomic replace upgrade.sh from $work/upgrade.sh.next"
mv -f -- "$work/upgrade.sh.next" upgrade.sh
complete=1
log "SUCCESS version=$version backup=$backup debug_log=$debug_log"
printf 'Upgrade v%s complete. Database and old code backup: %s; debug log: %s\n' "$version" "$backup" "$debug_log"
