#!/usr/bin/env bash
# Optional first-install .env setup. Requires Bash and standard Linux coreutils.
set -euo pipefail
umask 077

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
template="$root/.env.example"
output="$root/.env"
[[ -f "$template" && ! -L "$template" ]] || { printf 'Missing .env.example beside this script.\n' >&2; exit 1; }

declare -A defaults=() updates=() seen=() used_ports=()
while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" =~ ^([A-Z][A-Z0-9_]*)=(.*)$ ]]; then
        defaults["${BASH_REMATCH[1]}"]="${BASH_REMATCH[2]}"
    fi
done < "$template"

fail() { printf '%s\n' "$1" >&2; exit 1; }
read_answer() {
    printf '%s' "$1"
    IFS= read -r REPLY || fail 'Input ended; no configuration was written.'
}
read_private() {
    printf '%s' "$1"
    IFS= read -r -s REPLY || fail 'Input ended; no configuration was written.'
    printf '\n'
}

# An extracted source archive may contain an unchanged, public-default .env.
if [[ -e "$output" || -L "$output" ]]; then
    [[ -f "$output" && ! -L "$output" ]] && cmp -s -- "$output" "$template" ||
        fail 'An existing customized .env was found; edit it manually instead.'
    original_public=true
else
    original_public=false
fi

for key in DB_USER RADSEC_SERVER_DNS TIMEZONE DB_ROOT_PASSWORD DB_PASSWORD JWT_SECRET RADSEC_PASSPHRASE_ENCRYPTION_KEY \
           RADIUS_AUTH_PORT RADIUS_ACCT_PORT RADSEC_PORT DB_PORT API_PORT WEB_UI_PORT PHPMYADMIN_PORT; do
    [[ -v defaults[$key] ]] || fail "Missing $key in .env.example."
done

random_token() { head -c 32 /dev/urandom | base64 | tr '/+' '_-' | tr -d '=\n'; }
random_key() { head -c 32 /dev/urandom | base64 | tr -d '\n'; }
valid_secret() { [[ "$1" =~ ^[A-Za-z0-9_.~!@%+=:,/?-]{16,512}$ ]] && (( ${#1} >= "$2" )); }
valid_key() {
    local count
    count=$(printf '%s' "$1" | base64 -d 2>/dev/null | wc -c) || return 1
    [[ "$count" -eq 32 ]]
}
prompt_secret() {
    local key=$1 minimum=$2 shared=$3 format=$4 answer
    while :; do
        if [[ "$shared" == true ]]; then
            read_private "$key (enter the value from the primary): "
        else
            read_private "$key (Enter = generate random): "
        fi
        answer=$REPLY
        if [[ -z "$answer" && "$shared" == false ]]; then
            if [[ "$format" == base64 ]]; then
                updates["$key"]=$(random_key)
            else
                updates["$key"]=$(random_token)
            fi
            return
        fi
        if { [[ "$format" == base64 ]] && valid_key "$answer"; } ||
           { [[ "$format" == plain ]] && valid_secret "$answer" "$minimum"; }; then
            updates["$key"]=$answer
            return
        fi
        if [[ "$shared" == true && -z "$answer" ]]; then
            printf 'Value required: use the shared value from the primary node.\n'
        else
            printf 'Invalid %s: enter a compatible %s value (no spaces, $, quotes or #).\n' "$key" "$format"
        fi
    done
}
valid_peer() {
    local ip=$1 a b c d octet
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    IFS=. read -r a b c d <<< "$ip"
    for octet in "$a" "$b" "$c" "$d"; do
        (( 10#$octet <= 255 )) || return 1
    done
    (( 10#$a > 0 && 10#$a < 224 && 10#$a != 127 )) || return 1
    [[ ! ( "$a" == 169 && "$b" == 254 ) ]] || return 1
    (( 10#$d > 0 && 10#$d < 255 ))
}
valid_timezone() {
    [[ "$1" =~ ^[A-Za-z0-9_+./-]+$ && "$1" != /* && "$1" != *..* ]]
}
prompt_default() {
    local key=$1 answer
    while :; do
        read_answer "$key [${defaults[$key]}]: "
        answer=${REPLY:-${defaults[$key]}}
        case "$key" in
            DB_USER)
                [[ "$answer" =~ ^[A-Za-z_][A-Za-z0-9_]{0,31}$ ]] || { printf 'Invalid DB_USER.\n'; continue; } ;;
            TIMEZONE)
                valid_timezone "$answer" || { printf 'Invalid TIMEZONE.\n'; continue; } ;;
        esac
        updates["$key"]=$answer
        return
    done
}
prompt_port() {
    local key=$1 protocol=$2 answer number
    while :; do
        read_answer "$key [${defaults[$key]}]: "
        answer=${REPLY:-${defaults[$key]}}
        if [[ ! "$answer" =~ ^[0-9]{1,5}$ ]]; then
            printf 'Enter a port from 1 to 65535.\n'
            continue
        fi
        number=$((10#$answer))
        if (( number < 1 || number > 65535 )); then
            printf 'Enter a port from 1 to 65535.\n'
            continue
        fi
        if [[ -v used_ports["$protocol:$number"] ]]; then
            printf 'Port %s/%s is already selected; choose a different port.\n' "$number" "$protocol"
            continue
        fi
        used_ports["$protocol:$number"]=1
        updates["$key"]=$number
        return
    done
}

printf 'RadiusStack first-install settings. Press Enter for a shown default or a fresh random secret.\n'
while :; do
    read_answer 'Enable HA (Y/N): '
    case ${REPLY,,} in
        y|yes) updates[HA_ENABLED]=true; break ;;
        n|no)  updates[HA_ENABLED]=false; break ;;
        '')    printf 'Value required, please input either Y or N.\n' ;;
        *)     printf 'Please input either Y or N.\n' ;;
    esac
done
if [[ ${updates[HA_ENABLED]} == true ]]; then
    while :; do
        read_answer 'Primary node? [Y/n]: '
        case ${REPLY,,} in
            ''|y|yes) updates[HA_ROLE]=primary; updates[HA_DB_OFFSET]=1; break ;;
            n|no)    updates[HA_ROLE]=secondary; updates[HA_DB_OFFSET]=2; break ;;
            *)       printf 'Please input either Y or N.\n' ;;
        esac
    done
    while :; do
        read_answer 'Other node peer IPv4 address: '
        if valid_peer "$REPLY"; then
            updates[HA_PEER_IP]=$REPLY
            break
        fi
        printf 'Invalid peer IPv4 address; enter the other node reachable address.\n'
    done
    if [[ ${updates[HA_ROLE]} == secondary ]]; then
        printf 'Secondary: use the primary node shared JWT_SECRET, RadSec key and HA_API_TOKEN.\n'
    fi
fi

prompt_secret DB_ROOT_PASSWORD 16 false plain
prompt_secret DB_PASSWORD 16 false plain
secondary=false
[[ ${updates[HA_ROLE]:-} == secondary ]] && secondary=true
prompt_secret JWT_SECRET 32 "$secondary" plain
prompt_secret RADSEC_PASSPHRASE_ENCRYPTION_KEY 32 "$secondary" base64
prompt_default DB_USER
prompt_default TIMEZONE
if [[ ${updates[HA_ENABLED]} == true ]]; then
    prompt_secret HA_API_TOKEN 32 "$secondary" plain
fi
prompt_port RADIUS_AUTH_PORT udp
prompt_port RADIUS_ACCT_PORT udp
prompt_port RADSEC_PORT tcp
prompt_port DB_PORT tcp
prompt_port API_PORT tcp
prompt_port WEB_UI_PORT tcp
prompt_port PHPMYADMIN_PORT tcp

temp_file=$(mktemp "$root/.env.setup.XXXXXXXX")
trap 'rm -f -- "$temp_file"' EXIT
while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" =~ ^#?([A-Z][A-Z0-9_]*)= ]]; then
        key=${BASH_REMATCH[1]}
        if [[ -v updates[$key] ]]; then
            [[ ! -v seen[$key] ]] || fail "Duplicate $key in .env.example."
            printf '%s=%s\n' "$key" "${updates[$key]}" >> "$temp_file"
            seen["$key"]=1
            continue
        fi
    fi
    printf '%s\n' "$line" >> "$temp_file"
done < "$template"
for key in "${!updates[@]}"; do
    [[ -v seen[$key] ]] || fail "Missing $key in .env.example."
done
chmod 600 -- "$temp_file"
if [[ "$original_public" == true ]]; then
    [[ -f "$output" && ! -L "$output" ]] && cmp -s -- "$output" "$template" ||
        fail '.env changed during setup; refusing to overwrite it.'
    mv -f -- "$temp_file" "$output"
else
    ln -- "$temp_file" "$output" || fail '.env was created during setup; refusing to overwrite it.'
fi
printf 'Created %s (mode 0600). Review it before running Docker Compose.\n' "$output"
if [[ ${updates[HA_ENABLED]} == true ]]; then
    printf 'Use the same API_PORT on both nodes; keep HA_DB_OFFSET with this node if its role changes.\n'
fi
