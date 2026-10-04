#!/bin/sh
set -eu
debug_stage() { printf '%s\n' "$1" >> /certs_radsec/verifier-stage.log 2>/dev/null || true; }
cert=
for arg in "$@"; do
  case "$arg" in /tmp/radsec-verify/*) cert="$arg" ;; esac
done
[ -n "$cert" ] || { debug_stage bad-path; exit 1; }
[ -f "$cert" ] || { debug_stage missing-file; exit 1; }

subject=$(openssl x509 -in "$cert" -noout -subject -nameopt RFC2253 2>/dev/null) || { debug_stage subject-read; exit 1; }
serial=$(openssl x509 -in "$cert" -noout -serial 2>/dev/null | sed -n 's/^serial=//p' | tr 'A-F' 'a-f')
cn=$(printf '%s\n' "$subject" | sed -n 's/^subject=CN=\([^,]*\).*/\1/p')
case "$cn" in nas-[0-9]*-[0-9a-f]*) ;; *) debug_stage cn-parse; exit 1 ;; esac
nonce=${cn##*-}
[ ${#nonce} -eq 32 ] || { debug_stage nonce-length; exit 1; }
case "$nonce" in *[!0-9a-f]*) debug_stage nonce-format; exit 1 ;; esac
case "$serial" in ''|*[!0-9a-f]*) debug_stage serial-parse; exit 1 ;; esac

query="SELECT 1 FROM radsec_clients rc JOIN nas n ON n.id=rc.nas_id AND n.tenant_id=rc.tenant_id JOIN tenant_settings ts ON ts.tenant_id=rc.tenant_id AND ts.setting_key='radsec_enabled' AND ts.setting_value IN ('true','1') WHERE rc.common_name='$cn' AND rc.serial='$serial' AND rc.revoked_at IS NULL AND n.radsec_enabled=1 LIMIT 1"
result=$(mysql --defaults-extra-file=/run/radiusstack-radsec-db.cnf --skip-ssl -N -B -e "$query" 2>/dev/null) || { debug_stage mysql-query; exit 1; }
[ "$result" = 1 ] || { debug_stage no-active-record; exit 1; }
debug_stage accepted
