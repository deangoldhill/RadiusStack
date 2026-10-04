#!/bin/sh
set -eu
RADD=/opt/etc/raddb
SITE="$RADD/sites-available/radsec"
ENABLED="$RADD/sites-enabled/radsec"
ROOT=/certs_radsec
LISTENER="$ROOT/listener"
BUNDLE="$ROOT/enabled-ca-bundle.pem"
SERVER_CA_KEY="$LISTENER/server-ca.key"
SERVER_CA_PEM="$LISTENER/server-ca.pem"
SERVER_KEY="$LISTENER/server.key"
SERVER_PEM="$LISTENER/server.pem"
SERVER_FULLCHAIN_PEM="$LISTENER/server-fullchain.pem"
SERVER_DNS="${RADSEC_SERVER_DNS:-radiusstack-radsec}"
SERVER_IP="${RADSEC_SERVER_IP:-}"
mysql_q() { MYSQL_PWD="${DB_PASSWORD:?DB_PASSWORD required}" mysql --skip-ssl -N -B -h "${DB_HOST:-mariadb}" -u "${DB_USER:-radius}" -D "${DB_NAME:-radius}" -e "$1"; }
archive() { if [ -e "$1" ]; then mv "$1" "$1.replaced-$(date +%s)"; fi; }
enabled_count=$(mysql_q "SELECT COUNT(*) FROM tenant_settings WHERE setting_key='radsec_enabled' AND setting_value IN ('true','1')")
if [ "$enabled_count" -eq 0 ]; then rm -f "$ENABLED" "$SITE" "$BUNDLE" "$SERVER_FULLCHAIN_PEM"; echo 'RadSec listener disabled: no tenant has radsec_enabled=true'; exit 0; fi
umask 077
mkdir -p "$LISTENER"
: > "$BUNDLE"
for tenant_id in $(mysql_q "SELECT tenant_id FROM tenant_settings WHERE setting_key='radsec_enabled' AND setting_value IN ('true','1') ORDER BY tenant_id"); do
  ca="$ROOT/tenant-$tenant_id/ca.pem"
  [ -r "$ca" ] || { echo "FATAL: RadSec enabled tenant $tenant_id lacks its client CA certificate" >&2; exit 1; }
  cat "$ca" >> "$BUNDLE"; printf '\n' >> "$BUNDLE"
done
[ -s "$BUNDLE" ] || { echo 'FATAL: enabled RadSec client-CA bundle is empty' >&2; exit 1; }
if [ ! -s "$SERVER_CA_KEY" ] || [ ! -s "$SERVER_CA_PEM" ] || ! openssl x509 -in "$SERVER_CA_PEM" -noout >/dev/null 2>&1 || ! openssl verify -CAfile "$SERVER_CA_PEM" "$SERVER_CA_PEM" >/dev/null 2>&1 || ! openssl x509 -in "$SERVER_CA_PEM" -text -noout | grep -A1 'Basic Constraints' | grep -q 'CA:TRUE'; then
  archive "$SERVER_CA_KEY"; archive "$SERVER_CA_PEM"
  CA_CSR="$LISTENER/server-ca.csr.$$"; CA_EXT="$LISTENER/server-ca.ext.$$"
  openssl req -newkey rsa:3072 -sha256 -nodes -subj '/O=RadiusStack/CN=RadiusStack RadSec Server Trust CA' -keyout "$SERVER_CA_KEY" -out "$CA_CSR" >/dev/null 2>&1
  printf '%s\n' 'basicConstraints=critical,CA:TRUE,pathlen:0' 'keyUsage=critical,keyCertSign,cRLSign' 'subjectKeyIdentifier=hash' 'authorityKeyIdentifier=keyid:always' > "$CA_EXT"
  openssl x509 -req -sha256 -days 3650 -in "$CA_CSR" -signkey "$SERVER_CA_KEY" -extfile "$CA_EXT" -out "$SERVER_CA_PEM" >/dev/null 2>&1
  rm -f "$CA_CSR" "$CA_EXT"
  archive "$SERVER_KEY"; archive "$SERVER_PEM"
fi
leaf_is_valid() {
  [ -s "$SERVER_KEY" ] && [ -s "$SERVER_PEM" ] && openssl verify -CAfile "$SERVER_CA_PEM" "$SERVER_PEM" >/dev/null 2>&1 && [ "$(openssl x509 -in "$SERVER_PEM" -noout -subject)" != "$(openssl x509 -in "$SERVER_PEM" -noout -issuer)" ] && openssl x509 -in "$SERVER_PEM" -text -noout | grep -A1 'Basic Constraints' | grep -q 'CA:FALSE' && openssl x509 -in "$SERVER_PEM" -text -noout | grep -q 'TLS Web Server Authentication'
}
if ! leaf_is_valid; then
  archive "$SERVER_KEY"; archive "$SERVER_PEM"
  CSR="$LISTENER/server.csr.$$"; EXT="$LISTENER/server.ext.$$"; trap 'rm -f "$CSR" "$EXT"' EXIT HUP INT TERM
  SAN="DNS:${SERVER_DNS}"; [ -n "$SERVER_IP" ] && SAN="$SAN,IP:${SERVER_IP}"
  printf '%s\n' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature,keyEncipherment' 'extendedKeyUsage=serverAuth' "subjectAltName=$SAN" > "$EXT"
  openssl req -newkey rsa:3072 -sha256 -nodes -subj "/O=RadiusStack/CN=${SERVER_DNS}" -keyout "$SERVER_KEY" -out "$CSR" >/dev/null 2>&1
  openssl x509 -req -sha256 -days 3650 -in "$CSR" -CA "$SERVER_CA_PEM" -CAkey "$SERVER_CA_KEY" -CAcreateserial -extfile "$EXT" -out "$SERVER_PEM" >/dev/null 2>&1
  rm -f "$CSR" "$EXT" "$SERVER_CA_PEM.srl"; trap - EXIT HUP INT TERM
fi
cat "$SERVER_PEM" "$SERVER_CA_PEM" > "$SERVER_FULLCHAIN_PEM"
chmod 0700 "$ROOT" "$LISTENER"; chmod 0600 "$SERVER_CA_KEY" "$SERVER_KEY"; chmod 0644 "$SERVER_CA_PEM" "$SERVER_PEM" "$SERVER_FULLCHAIN_PEM" "$BUNDLE"
mkdir -p /tmp/radsec-verify; chmod 0700 /tmp/radsec-verify
cat > "$SITE" <<'EOF'
listen {
    ipaddr = *
    port = 2083
    type = auth+acct
    proto = tcp
    virtual_server = default
    check_client_connections = yes
    limit {
        max_connections = 128
        idle_timeout = 30
    }
    tls {
        private_key_file = /certs_radsec/listener/server.key
        certificate_file = /certs_radsec/listener/server-fullchain.pem
        ca_file = /certs_radsec/enabled-ca-bundle.pem
        tls_min_version = "1.2"
        tls_max_version = "1.3"
        require_client_cert = yes
        verify {
            tmpdir = /tmp/radsec-verify
            client = "/usr/local/sbin/radsec-verify-client %{TLS-Client-Cert-Filename}"
        }
    }
}
EOF
ln -sfn "$SITE" "$ENABLED"
echo "RadSec listener enabled for $enabled_count tenant(s); NAS clients trust $SERVER_CA_PEM"
