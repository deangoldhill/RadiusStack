#!/bin/sh
mkdir -p /certs_shared
if [ ! -f /certs_shared/server.pem ]; then
    echo "Generating default 10-year EAP certificates..."
    openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 \
        -keyout /certs_shared/server.key -out /certs_shared/server.pem \
        -subj "/C=US/ST=State/L=City/O=Radius/CN=RadiusServer"
fi

chmod 644 /certs_shared/server.key
chmod 644 /certs_shared/server.pem

# Use env vars injected by Docker Compose (from container_config.env)
DB_HOST="${DB_HOST:-mariadb}"
DB_USER="${DB_USER:-radius}"
DB_PASS="${DB_PASSWORD:-}"
DB_NAME="${DB_NAME:-radius}"

echo "Waiting for MariaDB at ${DB_HOST}..."
until mysql -h "${DB_HOST}" -u "${DB_USER}" -p"${DB_PASS}" -D "${DB_NAME}" -e "SELECT 1" >/dev/null 2>&1; do
    sleep 2
done

DEBUG_MODE=$(mysql -h "${DB_HOST}" -u "${DB_USER}" -p"${DB_PASS}" -D "${DB_NAME}" -N -B \
    -e "SELECT setting_value FROM settings WHERE setting_key='radius_debug';" 2>/dev/null)

# Locate the radiusd executable robustly
if command -v radiusd >/dev/null 2>&1; then
    RAD_CMD="radiusd"
elif [ -x "/opt/sbin/radiusd" ]; then
    RAD_CMD="/opt/sbin/radiusd"
elif [ -x "/opt/bin/radiusd" ]; then
    RAD_CMD="/opt/bin/radiusd"
elif [ -x "/usr/sbin/radiusd" ]; then
    RAD_CMD="/usr/sbin/radiusd"
elif [ -x "/usr/local/sbin/radiusd" ]; then
    RAD_CMD="/usr/local/sbin/radiusd"
else
    echo "Searching for radiusd..."
    RAD_CMD=$(find / -type f -name radiusd -executable 2>/dev/null | head -n 1)
fi

if [ -z "$RAD_CMD" ]; then
    echo "FATAL ERROR: radiusd executable not found anywhere on the system!"
    exit 1
fi

if [ "$DEBUG_MODE" = "true" ]; then
    echo "Starting FreeRADIUS ($RAD_CMD) in DEBUG mode (-X)..."
    exec "$RAD_CMD" -X
else
    echo "Starting FreeRADIUS ($RAD_CMD) in NORMAL mode (logging to stdout)..."
    exec "$RAD_CMD" -f -l stdout
fi