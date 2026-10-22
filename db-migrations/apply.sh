#!/bin/sh
set -eu

DB_HOST="${DB_HOST:-mariadb}"
DB_USER="${DB_USER:-radius}"
DB_PASS="${DB_PASSWORD:-}"
DB_NAME="${DB_NAME:-radius}"

mysql_cmd() {
    MYSQL_PWD="$DB_PASS" mariadb --protocol=tcp --skip-ssl -h "$DB_HOST" -u "$DB_USER" "$DB_NAME" "$@"
}

until mysql_cmd -e 'SELECT 1' >/dev/null 2>&1; do
    echo "Waiting for MariaDB at ${DB_HOST}..."
    sleep 2
done

mysql_cmd <<'SQL'
CREATE TABLE IF NOT EXISTS schema_migrations (
    migration_name VARCHAR(128) NOT NULL PRIMARY KEY,
    applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
SQL

for migration in /migrations/*.sql; do
    [ -f "$migration" ] || continue
    name=$(basename "$migration" .sql)
    applied=$(mysql_cmd -N -B --execute="SELECT COUNT(*) FROM schema_migrations WHERE migration_name = '${name}'")
    if [ "$applied" = "1" ]; then
        echo "Migration ${name} already recorded; skipping."
        continue
    fi
    if [ "$applied" != "0" ]; then
        echo "Migration ${name} has an invalid migration record count: ${applied}" >&2
        exit 1
    fi

    echo "Applying migration ${name}..."
    mysql_cmd < "$migration"
    mysql_cmd -e 'INSERT IGNORE INTO schema_migrations (migration_name) VALUES (?)' --execute="INSERT IGNORE INTO schema_migrations (migration_name) VALUES ('${name}')"
    recorded=$(mysql_cmd -N -B --execute="SELECT COUNT(*) FROM schema_migrations WHERE migration_name = '${name}'")
    if [ "$recorded" != "1" ]; then
        echo "Migration ${name} was not recorded; refusing to start dependent services." >&2
        exit 1
    fi
    echo "Migration ${name} applied and verified."
done
