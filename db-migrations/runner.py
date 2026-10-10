"""Versioned RadiusStack MariaDB migrations."""
import argparse
import os
import re
import sys
import hashlib
from pathlib import Path
from typing import NamedTuple


class Migration(NamedTuple):
    name: str
    checksum: str
    sql: str


def discover(path):
    root = Path(path)
    if not root.is_dir():
        raise ValueError(f'Migration directory missing: {root}')
    result = []
    for file in sorted(root.glob('*.sql')):
        if not re.fullmatch(r'[0-9]{8}_[a-z0-9_]+', file.stem) or len(file.stem) > 128:
            raise ValueError(f'Invalid versioned migration filename: {file.name}')
        data = file.read_bytes()
        result.append(Migration(file.stem, hashlib.sha256(data).hexdigest(), data.decode('utf-8')))
    if not result:
        raise ValueError(f'No SQL migrations in {root}')
    return result


def execute(db, sql, params=None):
    with db.cursor() as cur:
        cur.execute(sql, params)
        while cur.nextset():
            pass


def query(db, sql, params=None):
    with db.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall()


def metadata(db):
    tables = {r[0] for r in query(db, 'SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE()')}
    columns = {(t, c): nullable for t, c, nullable in query(db, 'SELECT TABLE_NAME,COLUMN_NAME,IS_NULLABLE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE()')}
    indexes = {(t, idx) for t, idx in query(db, 'SELECT TABLE_NAME,INDEX_NAME FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE()')}
    return tables, columns, indexes


TENANT_TABLES = {'tenants', 'admin_tenants', 'tenant_settings', 'plan_pod_enforcements'}
LEGACY_TABLES = {'admins', 'nas', 'radcheck', 'radreply', 'radacct', 'settings', 'plans'}
TENANT_COLUMNS = {('admins', 'is_super_admin'), ('nas', 'dynamic_auth_attributes'),
    ('plans', 'auto_pod_on_data_depleted'), ('plans', 'auto_pod_on_time_depleted'),
    ('radacct', 'nasidentifier'), ('admin_audit_log', 'tenant_id'),
    ('plan_pod_enforcements', 'radacctid'), ('plan_pod_enforcements', 'tenant_id'),
    ('plan_pod_enforcements', 'reason'), ('plan_pod_enforcements', 'status')}
TENANT_SCOPED = ('nas', 'radcheck', 'radreply', 'radusergroup', 'radgroupcheck',
    'radgroupreply', 'plans', 'mac_auth_devices', 'user_plans', 'user_plan_usage',
    'user_totp', 'radacct', 'radpostauth')
TENANT_INDEXES = {('admin_tenants', 'PRIMARY'), ('tenant_settings', 'PRIMARY'),
    ('nas', 'uq_nas_tenant_ip'), ('radacct', 'idx_radacct_tenant'),
    ('radacct', 'idx_radacct_nasidentifier'), ('radcheck', 'uq_radcheck_username_attribute'),
    ('radpostauth', 'idx_radpostauth_tenant'), ('admin_audit_log', 'idx_audit_tenant'),
    ('plans', 'uq_plans_tenant_name'), ('plan_pod_enforcements', 'PRIMARY'),
    ('plan_pod_enforcements', 'idx_plan_pod_enforcements_tenant_status'),
    ('radgroupcheck', 'uq_radgroupcheck_tenant_group_attribute_value'),
    ('radgroupreply', 'uq_radgroupreply_tenant_group_attribute')}


def validate_tenant_baseline(db):
    """Return True for fully verified tenant schema, False for genuine legacy HEAD.

    Any tenant footprint that does not satisfy all postconditions is unsafe.
    """
    tables, columns, indexes = metadata(db)
    if not LEGACY_TABLES <= tables:
        raise RuntimeError(f'Unknown baseline: missing core tables {sorted(LEGACY_TABLES - tables)}')
    if 'tenants' not in tables and not any((t, 'tenant_id') in columns for t in TENANT_SCOPED):
        return False
    required = TENANT_COLUMNS | {(t, 'tenant_id') for t in TENANT_SCOPED} | {
        ('tenant_settings', 'tenant_id'), ('tenant_settings', 'setting_value')}
    missing = (TENANT_TABLES - tables) or (required - columns.keys()) or (TENANT_INDEXES - indexes)
    nullable = [t for t in TENANT_SCOPED if columns.get((t, 'tenant_id')) != 'NO']
    if missing or nullable or columns.get(('tenant_settings', 'setting_value')) != 'NO':
        raise RuntimeError(f'Incomplete tenant baseline (missing={missing}, nullable={nullable})')
    if query(db, "SELECT COUNT(*) FROM tenants WHERE name='Default'")[0][0] != 1:
        raise RuntimeError('Incomplete tenant baseline: Default tenant missing')
    return True


POSTCONDITIONS = {
    '20260802_tenant_settings_stats': ({'radius_stats', 'settings', 'tenant_settings'}, {('radius_stats', 'tenant_id')}, {('radius_stats', 'idx_radius_stats_tenant_time')}),
    '20260918_radsec': ({'radsec_clients'}, {('nas', 'radsec_enabled'), ('radsec_clients', 'tenant_id'), ('radsec_clients', 'nas_id')}, {('radsec_clients', 'uq_radsec_client_serial')}),
    '20260919_radsec_credential_sets': ({'radsec_credential_sets', 'radsec_credential_set_nas'}, {('radsec_clients', 'credential_set_id')}, {('radsec_clients', 'idx_radsec_clients_set'), ('radsec_credential_sets', 'uq_radsec_credential_sets_serial')}),
    '20260924_radsec_proxy_enrollments': ({'radsec_proxy_enrollments'}, {('radsec_proxy_enrollments', 'tenant_id'), ('radsec_proxy_enrollments', 'radsec_client_id')}, {('radsec_proxy_enrollments', 'uq_radsec_proxy_enrollments_client')}),
    '20260929_radsec_nas_passphrases': ({'radsec_nas_passphrases'}, {('radsec_nas_passphrases', 'ciphertext'), ('radsec_nas_passphrases', 'auth_tag')}, {('nas', 'uq_nas_tenant_id'), ('radsec_nas_passphrases', 'uq_radsec_nas_passphrase_tenant_nas')}),
    '20261009_ha_columns': (set(), {('ha_queue', 'insert_id'), ('ha_sync_state', 'last_time'), ('radacct', 'ha_updated_at')}, set()),
}


def validate_postcondition(db, name):
    if name == '20260801_legacy_to_tenants':
        if not validate_tenant_baseline(db):
            raise RuntimeError(f'Migration postcondition absent: {name}')
        return
    if name not in POSTCONDITIONS:
        return
    tables, columns, indexes = metadata(db)
    required_tables, required_columns, required_indexes = POSTCONDITIONS[name]
    if not required_tables <= tables or not required_columns <= columns.keys() or not required_indexes <= indexes:
        raise RuntimeError(f'Migration postcondition incomplete: {name}')
    if name == '20260802_tenant_settings_stats':
        for table in ('settings', 'tenant_settings'):
            types = query(db, 'SELECT DATA_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=%s AND COLUMN_NAME=\'setting_value\'', (table,))
            if len(types) != 1 or types[0][0] != 'text':
                raise RuntimeError(f'Migration postcondition incomplete: {name} {table}.setting_value')
    if name == '20260919_radsec_credential_sets' and query(db,
            'SELECT COUNT(*) FROM radsec_clients rc LEFT JOIN radsec_credential_sets cs ON cs.id=rc.credential_set_id AND cs.serial=rc.serial LEFT JOIN radsec_credential_set_nas cn ON cn.credential_set_id=rc.credential_set_id AND cn.nas_id=rc.nas_id WHERE cs.id IS NULL OR cn.nas_id IS NULL')[0][0]:
        raise RuntimeError(f'Migration postcondition incomplete: {name} credential backfill')


def run(db, path, migrate=False):
    """Check or apply migrations, holding one session-level MariaDB lock throughout."""
    try:
        migrations = discover(path)
        if query(db, "SELECT GET_LOCK('radiusstack_schema_migrations', 60)")[0][0] != 1:
            raise RuntimeError('Could not acquire migration lock')
        try:
            tables = {row[0] for row in query(db, 'SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE()')}
            columns = {(t, c) for t, c, _ in query(db, 'SELECT TABLE_NAME,COLUMN_NAME,IS_NULLABLE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE()')}
            if any(m.name == '20260801_legacy_to_tenants' for m in migrations):
                validate_tenant_baseline(db)
            if 'schema_migrations' in tables:
                if not {('schema_migrations', 'checksum'), ('schema_migrations', 'state')} <= columns:
                    if not migrate:
                        raise RuntimeError('Legacy ledger lacks checksum/state; run --migrate')
                    execute(db, 'ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS checksum CHAR(64) NULL, ADD COLUMN IF NOT EXISTS state VARCHAR(16) NOT NULL DEFAULT \'applied\'')
                applied = {name: (checksum, state) for name, checksum, state in query(db, 'SELECT migration_name, checksum, state FROM schema_migrations')}
            else:
                applied = {}
                if migrate:
                    execute(db, "CREATE TABLE schema_migrations (migration_name VARCHAR(128) PRIMARY KEY, checksum CHAR(64) NULL, state VARCHAR(16) NOT NULL DEFAULT 'applied', applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)")
            known = {m.name: m for m in migrations}
            for name, (checksum, state) in applied.items():
                if name not in known:
                    raise RuntimeError(f'Unknown applied migration: {name}')
                if state != 'applied':
                    raise RuntimeError(f'Incomplete migration: {name}')
                if checksum and checksum != known[name].checksum:
                    raise RuntimeError(f'Changed applied migration: {name}')
                validate_postcondition(db, name)
                if not checksum:
                    if not migrate:
                        raise RuntimeError(f'Unchecked legacy checksum: {name}; run --migrate')
                    execute(db, 'UPDATE schema_migrations SET checksum=%s, state=\'applied\', applied_at=CURRENT_TIMESTAMP WHERE migration_name=%s', (known[name].checksum, name))
                    db.commit()
            pending = [m for m in migrations if m.name not in applied]
            # Detect unledgered DDL before executing anything: MariaDB DDL is not rollbackable.
            completed = set()
            for m in pending:
                if m.name == '20260801_legacy_to_tenants':
                    if validate_tenant_baseline(db):
                        completed.add(m.name)
                elif m.name in POSTCONDITIONS:
                    tables_now, cols_now, idx_now = metadata(db)
                    required_tables, required_cols, required_idx = POSTCONDITIONS[m.name]
                    footprint = (required_tables & tables_now or required_cols & cols_now.keys() or required_idx & idx_now)
                    if m.name == '20260802_tenant_settings_stats':
                        # The legacy database already has both settings tables and radius_stats.
                        footprint = ('radius_stats', 'tenant_id') in cols_now
                    if m.name == '20261009_ha_columns':
                        # Two HA fields were present in both fresh and legacy init SQL;
                        # only radacct.ha_updated_at marks this migration as complete.
                        footprint = ('radacct', 'ha_updated_at') in cols_now
                    if footprint:
                        validate_postcondition(db, m.name)
                        completed.add(m.name)
            if migrate:
                for m in pending:
                    if m.name in completed:
                        execute(db, "INSERT INTO schema_migrations (migration_name, checksum, state) VALUES (%s, %s, 'applied')", (m.name, m.checksum))
                        db.commit()
                        continue
                    execute(db, 'INSERT INTO schema_migrations (migration_name, checksum, state) VALUES (%s, %s, \'applying\')', (m.name, m.checksum))
                    db.commit()
                    execute(db, m.sql)
                    validate_postcondition(db, m.name)
                    execute(db, 'UPDATE schema_migrations SET checksum=%s, state=\'applied\', applied_at=CURRENT_TIMESTAMP WHERE migration_name=%s', (m.checksum, m.name))
                    db.commit()
            return [m.name for m in pending]
        finally:
            query(db, "SELECT RELEASE_LOCK('radiusstack_schema_migrations')")
    finally:
        db.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description='Check or run RadiusStack MariaDB migrations')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--check', action='store_true', help='read-only validation and pending list')
    mode.add_argument('--migrate', action='store_true', help='apply verified migrations')
    parser.add_argument('--migrations', default='/migrations', help='directory of immutable SQL migrations')
    args = parser.parse_args(argv)
    import pymysql
    db = pymysql.connect(host=os.environ.get('DB_HOST', 'mariadb'),
                         user=os.environ.get('DB_USER', 'radius'),
                         password=os.environ.get('DB_PASSWORD', ''),
                         database=os.environ.get('DB_NAME', 'radius'),
                         charset='utf8mb4', autocommit=True,
                         client_flag=pymysql.constants.CLIENT.MULTI_STATEMENTS)
    pending = run(db, args.migrations, migrate=args.migrate)
    for name in pending:
        print(('applied' if args.migrate else 'pending') + ': ' + name)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as exc:
        print(f'Migration failed: {exc}', file=sys.stderr)
        sys.exit(1)
