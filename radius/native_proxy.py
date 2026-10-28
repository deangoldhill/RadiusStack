#!/usr/bin/env python3
"""Generate FreeRADIUS 3.2 UDP proxy definitions from tenant destinations."""
import argparse
import ipaddress
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile

CONF = Path('/opt/etc/raddb')
DEST_SQL = ('SELECT id, tenant_id, ipv4, auth_port, accounting_port, shared_secret '
            'FROM downstream_radius_destinations ORDER BY id')
ROUTE_SQL = ("SELECT 'nas', downstream_destination_id, tenant_id, downstream_mode, "
             "downstream_validate_response FROM nas WHERE downstream_destination_id IS NOT NULL "
             "UNION ALL SELECT 'profile', destination_id, tenant_id, mode, validate_response "
             "FROM profile_downstream_routes")


def _integer(value, low, high):
    number = int(value)
    if str(number) != str(value) or not low <= number <= high:
        raise ValueError('Invalid integer in downstream destination')
    return number


def local_ipv4_addresses(rows):
    addresses = {'127.0.0.1'}
    addresses.update(s.strip() for s in os.environ.get('DOWNSTREAM_DENY_IPS', '').split(',') if s.strip())
    try:
        addresses.update(socket.gethostbyname_ex(socket.gethostname())[2])
    except OSError:
        pass
    for _, _, host, port, _, _ in rows:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                probe.connect((host, int(port)))  # No packet is transmitted.
                addresses.add(probe.getsockname()[0])
        except (OSError, ValueError):
            pass
    return addresses

def validate_rows(rows, routes, local_ips=None):
    if local_ips is None:
        local_ips = local_ipv4_addresses(rows)
    owners = {}
    for row in rows:
        ident, tenant, host, auth, acct, secret = row
        ident = _integer(ident, 1, 2147483647)
        if ident in owners:
            raise ValueError('Duplicate downstream destination id')
        owners[ident] = tenant
        addr = ipaddress.IPv4Address(host)
        if str(addr) in local_ips:
            raise ValueError('Unsafe self-target downstream endpoint')
        if not addr.is_global and not addr.is_private:
            raise ValueError('Unsafe downstream endpoint')
        if addr.is_loopback or addr.is_multicast or addr.is_unspecified or addr.is_link_local:
            raise ValueError('Unsafe downstream endpoint')
        _integer(auth, 1, 65535)
        _integer(acct, 1, 65535)
        if not secret or len(secret) > 253 or any(c in secret for c in '\r\n"\\') or any(ord(c) < 32 for c in secret):
            raise ValueError('Unsafe downstream shared secret syntax')
    for owner, dest, tenant, mode, validated in routes:
        dest = _integer(dest, 1, 2147483647)
        if dest not in owners or owners[dest] != tenant:
            raise ValueError('Cross-tenant or missing downstream destination')
        if mode not in ('proxy-only', 'duplicate') or (mode == 'proxy-only' and int(validated)):
            raise ValueError('Unsupported downstream mode')


def render(rows):
    validate_rows(rows, [])
    blocks = []
    for ident, tenant, host, auth, acct, secret in rows:
        for kind, port in (('auth', auth), ('acct', acct)):
            blocks.append(f'home_server downstream_{ident}_{kind} {{\n'
                          f' type = {kind}\n ipaddr = {host}\n port = {port}\n'
                          f' secret = "{secret}"\n response_window = 5\n'
                          f' zombie_period = 10\n revive_interval = 30\n}}\n')
            blocks.append(f'home_server_pool downstream_{ident}_{kind}_pool {{\n'
                          f' type = fail-over\n home_server = downstream_{ident}_{kind}\n}}\n')
        blocks.append(f'realm downstream_{ident} {{\n auth_pool = downstream_{ident}_auth_pool\n'
                      f' acct_pool = downstream_{ident}_acct_pool\n}}\n')
    return '\n'.join(blocks) + '\n'


def install_site(source):
    for section, invocation in (('authorize', 'native_proxy_auth'), ('preacct', 'native_proxy_acct')):
        if invocation in source.split(section + ' {', 1)[-1].split('\n}', 1)[0]:
            continue
        marker = section + ' {'
        if source.count(marker) != 1:
            raise ValueError(f'Expected one {section} section')
        source = source.replace(marker, marker + '\n\t' + invocation, 1)
    marker = 'accounting {'
    guard = '\n\tif (&control:Proxy-To-Realm) {\n\t\treturn\n\t}\n'
    if source.count(marker) != 1:
        raise ValueError('Expected one accounting section')
    if marker + guard not in source:
        source = source.replace(marker, marker + guard, 1)
    return source


def query(sql):
    # defaults-extra-file is owner-private and avoids database passwords in argv.
    result = subprocess.run(['mysql', '--defaults-extra-file=/run/radiusstack-radsec-db.cnf',
                             '--skip-ssl', '--batch', '--raw', '--skip-column-names', '-e', sql],
                            check=True, capture_output=True, text=True)
    return [tuple(None if value == 'NULL' else value for value in line.split('\t'))
            for line in result.stdout.splitlines()]


def generate(conf, rows, routes):
    validate_rows(rows, routes)
    target = conf / 'native-downstream-proxy.conf'
    content = render(rows)
    fd, temp = tempfile.mkstemp(prefix='.native-proxy-', dir=conf)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w') as out:
            out.write(content)
        os.replace(temp, target)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true', help='validate SQL routes and candidate radiusd configuration without changing live files')
    args = parser.parse_args()
    rows = query(DEST_SQL)
    routes = query(ROUTE_SQL)
    validate_rows(rows, routes)
    if args.check:
        # radiusd -XC is run against a complete private copy, never the live config.
        with tempfile.TemporaryDirectory(prefix='radius-native-check-') as tmp:
            import shutil
            conf = Path(tmp) / 'raddb'
            shutil.copytree(CONF, conf, symlinks=True)
            generate(conf, rows, routes)
            subprocess.run(['/opt/sbin/radiusd', '-XC', '-d', str(conf)], check=True)
    else:
        generate(CONF, rows, routes)


if __name__ == '__main__':
    main()
