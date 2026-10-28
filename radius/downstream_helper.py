"""Synchronous, fail-closed PAP downstream decision engine; no listener or packet forwarding."""
from dataclasses import dataclass
from functools import lru_cache
import io
import ipaddress
import json
import os
from pathlib import Path
import socket
import sys

from pyrad import dictionary, packet


@dataclass(frozen=True)
class Request:
    kind: str
    username: str
    password: str = ''
    accounting: dict | None = None
    auth: list | None = None


@dataclass(frozen=True)
class Route:
    destination: str
    auth_port: int
    accounting_port: int
    secret: bytes
    mode: str
    validate_response: bool


class MariaDB:
    """Read-only application account; password from an owner-private option file."""
    def __init__(self, defaults_file='/run/radiusstack-radsec-db.cnf'):
        import pymysql
        self.conn = pymysql.connect(read_default_file=defaults_file, cursorclass=pymysql.cursors.DictCursor,
                                    connect_timeout=1, read_timeout=1, write_timeout=1, autocommit=True)

    def query(self, sql, args):
        with self.conn.cursor() as cursor:
            cursor.execute(sql, args)
            return cursor.fetchone()

    def query_all(self, sql, args):
        with self.conn.cursor() as cursor:
            cursor.execute(sql, args)
            return cursor.fetchall()

    def close(self):
        self.conn.close()


def resolve_route(db, source_ip, username, kind='auth'):
    """Source packet IP, not NAS-IP-Address AVP, binds tenant and source NAS."""
    ipaddress.IPv4Address(source_ip)
    nas_rows = db.query_all('SELECT id, tenant_id, downstream_destination_id, downstream_mode, '
                            'downstream_validate_response FROM nas WHERE nasname = %s LIMIT 2', (source_ip,))
    if len(nas_rows) > 1:
        raise ValueError('ambiguous NAS source')
    if not nas_rows:
        return None
    nas = nas_rows[0]
    tenant = nas['tenant_id']
    configured = None
    if username and db.query('SELECT 1 AS known FROM radcheck WHERE username = %s AND tenant_id <=> %s LIMIT 1',
                             (username, tenant)):
        configured = db.query('SELECT r.destination_id, r.mode, r.validate_response '
                              'FROM radusergroup g JOIN profile_downstream_routes r '
                              'ON r.profile_name = g.groupname AND r.tenant_id <=> g.tenant_id '
                              'WHERE g.username = %s AND g.tenant_id <=> %s '
                              'ORDER BY g.priority, g.id LIMIT 1', (username, tenant))
    if configured:
        dest_id, mode, validate = configured['destination_id'], configured['mode'], configured['validate_response']
    else:
        dest_id, mode, validate = (nas['downstream_destination_id'], nas['downstream_mode'],
                                   nas['downstream_validate_response'])
    if not dest_id:
        return None
    dest = db.query('SELECT ipv4, auth_port, accounting_port, shared_secret '
                    'FROM downstream_radius_destinations WHERE tenant_id <=> %s AND id = %s', (tenant, dest_id))
    permitted = (mode == 'duplicate' and bool(validate)) or (kind == 'acct' and mode == 'proxy-only' and not validate)
    if not dest or not permitted:
        raise ValueError('unusable route')
    target = ipaddress.IPv4Address(dest['ipv4'])
    if not (target.is_private or target.is_global):
        raise ValueError('unsafe destination')
    if target.is_loopback or target.is_link_local or str(target) == source_ip or target.is_multicast or target.is_unspecified:
        raise ValueError('unsafe destination')
    blocked = {ip.strip() for ip in os.environ.get('DOWNSTREAM_DENY_IPS', '').split(',') if ip.strip()}
    if str(target) in blocked:
        raise ValueError('unsafe destination')
    secret = dest['shared_secret']
    if not secret:
        raise ValueError('missing downstream secret')
    auth_port, acct_port = int(dest['auth_port']), int(dest['accounting_port'])
    if not all(1 <= port <= 65535 for port in (auth_port, acct_port)):
        raise ValueError('invalid port')
    own_ips = {'127.0.0.1'}
    try:
        own_ips.update(socket.gethostbyname_ex(socket.gethostname())[2])
    except OSError:
        pass
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect((str(target), auth_port))  # Select an egress source; send no packet.
        own_ips.add(probe.getsockname()[0])
    if str(target) in own_ips:
        raise ValueError('unsafe destination')
    return Route(str(target), auth_port, acct_port, secret.encode() if isinstance(secret, str) else secret,
                 mode, True)


@lru_cache(maxsize=2)
def _dictionary(path):
    """Read trusted FreeRADIUS includes with explicit UTF-8; embedded Python may use ASCII."""
    budget = [0]

    def expand(name, active):
        file = Path(name).resolve()
        if file in active:
            raise ValueError('recursive dictionary include')
        with file.open('rt', encoding='utf-8', errors='replace') as stream:
            for line in stream:
                budget[0] += len(line)
                if budget[0] > 16 * 1024 * 1024:
                    raise ValueError('dictionary exceeds size limit')
                fields = line.split('#', 1)[0].strip().split()
                if fields and fields[0].upper() in ('$INCLUDE', '$INCLUDE-'):
                    if len(fields) < 2:
                        raise ValueError('missing dictionary include name')
                    child = Path(' '.join(fields[1:]))
                    if not child.is_absolute():
                        child = file.parent / child
                    if fields[0].upper() == '$INCLUDE-' and not child.exists():
                        continue
                    yield from expand(child, active | {file})
                else:
                    yield line

    return dictionary.Dictionary(io.StringIO(''.join(expand(path, set()))))


def _accounting_packet(route, request, dict_path):
    if not isinstance(request.accounting, (list, tuple)):
        return None
    entries = request.accounting
    names = [name for name, _ in entries if isinstance(name, str)]
    if names.count('Acct-Status-Type') != 1:
        return None
    status = next(value for name, value in entries if name == 'Acct-Status-Type')
    if status not in ('Accounting-On', 'Accounting-Off') and (
            names.count('User-Name') != 1 or names.count('Acct-Session-Id') != 1):
        return None
    if names.count('User-Name') > 1 or names.count('Acct-Session-Id') > 1:
        return None
    lookup = _dictionary(dict_path)
    pkt = packet.AcctPacket(code=packet.AccountingRequest, secret=route.secret, dict=lookup)
    for name, value in entries:
        if not isinstance(name, str) or not isinstance(value, str):
            return None
        if name.startswith('Tmp-') or name in ('Acct-Unique-Session-Id', 'SQL-User-Name'):
            continue  # FreeRADIUS-only control fields, never wire AVPs.
        if name == 'Message-Authenticator':
            continue  # It belongs to the original NAS secret, not this peer.
        if name not in lookup.attributes:
            return None  # Never silently lose a wire accounting AVP.
        try:
            meta = lookup.attributes[name]
            encoded = int(value) if meta.type in ('integer', 'integer64', 'signed') and value.isdecimal() else value
            pkt.AddAttribute(name, encoded)
        except (ValueError, TypeError, KeyError):
            return None
    return pkt


# NAS metadata needed by downstream authorization; no control/internal attributes,
# Proxy-State, encrypted attributes, or vendor attributes may be synthesized.
AUTH_CONTEXT = frozenset(('NAS-IP-Address', 'NAS-Port', 'NAS-Port-Type', 'Service-Type',
                          'Called-Station-Id', 'Calling-Station-Id', 'Connect-Info'))


def _auth_packet(route, request, dict_path):
    if not request.username or not request.password:
        return None
    lookup = _dictionary(dict_path) if request.auth else dictionary.Dictionary()
    pkt = packet.AuthPacket(code=packet.AccessRequest, secret=route.secret, dict=lookup)
    pkt[1] = [request.username.encode('utf-8')]
    pkt[2] = [pkt.PwCrypt(request.password)]
    seen = set()
    for name, value in request.auth or ():
        if not isinstance(name, str) or not isinstance(value, str) or len(value) > 253:
            return None
        if name not in AUTH_CONTEXT:
            continue
        if name in seen:
            return None
        seen.add(name)
        if name not in pkt.dict.attributes:
            return None
        try:
            meta = pkt.dict.attributes[name]
            pkt.AddAttribute(name, int(value) if meta.type == 'integer' and value.isdecimal() else value)
        except (ValueError, TypeError, KeyError):
            return None
    pkt.add_message_authenticator()
    return pkt


def verify(route, request, timeout=1.0, dict_path='/opt/share/freeradius/dictionary'):
    """Only an authenticated downstream response permits local processing."""
    if not 0 < timeout <= 3:
        raise ValueError('invalid timeout')
    if request.kind == 'auth':
        pkt = _auth_packet(route, request, dict_path)
        if pkt is None:
            return 'error'
        target_port = route.auth_port
    elif request.kind == 'acct':
        pkt = _accounting_packet(route, request, dict_path)
        if pkt is None:
            return 'error'
        target_port = route.accounting_port
    else:
        return 'error'
    raw = pkt.RequestPacket()
    if len(raw) > 4096:
        return 'error'
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.connect((route.destination, target_port))
        sock.send(raw)
        try:
            while True:
                raw_reply = sock.recv(4096)
                try:
                    reply = pkt.CreateReply(packet=raw_reply)
                    if not pkt.VerifyReply(reply, raw_reply, enforce_ma=(request.kind == 'auth')):
                        continue
                    if request.kind == 'acct':
                        return 'accept' if reply.code == packet.AccountingResponse else 'reject'
                    return 'accept' if reply.code == packet.AccessAccept else 'reject'
                except (packet.PacketError, ValueError):
                    continue
        except socket.timeout:
            return 'timeout'


def decide(db, source_ip, request):
    try:
        route = resolve_route(db, source_ip, request.username, request.kind)
        return 'unrouted' if route is None else verify(route, request)
    except Exception:
        return 'error'


def run_cli(argv, stdin, stdout, db_factory=MariaDB):
    """Trusted stdin JSON only; argv is always rejected. stdout contains outcome only."""
    outcome = 'error'
    if not argv:
        db = None
        try:
            data = json.load(stdin)
            if not isinstance(data, dict) or set(data) != {'source_ip', 'username', 'password', 'kind'}:
                raise ValueError('invalid input')
            if not all(isinstance(data[key], str) for key in data):
                raise ValueError('invalid types')
            db = db_factory()
            outcome = decide(db, data['source_ip'], Request(data['kind'], data['username'], data['password']))
        except Exception:
            pass
        finally:
            if db is not None and hasattr(db, 'close'):
                db.close()
    stdout.write(json.dumps({'outcome': outcome}) + '\n')
    return 0 if outcome in ('accept', 'reject', 'timeout', 'unrouted') else 1


if __name__ == '__main__':
    sys.exit(run_cli(sys.argv[1:], sys.stdin, sys.stdout))
