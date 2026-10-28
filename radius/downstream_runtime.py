"""PAP-only UDP RADIUS router. Isolated front end for the local FreeRADIUS daemon.

No SQL values are interpolated into queries; secrets never enter logs/argv.
Matched CHAP/MSCHAP/EAP and malformed PAP are explicitly denied.
"""
import ipaddress
import logging
import os
import socket
import threading
from dataclasses import dataclass
from pathlib import Path

import pymysql
from pyrad import dictionary, packet

DICT = dictionary.Dictionary(str(Path(__file__).with_name('downstream.dictionary')))
LOG = logging.getLogger('radiusstack.downstream')


@dataclass(frozen=True)
class RadiusPeer:
    address: str
    auth_port: int
    accounting_port: int
    secret: bytes


@dataclass(frozen=True)
class Route:
    mode: str
    validate: bool
    peer: RadiusPeer


class SQLResolver:
    def __init__(self):
        self.db = dict(host=os.environ.get('DB_HOST', 'mariadb'),
                       user=os.environ.get('DB_USER', 'radius'),
                       password=os.environ.get('DB_PASSWORD', ''),
                       database=os.environ.get('DB_NAME', 'radius'),
                       connect_timeout=2, read_timeout=2,
                       cursorclass=pymysql.cursors.DictCursor)

    def __call__(self, source, username):
        with pymysql.connect(**self.db) as conn, conn.cursor() as cur:
            # FreeRADIUS accepts CIDR clients; match the same addresses here.
            cur.execute('SELECT nasname, secret, tenant_id, downstream_destination_id, '
                        'downstream_mode, downstream_validate_response FROM nas')
            clients = [n for n in cur.fetchall() if _contains(n['nasname'], source)]
            if len(clients) != 1:
                raise ValueError('unknown or ambiguous NAS')
            nas = clients[0]
            route = None
            if username:
                cur.execute('SELECT 1 FROM radcheck WHERE username=%s AND tenant_id <=> %s LIMIT 1',
                            (username, nas['tenant_id']))
                known = cur.fetchone() is not None
                if known:
                    cur.execute('SELECT r.destination_id, r.mode, r.validate_response '
                                'FROM radusergroup g JOIN profile_downstream_routes r '
                                'ON r.profile_name=g.groupname AND r.tenant_id <=> g.tenant_id '
                                'WHERE g.username=%s AND g.tenant_id <=> %s '
                                'ORDER BY g.priority, g.id LIMIT 1', (username, nas['tenant_id']))
                    route = cur.fetchone()
            if route is None and nas['downstream_destination_id'] is not None:
                route = dict(destination_id=nas['downstream_destination_id'],
                             mode=nas['downstream_mode'],
                             validate_response=nas['downstream_validate_response'])
            if route is None:
                return nas['secret'].encode(), None
            if route['mode'] not in ('duplicate', 'proxy-only'):
                raise ValueError('invalid downstream mode')
            cur.execute('SELECT ipv4, auth_port, accounting_port, shared_secret '
                        'FROM downstream_radius_destinations WHERE id=%s AND tenant_id <=> %s',
                        (route['destination_id'], nas['tenant_id']))
            dest = cur.fetchone()
            if not dest:
                raise ValueError('downstream target absent or cross-tenant')
            return nas['secret'].encode(), Route(route['mode'], bool(route['validate_response']),
                RadiusPeer(dest['ipv4'], int(dest['auth_port']), int(dest['accounting_port']),
                           dest['shared_secret'].encode()))


def _contains(network, source):
    try:
        return ipaddress.ip_address(source) in ipaddress.ip_network(network, strict=False)
    except ValueError:
        return False


class DownstreamRouter:
    def __init__(self, resolve, local, timeout=2.0):
        self.resolve, self.local, self.timeout = resolve, local, timeout
        self._source = threading.local()
        self.sock = None
        self.running = False

    def start(self, address=('0.0.0.0', 1812), accounting=('0.0.0.0', 1813)):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(address)
        self.address = self.sock.getsockname()
        self.sock.settimeout(.2)
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
        if accounting:
            self.acct_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.acct_sock.bind(accounting)
            self.acct_sock.settimeout(.2)
            self.acct_thread = threading.Thread(target=self._loop, args=(self.acct_sock,), daemon=True)
            self.acct_thread.start()
        else:
            self.acct_sock = None

    def close(self):
        self.running = False
        self.sock.close()
        if self.acct_sock:
            self.acct_sock.close()
            self.acct_thread.join(timeout=1)
        self.thread.join(timeout=1)

    def _loop(self, sock=None):
        sock = sock or self.sock
        while self.running:
            try:
                raw, address = sock.recvfrom(4096)
            except (OSError, socket.timeout):
                continue
            threading.Thread(target=self._serve, args=(sock, raw, address), daemon=True).start()

    def _serve(self, sock, raw, address):
        try:
            self._source.ip = address[0]
            if len(raw) < 20 or raw[0] not in (packet.AccessRequest, packet.AccountingRequest):
                return
            username = packet.AuthPacket(packet=raw, dict=DICT).get('User-Name', [None])[0]
            if isinstance(username, bytes):
                username = username.decode('utf8', errors='strict')
            secret, route = self.resolve(address[0], username)
            kind = packet.AcctPacket if raw[0] == packet.AccountingRequest else packet.AuthPacket
            req = kind(packet=raw, secret=secret, dict=DICT)
            if any(len(value) >= 6 and value[:6] == b'\x00\x00\xa0\x98\xfa\x06'
                   for value in req.get(26, [])):
                # Never allow a NAS to supply our private source stamp.
                return
            if raw[0] == packet.AccountingRequest and not req.VerifyAcctRequest():
                return
            if 80 in req and not req.verify_message_authenticator():
                return
            if route and _unsupported(req):
                if raw[0] == packet.AccountingRequest:
                    return
                response = _reply(req, packet.AccessReject)
            elif route is None:
                response = self._send(req, self.local)
            elif raw[0] == packet.AccountingRequest:
                local = self._send(req, self.local) if route.mode == 'duplicate' else None
                remote = self._send(req, route.peer)
                response = remote if route.mode == 'proxy-only' else local
            elif route.mode == 'proxy-only':
                response = self._send(req, route.peer)
            else:
                local = self._send(req, self.local)
                remote = self._send(req, route.peer)
                response = local
                if route.validate and (local is None or local.code != packet.AccessAccept or
                                       remote is None or remote.code != packet.AccessAccept):
                    response = _reply(req, packet.AccessReject)
            if response is not None:
                reply = _reply(req, response.code, response)
                if 80 in req and raw[0] == packet.AccessRequest:
                    reply.add_message_authenticator()
                sock.sendto(reply.ReplyPacket(), address)
            elif route and raw[0] == packet.AccessRequest:
                # Downstream timeout must never turn into a local accept.
                reply = _reply(req, packet.AccessReject)
                if 80 in req:
                    reply.add_message_authenticator()
                sock.sendto(reply.ReplyPacket(), address)
        except Exception:
            LOG.exception('RADIUS request failed without exposing request attributes')

    def _send(self, req, peer):
        kind = packet.AcctPacket if req.code == packet.AccountingRequest else packet.AuthPacket
        outbound = kind(code=req.code, id=req.id, secret=peer.secret, dict=DICT)
        for key, values in req.items():
            if key in (2, 80) or key == 26 and peer is not self.local:
                continue
            outbound[key] = list(values)
        if peer is self.local:
            # Only the router can reach the loopback backend and knows this
            # socket's peer; never trust a NAS-provided source assertion.
            outbound['RadiusStack-Source-IP'] = self._source.ip
        if req.code == packet.AccessRequest and 2 in req:
            try:
                outbound[2] = [outbound.PwCrypt(req.PwDecrypt(req[2][0]))]
            except (KeyError, ValueError):
                return None
        if req.code == packet.AccessRequest:
            outbound.add_message_authenticator()
        raw = outbound.RequestPacket()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            sender.settimeout(self.timeout)
            sender.sendto(raw, (peer.address, peer.accounting_port if req.code == packet.AccountingRequest else peer.auth_port))
            try:
                answer, source = sender.recvfrom(4096)
            except socket.timeout:
                return None
            if source != (peer.address, peer.accounting_port if req.code == packet.AccountingRequest else peer.auth_port):
                return None
            reply = kind(packet=answer, secret=peer.secret, dict=DICT)
            if not outbound.VerifyReply(reply, answer):
                return None
            if 80 in reply and not reply.verify_message_authenticator(original_authenticator=outbound.authenticator):
                return None
            if any(key not in SAFE_REPLIES for key in reply):
                return None
            return reply


def _unsupported(req):
    allowed = ACCT_ATTRIBUTES if req.code == packet.AccountingRequest else AUTH_ATTRIBUTES
    return (any(key not in allowed for key in req) or
            (req.code == packet.AccessRequest and (2 not in req or len(req[2]) != 1)))


# Explicit, intentionally small PAP/accounting forwarding surface. EAP, CHAP,
# MS-CHAP, VSAs and secret-dependent attributes must not cross shared secrets.
AUTH_ATTRIBUTES = {1, 2, 4, 5, 6, 30, 31, 32, 80}
ACCT_ATTRIBUTES = {1, 4, 5, 6, 8, 30, 31, 32, 40, 44, 46, 49, 80}
SAFE_REPLIES = {1, 8, 18, 24, 25, 27, 28, 79, 80}


def _reply(original, code, source=None):
    answer = original.CreateReply()
    answer.code = code
    if source is not None:
        for key, values in source.items():
            # Never relay upstream authenticators, encrypted keying material,
            # proxy state, or attributes when we are synthesizing a reject.
            if key not in SAFE_REPLIES or key == 80 or code == packet.AccessReject and source.code != code:
                continue
            answer[key] = list(values)
    return answer


def main():
    logging.basicConfig(level=logging.WARNING)
    secret = Path('/run/radiusstack-backend.secret').read_bytes().strip()
    if len(secret) < 32:
        raise ValueError('backend secret missing or too short')
    router = DownstreamRouter(SQLResolver(), RadiusPeer('127.0.0.1', 18122, 18123, secret))
    router.start()
    try:
        router.thread.join()
    finally:
        router.close()


if __name__ == '__main__':
    main()
