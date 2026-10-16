#!/usr/bin/env python3
"""Local x360 KDC experiment with authenticated TGTs and sg/S0 replies."""
import argparse
import datetime
import hashlib
import hmac
import json
import os
import socket
import struct
import time
from pathlib import Path
import kdc
import xeas
from xeas import require


def principal(value):
    f = kdc.fields(value)
    return [v.decode('ascii') for _, v in kdc.parse(f[1][1])]


def generalized(value):
    return datetime.datetime.strptime(value.decode(), '%Y%m%d%H%M%SZ').replace(tzinfo=datetime.timezone.utc).timestamp()


def gt(value):
    return kdc.tl(24, time.strftime('%Y%m%d%H%M%SZ', time.gmtime(value)).encode())


def rebuild(fields):
    return kdc.seq(*(kdc.cx(i, kdc.tl(tag, value)) for i, (tag, value) in fields.items()))


class Server(xeas.Server):
    def __init__(self, state_path, ticket_path, sg_address='10.0.2.2'):
        super().__init__(state_path)
        self.sg_address = socket.inet_aton(sg_address)
        path = Path(ticket_path)
        if not path.exists():
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as output:
                output.write(os.urandom(16))
        self.ticket_key = path.read_bytes()
        require(len(self.ticket_key) == 16, 'ticket key size')

    def ticket(self, realm, names, service, session):
        now = time.time()
        # Ticket contents are opaque to XAM. This server owns their format/key.
        plain = kdc.tl(0x63, kdc.seq(
            kdc.cx(0, kdc.tl(3, b'\0\0\0\0\0')),
            kdc.cx(1, kdc.seq(kdc.cx(0, kdc.integer(23)), kdc.cx(1, kdc.octet(session)))),
            kdc.cx(2, kdc.st(realm)), kdc.cx(3, kdc.princ(names)),
            kdc.cx(4, kdc.seq(kdc.cx(0, kdc.integer(0)), kdc.cx(1, kdc.octet(b'')))),
            kdc.cx(5, gt(now)), kdc.cx(6, gt(now)), kdc.cx(7, gt(now + 3600))))
        return kdc.tl(0x61, kdc.seq(kdc.cx(0, kdc.integer(5)), kdc.cx(1, kdc.st(realm)),
                                  kdc.cx(2, kdc.princ(service)), kdc.cx(3, kdc.ed(kdc.enc(self.ticket_key, 2, plain)))))

    def handle(self, data):
        if data[0] == 0x6a:
            response, detail = super().handle(data)
            if response is not None and detail['event'] == 'XEAS verified':
                account = self.accounts[detail['cname'][0]]
                key = bytes.fromhex(account['account'])[-16:]
                outer = kdc.fields(kdc.unwrap(kdc.unwrap(response)))
                part = kdc.fields(kdc.unwrap(kdc.unwrap(kdc.dec(key, 8, kdc.fields(outer[6][1])[2][1]))))
                session = kdc.fields(part[0][1])[1][1]
                ticket = self.ticket(detail['realm'], detail['cname'], ['krbtgt', detail['realm']], session)
                outer[5] = (0x61, kdc.unwrap(ticket))
                response = kdc.tl(0x6b, rebuild(outer))
                detail['authenticated_ticket'] = True
            return response, detail
        if data[0] != 0x6c:
            return None, {'event': 'record-only', 'tag': hex(data[0])}
        f = kdc.fields(kdc.unwrap(kdc.unwrap(data)))
        require(kdc.num(f[1][1]) == 5 and kdc.num(f[2][1]) == 12, 'TGS version/type')
        body = kdc.fields(f[4][1]); realm = body[2][1].decode(); service = principal(body[3][1])
        require(realm == 'XBOX.COM' and service == ['sg', 'S0'], 'only sg/S0 served')
        nonce = kdc.num(body[7][1]); pa = {}
        for _, value in kdc.parse(f[3][1]):
            item = kdc.fields(value); kind = kdc.num(item[1][1])
            require(kind not in pa, 'duplicate padata'); pa[kind] = item[2][1]
        require(set(pa) == {214, 206, 1}, 'TGS padata set')
        ap = kdc.fields(kdc.unwrap(kdc.unwrap(pa[1])))
        require(kdc.num(ap[0][1]) == 5 and kdc.num(ap[1][1]) == 14, 'AP version/type')
        ticket = kdc.fields(kdc.unwrap(ap[3][1]))
        require(ticket[1][1] == b'XBOX.COM' and principal(ticket[2][1]) == ['krbtgt', 'XBOX.COM'], 'TGT service')
        inner = kdc.fields(kdc.unwrap(kdc.unwrap(kdc.dec(self.ticket_key, 2, kdc.fields(ticket[3][1])[2][1]))))
        names = principal(inner[3][1]); require(len(names) == 1, 'ticket principal count')
        account = self.accounts.get(names[0]); require(account is not None, 'unknown ticket identity')
        require(account.get('console_signature_verified') is True, 'ticket account provenance')
        self.verify_ca(bytes.fromhex(account['certificate']))
        require(inner[2][1] == b'XBOX.COM', 'ticket client realm')
        require(generalized(inner[6][1]) <= time.time() <= generalized(inner[7][1]), 'ticket validity')
        session = kdc.fields(inner[1][1])[1][1]; require(len(session) == 16, 'ticket session size')
        auth = kdc.fields(kdc.unwrap(kdc.unwrap(kdc.dec(session, 7, kdc.fields(ap[4][1])[2][1]))))
        require(auth[1][1] == inner[2][1] and principal(auth[2][1]) == names, 'authenticator identity')
        require(6 not in auth, 'authenticator subkey path not implemented')
        require(abs(time.time() - generalized(auth[5][1])) < 300, 'authenticator freshness')
        checksum = kdc.fields(auth[3][1]); require(kdc.num(checksum[0][1]) == 7, 'body checksum type')
        require(hmac.compare_digest(checksum[1][1], hashlib.md5(kdc.tl(0x30, f[4][1])).digest()), 'request body checksum')
        ce = pa[206]; derived = kdc.derive(session, nonce)
        require(hmac.compare_digest(ce[:20], hmac.new(derived, ce[20:], hashlib.sha1).digest()), 'TGS CE checksum')
        request_data = kdc.dec(derived, 1201, kdc.fields(kdc.unwrap(pa[214]))[2][1])
        require(len(request_data) == 126 and request_data[:2] == b'\x06\0', 'D6 version/length')
        require(request_data[0x26:0x46] == bytes(32), 'user TGS authentication not implemented')
        services = bytearray(b'\xff' * 32)
        # Service1 is the default selected by81735080; service20 identifies SG.
        for service_id in (1, 20, 25):  # 25 = LiveHive /liveinfo (XRL 0x1300), required after logon
            services[service_id // 4] &= ~(3 << ((service_id % 4) * 2))
        record = bytearray(184); record[0x24:0x28] = self.sg_address; record[0x5c:0x7c] = services
        record[0xb0:0xb8] = struct.pack('<Q', 1)
        session_out = os.urandom(16); now = time.time()
        ticket_out = self.ticket(realm, names, service, session_out)
        part = kdc.tl(0x7a, kdc.seq(
            kdc.cx(0, kdc.seq(kdc.cx(0, kdc.integer(23)), kdc.cx(1, kdc.octet(session_out)))),
            kdc.cx(1, kdc.seq(kdc.seq(kdc.cx(0, kdc.integer(0)), kdc.cx(1, gt(now))))),
            kdc.cx(2, kdc.nonce_integer(nonce)), kdc.cx(4, kdc.tl(3, b'\0\0\0\0\0')),
            kdc.cx(5, gt(now)), kdc.cx(6, gt(now)), kdc.cx(7, gt(now + 3600)),
            kdc.cx(9, kdc.st(realm)), kdc.cx(10, kdc.princ(service))))
        response = kdc.tl(0x6d, kdc.seq(kdc.cx(0, kdc.integer(5)), kdc.cx(1, kdc.integer(13)),
            kdc.cx(2, kdc.seq(kdc.pa(215, kdc.ed(kdc.enc(derived, 1202, record))))),
            kdc.cx(3, kdc.st(realm)), kdc.cx(4, kdc.princ(names)), kdc.cx(5, ticket_out),
            kdc.cx(6, kdc.ed(kdc.enc(session, 8, part)))))
        return response, {'event': 'TGS verified', 'cname': names, 'service': service, 'nonce': nonce,
                          'title': ce[20:].decode(), 'D6': request_data.hex(), 'SG': socket.inet_ntoa(self.sg_address)}


def main():
    require(__debug__, 'run without optimization')
    parser = argparse.ArgumentParser(); parser.add_argument('--out', required=True)
    parser.add_argument('--sg-address', default='10.0.2.2'); args = parser.parse_args()
    out = Path(args.out); out.mkdir(parents=True, exist_ok=True)
    server = Server(kdc.ROOT / 'keys/x360-dev-accounts.json', kdc.ROOT / 'keys/x360-ticket-key.bin', args.sg_address)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); sock.bind(('127.0.0.1', 18088)); index = 0
    print('listening', sock.getsockname(), flush=True)
    while True:
        data, address = sock.recvfrom(65535); (out / f'req-{index:03}.bin').write_bytes(data)
        try:
            response, detail = server.handle(data)
            if response is not None:
                (out / f'rep-{index:03}.bin').write_bytes(response); sock.sendto(response, address); detail['reply_bytes'] = len(response)
        except Exception as error:
            detail = {'event': 'REJECT', 'error': type(error).__name__, 'detail': str(error)}
        print(json.dumps(dict(detail, at=time.time(), peer=address, request_bytes=len(data))), flush=True); index += 1


if __name__ == '__main__':
    main()
