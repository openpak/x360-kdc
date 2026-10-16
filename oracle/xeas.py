#!/usr/bin/env python3
"""Local x360 MACS and XEAS experiment; subsequent stages are recorded only."""
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

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import kdc


def require(condition, message):
    if not condition:
        raise ValueError(message)


def decode_request(data):
    outer = kdc.parse(data)
    require(len(outer) == 1 and outer[0][0] == 0x6a, 'not AS-REQ; record only')
    fields = kdc.fields(kdc.unwrap(outer[0][1]))
    require(kdc.num(fields[1][1]) == 5 and kdc.num(fields[2][1]) == 10, 'AS-REQ version/type')
    body = kdc.fields(fields[4][1])
    name = kdc.fields(body[1][1])
    names = [value.decode('ascii') for _, value in kdc.parse(name[1][1])]
    service = kdc.fields(body[3][1])
    services = [value.decode('ascii') for _, value in kdc.parse(service[1][1])]
    padata = {}
    for _, value in kdc.parse(fields[3][1]):
        item = kdc.fields(value)
        kind = kdc.num(item[1][1])
        require(kind not in padata, 'duplicate padata')
        padata[kind] = item[2][1]
    return body[2][1].decode('ascii'), names, services, kdc.num(body[7][1]), padata


class Server:
    def __init__(self, state_path):
        self.state_path = Path(state_path)
        self.private = serialization.load_pem_private_key((kdc.ROOT / 'keys/xmacs-dev-private.pem').read_bytes(), None)
        self.ca = serialization.load_pem_public_key((kdc.ROOT / 'keys/console-ca-public.pem').read_bytes())
        self.accounts = json.loads(self.state_path.read_text()) if self.state_path.exists() else {}

    def save(self):
        pending = self.state_path.with_suffix('.pending')
        fd = os.open(pending, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'w') as output:
            json.dump(self.accounts, output, indent=2)
        pending.replace(self.state_path)

    def verify_ca(self, cert):
        require(len(cert) == 424 and cert[:2] == b'\x01\xa8', 'certificate header')
        self.ca.verify(cert[168:], cert[:168], padding.PSS(mgf=padding.MGF1(hashes.SHA1()), salt_length=10), hashes.SHA1())

    def handle(self, data):
        # Any later Kerberos message is retained by the listener but never answered.
        if kdc.parse(data)[0][0] != 0x6a:
            return None, {'event': 'record-only', 'application_tag': hex(data[0]), 'bytes': len(data)}
        realm, names, services, nonce, padata = decode_request(data)
        require(services == ['krbtgt', realm], 'unexpected AS service')
        summary = {'realm': realm, 'cname': names, 'nonce': nonce,
                   'padata': {str(kind): len(value) for kind, value in padata.items()}}
        if realm == 'MACS.XBOX.COM':
            key, _, _, _, ce, cert, timestamp = kdc.request(data, self.private, self.ca)
            cid = int.from_bytes(cert[2:7], 'big')
            account_name = '%012d@xbox.com' % (cid % 1000000000000)
            existing = self.accounts.get(account_name)
            if existing is None or existing['certificate'] != cert.hex():
                account = (struct.pack('<Q', 0x0009000000000000 | cid)
                           + account_name.split('@')[0].encode().ljust(16, b'\0')
                           + b'xbox.com'.ljust(20, b'\0')
                           + b'XBOX.COM'.ljust(24, b'\0') + os.urandom(16))
                self.accounts[account_name] = {
                    'certificate': cert.hex(), 'account': account.hex(),
                    'console_signature_verified': True, 'issued_at': time.time(),
                }
                self.save()
            else:
                require(existing.get('console_signature_verified') is True, 'account provenance')
                account = bytes.fromhex(existing['account'])
            summary.update(event='MACS verified', title=ce.decode(), console_id=cert[2:7].hex())
            return kdc.reply(key, nonce, realm, names, cert, account), summary
        if realm != 'XBOX.COM':
            return None, dict(summary, event='record-only')
        require(len(names) == 1, 'XEAS principal count')
        account = self.accounts.get(names[0])
        require(account is not None, 'unknown account: CA-backed MACS provisioning required')
        require(account.get('console_signature_verified') is True, 'unverified account provenance')
        self.verify_ca(bytes.fromhex(account['certificate']))
        key = bytes.fromhex(account['account'])[-16:]
        require(set(padata) == {216, 206, 2}, 'unexpected XEAS padata set')
        require(len(padata[216]) == 20, 'D8 length')
        ce = padata[206]
        expected = hmac.new(kdc.derive(key, 0), ce[20:], hashlib.sha1).digest()
        require(hmac.compare_digest(ce[:20], expected), 'XEAS CE checksum')
        encrypted = kdc.fields(kdc.unwrap(padata[2]))
        require(kdc.num(encrypted[0][1]) == 23, 'timestamp enctype')
        timestamp = kdc.dec(key, 1, encrypted[2][1])
        ts = kdc.fields(kdc.unwrap(timestamp))
        instant = datetime.datetime.strptime(ts[0][1].decode(), '%Y%m%d%H%M%SZ').replace(tzinfo=datetime.timezone.utc)
        require(abs(time.time() - instant.timestamp()) < 300, 'XEAS timestamp outside 5 minutes')
        summary.update(event='XEAS verified', title=ce[20:].decode(), kernel_block_sha1=padata[216].hex(),
                       timestamp=instant.isoformat())
        return kdc.reply(key, nonce, realm, names, macs=False), summary


def main():
    require(__debug__, 'run without Python optimization')
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=18088)
    parser.add_argument('--state', default=str(kdc.ROOT / 'keys/x360-dev-accounts.json'))
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    server = Server(args.state)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('127.0.0.1', args.port))
    print('listening', sock.getsockname(), flush=True)
    index = 0
    while True:
        data, address = sock.recvfrom(65535)
        (out / f'req-{index:03}.bin').write_bytes(data)
        try:
            response, detail = server.handle(data)
            if response is not None:
                (out / f'rep-{index:03}.bin').write_bytes(response)
                sock.sendto(response, address)
                detail['reply_bytes'] = len(response)
        except Exception as error:
            detail = {'event': 'REJECT', 'error': type(error).__name__, 'detail': str(error)}
        print(json.dumps(dict(detail, at=time.time(), peer=address, request_bytes=len(data))), flush=True)
        index += 1


if __name__ == '__main__':
    main()
