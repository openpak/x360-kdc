#!/usr/bin/env python3
"""Local authenticated security gateway and XEXDS listener."""
import argparse
import hashlib
import hmac
import json
import os
import socket
import struct
import sys
import time
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
import kdc
import sg_data_check as sdc
import xetgs
from xeas import require
sys.path.insert(0, str(kdc.ROOT))
import udpcap

P = int('FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF', 16)

def chunk(kind, data):
    return struct.pack('<HH', kind, len(data) + 4) + data

class Gateway:
    def __init__(self):
        self.kdc = xetgs.Server(kdc.ROOT / 'keys/x360-dev-accounts.json', kdc.ROOT / 'keys/x360-ticket-key.bin')
        self.connections = {}

    def handle(self, data, address):
        require(data[:4] == bytes(4), 'control framing')
        wire = data[4:]; chunks = {}; offset = 0
        while offset < len(wire):
            kind, size = struct.unpack_from('<HH', wire, offset)
            require(size >= 4 and offset + size <= len(wire), 'chunk bounds')
            require(kind not in chunks, 'duplicate chunk')
            chunks[kind] = (offset, wire[offset + 4:offset + size]); offset += size
        require(0x5802 in chunks and 0x5880 in chunks and 0x5882 in chunks, 'SG initiation chunks')
        core = chunks[0x5802][1]; public = chunks[0x5880][1]
        require(len(core) == 20 and len(public) == 96, 'SG core/DH size')
        remote = int.from_bytes(public, 'little'); require(1 < remote < P - 1, 'DH public range')
        ap = kdc.fields(kdc.unwrap(kdc.unwrap(chunks[0x5882][1])))
        require(kdc.num(ap[0][1]) == 5 and kdc.num(ap[1][1]) == 14, 'AP-REQ version/type')
        require(ap[2] == (3, b'\0\x20\0\0\0'), 'mutual authentication AP options')
        ticket = kdc.fields(kdc.unwrap(ap[3][1]))
        require(ticket[1][1] == b'XBOX.COM' and xetgs.principal(ticket[2][1]) == ['sg', 'S0'], 'SG ticket service')
        inner = kdc.fields(kdc.unwrap(kdc.unwrap(kdc.dec(self.kdc.ticket_key, 2, kdc.fields(ticket[3][1])[2][1]))))
        name = xetgs.principal(inner[3][1]); require(len(name) == 1, 'ticket identity')
        # Refresh accounts issued by the simultaneously running KDC.
        self.kdc.accounts = json.loads((kdc.ROOT / 'keys/x360-dev-accounts.json').read_text())
        account = self.kdc.accounts.get(name[0]); require(account and account.get('console_signature_verified') is True, 'CA-backed identity provenance')
        self.kdc.verify_ca(bytes.fromhex(account['certificate']))
        require(xetgs.generalized(inner[6][1]) <= time.time() <= xetgs.generalized(inner[7][1]), 'ticket validity')
        key = kdc.fields(inner[1][1])[1][1]; require(len(key) == 16, 'SG session key')
        auth = kdc.fields(kdc.unwrap(kdc.unwrap(kdc.dec(key, 11, kdc.fields(ap[4][1])[2][1]))))
        require(kdc.num(auth[0][1]) == 5, 'authenticator version')
        require(6 not in auth, 'authenticator subkey unsupported')
        require(auth[1][1] == inner[2][1] and xetgs.principal(auth[2][1]) == name, 'authenticator identity')
        require(abs(time.time() - xetgs.generalized(auth[5][1])) < 300, 'authenticator freshness')
        check = kdc.fields(auth[3][1]); require(check[0][1] == b'\xff\x7d', 'SG checksum type')
        require(hmac.compare_digest(check[1][1], hmac.new(key, wire[:chunks[0x5882][0]], hashlib.sha1).digest()), 'SG initiation HMAC')
        private = int.from_bytes(os.urandom(96), 'little')
        public_out = pow(2, private, P).to_bytes(96, 'little')
        shared = pow(remote, private, P).to_bytes(96, 'little')
        server_nonce = os.urandom(8)
        reply_core = bytearray(60)
        struct.pack_into('<H', reply_core, 2, 2)  # 3DES, accepted by81752AF8.
        reply_core[4:8] = core[4:8]
        reply_core[8:12] = b'\0\xab\xc1\x23'
        reply_core[12:20] = core[8:16]
        reply_core[20:28] = server_nonce
        reply_core[28:32] = socket.inet_aton(address[0])
        struct.pack_into('<HH', reply_core, 54, 300, 60)
        material = bytearray()
        for counter in range(5):
            block = bytes([(shared[0] + counter) & 255]) + shared[1:]
            material += hmac.new(key, block + core[8:16] + server_nonce, hashlib.sha1).digest()
        cipher = Cipher(TripleDES(bytes(material[56:80])), modes.CBC(server_nonce)).encryptor()
        reply_core[28:60] = cipher.update(bytes(reply_core[28:60])) + cipher.finalize()
        # 0x5887: challenge/record chunk XAM requires (81752E3C..): size 0x11c..0x91c, (size-4)%8==0,
        # body 3DES-CBC with the reply key, IV = server nonce. 0x11c of zeros = no XeKeysExecute, no disc read.
        record = Cipher(TripleDES(bytes(material[56:80])), modes.CBC(server_nonce)).encryptor()
        prefix = chunk(0x5803, reply_core) + chunk(0x5880, public_out) + chunk(0x5887, record.update(bytes(0x118)) + record.finalize())
        digest = hmac.new(key, prefix, hashlib.sha1).digest()
        part = kdc.tl(0x7b, kdc.seq(kdc.cx(0, kdc.tl(*auth[5])), kdc.cx(1, kdc.tl(*auth[4])),
            kdc.cx(2, kdc.seq(kdc.cx(0, kdc.tl(2, b'\xff\x7d')), kdc.cx(1, kdc.octet(digest))))))
        ap_reply = kdc.tl(0x6f, kdc.seq(kdc.cx(0, kdc.integer(5)), kdc.cx(1, kdc.integer(15)),
            kdc.cx(2, kdc.ed(kdc.enc(key, 12, part)))))
        c2s, s2c = sdc.derive(bytes(material))
        self.connections[address] = {'c2s': c2s, 's2c': s2c, 'spi': bytes(core[4:8]), 'ctr': 0}
        (Path(sys.argv[sys.argv.index('--out') + 1]) / 'session.json').write_text(json.dumps({'key': key.hex(), 'shared': shared.hex(), 'cnonce': core[8:16].hex(), 'snonce': server_nonce.hex(), 'material': bytes(material).hex()}))  # ponytail: RE probe
        return bytes(4) + prefix + chunk(0x5883, ap_reply), {'event': 'SG authenticated', 'cname': name, 'chunks': [hex(t) for t in chunks]}

    def data(self, data, address):
        """Secure-channel data datagram: SPI | 3DES-CBC body | ctr lo16 | ICV10 (XAM 8174e518 / 8174dff8)."""
        conn = self.connections.get(address); require(conn, 'data before SG authentication')
        spi, ct, ctr, icv = sdc.parse(data)
        require(hmac.compare_digest(icv, sdc.mac(conn['c2s']['hk'], spi, ctr, ct)), 'data ICV')
        d = Cipher(TripleDES(conn['c2s']['k']), modes.CBC(sdc.iv_for(conn['c2s']['seed'], ctr))).decryptor()
        plain = d.update(ct) + d.finalize()
        mtype, size = struct.unpack_from('>HH', plain, 0); size = struct.unpack_from('<H', plain, 2)[0]
        require(4 <= size <= len(plain), 'data message size')
        body = plain[4:size]
        detail = {'event': 'DATA', 'type': hex(mtype), 'ctr': ctr, 'body': body.hex()}
        if mtype == 0x0a53:
            # Challenge result; any authenticated datagram moves XAM's gateway state 5 -> 6 (8175xxxx).
            conn['ctr'] += 1
            return sdc.seal(conn['s2c'], conn['spi'], conn['ctr'], 0x0153), dict(detail, reply='0x153')
        return None, detail

def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--out', required=True); args = parser.parse_args()
    out = Path(args.out); out.mkdir(parents=True, exist_ok=True)
    server = Gateway(); sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); sock.bind(('127.0.0.1', 3074)); index = 0
    print('listening', sock.getsockname(), flush=True)
    while True:
        data, address = sock.recvfrom(65535); (out / f'req-{index:04}.bin').write_bytes(data)
        try:
            if data[:2] == b'\x01\0':
                result = udpcap.xexds_reply(data, address); require(result is not None and result[1], 'XEXDS tag')
                response, detail = result[0], {'event': 'XEXDS'}
            elif data[:4] != bytes(4):
                response, detail = server.data(data, address); detail['hex'] = data.hex()
                if response is None:
                    print(json.dumps(dict(detail, peer=address, at=time.time())), flush=True); index += 1; continue
            else:
                response, detail = server.handle(data, address)
            sock.sendto(response, address); (out / f'rep-{index:04}.bin').write_bytes(response)
            detail['reply_bytes'] = len(response)
        except Exception as error:
            detail = {'event': 'REJECT', 'error': str(error)}
        print(json.dumps(dict(detail, peer=address, at=time.time(), request_bytes=len(data))), flush=True); index += 1

if __name__ == '__main__': main()
