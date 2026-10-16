#!/usr/bin/env python3
"""Verify XAM secure-channel data packet layout against session.json (sg3)."""
import hmac, hashlib, json, struct, sys, itertools
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES

def derive(material, client=True):
    m = material
    a = dict(hk=m[0:16], k=m[16:40], seed=m[80:88])     # param_7 != 0: entry+0x88/0x98/0xb0
    b = dict(hk=m[40:56], k=m[56:80], seed=m[88:96])    # entry+0x58/0x68/0x80
    return (a, b) if client else (b, a)                  # (client->server, server->client)

def iv_for(seed, counter):   # FUN_8174b540
    x = int.from_bytes(seed[0:4], 'little') * counter
    y = int.from_bytes(seed[4:8], 'little') * counter
    lo = lambda v: v & 0xffffffff
    hi = lambda v: (v >> 32) & 0xffffffff
    return struct.pack('<II', hi(y) ^ lo(x), lo(y) ^ hi(x))

def mac(hk, spi, counter, ct):
    trailer = struct.pack('<HH', counter & 0xffff, counter >> 16) + spi
    return hmac.new(hk, trailer + ct, hashlib.sha1).digest()[:10]

def seal(d, spi, counter, mtype, body=b''):
    """Build one data datagram: SPI | 3DES-CBC(type BE16, len LE16, body, zero pad to 8) | ctr lo16 LE | ICV10."""
    pt = struct.pack('>H', mtype) + struct.pack('<H', len(body) + 4) + body
    pt += bytes(-len(pt) % 8)
    e = Cipher(TripleDES(d['k']), modes.CBC(iv_for(d['seed'], counter))).encryptor()
    ct = e.update(pt) + e.finalize()
    return spi + ct + struct.pack('<H', counter & 0xffff) + mac(d['hk'], spi, counter, ct)

def parse(pkt):
    return pkt[:4], pkt[4:-12], struct.unpack_from('<H', pkt, len(pkt) - 12)[0], pkt[-10:]

def check(pkt, s):
    mat = bytes.fromhex(s['material'])
    spi, ct, ctr, icv = parse(pkt)
    for name, d in zip(('c2s', 's2c'), derive(mat)):
        for spi_v in (spi, bytes([spi[0] & 0x7f]) + spi[1:]):
            got = mac(d['hk'], spi_v, ctr, ct)
            ok = got == icv
            print(name, spi_v.hex(), 'ctr', ctr, 'icv', 'OK' if ok else 'no', got.hex())
            if ok and ct:
                pt = Cipher(TripleDES(d['k']), modes.CBC(iv_for(d['seed'], ctr))).decryptor()
                print('  plaintext', (pt.update(ct) + pt.finalize()).hex())

if __name__ == '__main__':
    s = json.load(open(sys.argv[1]))
    for h in sys.argv[2:]:
        print(h); check(bytes.fromhex(h), s)
    # self-test: re-seal packet 1 with the verified client keys
    c2s = derive(bytes.fromhex(s['material']))[0]
    assert seal(c2s, bytes.fromhex('80abc123'), 1, 0x0153).hex() == '80abc1236d6453dc3f1f7e4e0100b194e7a2f6e5caf9bfaa'
    assert seal(c2s, bytes.fromhex('00abc123'), 2, 0x0053, bytes(4)).hex() == '00abc123bce342ce0c3278f202003346c74f58a218353466'
    print('seal() reproduces both packets')
