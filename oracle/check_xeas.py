#!/usr/bin/env python3
"""Exercise XEAS key provenance, encryption and rejection with local fixtures."""
import datetime
import hashlib
import hmac
from pathlib import Path
import kdc
import xeas

path = kdc.ROOT / 'keys/x360-xeas-teststate.json'
try:
    if path.exists():
        path.unlink()
    server = xeas.Server(path)
    source = kdc.ROOT / 'run/logs/kdc-asrep-final'
    response, summary = server.handle((source / 'req-000.bin').read_bytes())
    assert summary['event'] == 'MACS verified'
    original = (source / 'req-001.bin').read_bytes()
    realm, names, services, nonce, old_pa = xeas.decode_request(original)
    key = bytes.fromhex(server.accounts[names[0]]['account'])[-16:]
    outer = kdc.fields(kdc.unwrap(kdc.unwrap(original)))
    body = kdc.fields(outer[4][1])
    body[7] = (2, bytes.fromhex('b3ef5bf0'))
    request_body = kdc.seq(*(kdc.cx(i, kdc.tl(tag, value)) for i, (tag, value) in body.items()))
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d%H%M%SZ')
    ts = kdc.seq(kdc.cx(0, kdc.tl(24, timestamp.encode())), kdc.cx(1, kdc.integer(0)))
    ce = old_pa[206][20:]
    padata = {216: old_pa[216], 206: hmac.new(kdc.derive(key, 0), ce, hashlib.sha1).digest() + ce,
              2: kdc.ed(kdc.enc(key, 1, ts))}
    def packet(pa):
        return kdc.tl(0x6a, kdc.seq(kdc.cx(1, kdc.integer(5)), kdc.cx(2, kdc.integer(10)),
                                  kdc.cx(3, kdc.seq(*(kdc.pa(t, value) for t, value in pa.items()))),
                                  kdc.cx(4, request_body)))
    data = packet(padata)
    response, summary = server.handle(data)
    assert summary['event'] == 'XEAS verified'
    fields = kdc.fields(kdc.unwrap(kdc.unwrap(response)))
    assert 2 not in fields, 'XEAS must not reissue MACS account record'
    plaintext = kdc.dec(key, 8, kdc.fields(fields[6][1])[2][1])
    assert kdc.parse(plaintext)[0][0] == 0x79
    part = kdc.fields(kdc.unwrap(kdc.unwrap(plaintext)))
    assert part[2][1] == bytes.fromhex('b3ef5bf0'), 'signed nonce encoding'
    print('valid XEAS accepted; reply usage8 decrypts; CB absent')
    for kind in [206, 2]:
        altered = dict(padata)
        value = bytearray(altered[kind]); value[-2] ^= 1; altered[kind] = bytes(value)
        try:
            server.handle(packet(altered))
        except (ValueError, AssertionError):
            print('rejected tampered padata', kind)
        else:
            raise RuntimeError('tampered request accepted')
    saved = server.accounts
    server.accounts = {}
    try:
        server.handle(data)
    except ValueError:
        print('rejected unknown account')
    else:
        raise RuntimeError('unknown account accepted')
    server.accounts = saved
    saved[names[0]]['console_signature_verified'] = False
    try:
        server.handle(data)
    except ValueError:
        print('rejected account lacking verified console signature provenance')
    else:
        raise RuntimeError('unsigned account accepted')
finally:
    if path.exists():
        path.unlink()
