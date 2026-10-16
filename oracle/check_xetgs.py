#!/usr/bin/env python3
"""Synthetic fresh TGS fixture based on the recorded firmware request."""
from pathlib import Path
import time, hashlib, hmac
import kdc, xeas, xetgs

server = xetgs.Server(kdc.ROOT/'keys/x360-dev-accounts.json', kdc.ROOT/'keys/x360-ticket-key.bin')
p = kdc.ROOT/'run/logs/kdc-xeas2'
original = (p/'req-002.bin').read_bytes(); outer = kdc.fields(kdc.unwrap(kdc.unwrap(original))); body = kdc.fields(outer[4][1]); nonce=kdc.num(body[7][1])
account = next(iter(server.accounts)); session = bytes(range(16)); ticket=server.ticket('XBOX.COM',[account],['krbtgt','XBOX.COM'],session)
body_hash=hashlib.md5(kdc.tl(0x30,outer[4][1])).digest()
auth=kdc.tl(0x62,kdc.seq(kdc.cx(0,kdc.integer(5)),kdc.cx(1,kdc.st('XBOX.COM')),kdc.cx(2,kdc.princ([account])),kdc.cx(3,kdc.seq(kdc.cx(0,kdc.integer(7)),kdc.cx(1,kdc.octet(body_hash)))),kdc.cx(4,kdc.integer(0)),kdc.cx(5,xetgs.gt(time.time())),kdc.cx(7,kdc.nonce_integer(nonce))))
ap=kdc.tl(0x6e,kdc.seq(kdc.cx(0,kdc.integer(5)),kdc.cx(1,kdc.integer(14)),kdc.cx(2,kdc.tl(3,b'\0\0\0\0\0')),kdc.cx(3,ticket),kdc.cx(4,kdc.ed(kdc.enc(session,7,auth)))))
text=b'Xbox Version=2.00.17559.0 Title=0xFFFE07D1 TitleVersion=0\0';derived=kdc.derive(session,nonce);request_data=b'\x06\0'+bytes(124)
pa={1:ap,206:hmac.new(derived,text,hashlib.sha1).digest()+text,214:kdc.ed(kdc.enc(derived,1201,request_data))}
def packet(values):
 f=dict(outer);f[3]=(0x30,b''.join(kdc.pa(t,v) for t,v in values.items()));return kdc.tl(0x6c,xetgs.rebuild(f))
data=packet(pa);reply,summary=server.handle(data);assert summary['event']=='TGS verified'
r=kdc.fields(kdc.unwrap(kdc.unwrap(reply)));part=kdc.dec(session,8,kdc.fields(r[6][1])[2][1]);assert part[0]==0x7a
pd=kdc.fields(kdc.unwrap(r[2][1]));record=kdc.dec(derived,1202,kdc.fields(kdc.unwrap(pd[2][1]))[2][1]);assert len(record)==184 and record[0x24:0x28]==bytes([10,0,2,2])
print('TGS valid; ticket verified; reply usage8 and D7 usage1202 verified; reply bytes',len(reply))
for kind in [1,206,214]:
 values=dict(pa);v=bytearray(values[kind]);v[-2]^=1;values[kind]=bytes(v)
 try:server.handle(packet(values))
 except Exception:print('rejected tampered padata',kind)
 else:raise RuntimeError('tampering accepted')

old=(kdc.ROOT/'run/logs/kdc-xeas2/req-002.bin').read_bytes()
try:server.handle(old)
except Exception:print('rejected old opaque unauthenticated ticket')
else:raise RuntimeError('legacy ticket accepted')
changed=dict(outer);body_changed=kdc.fields(outer[4][1]);body_changed[7]=(2,b'\x01');changed[4]=(0x30,kdc.unwrap(xetgs.rebuild(body_changed)));changed[3]=(0x30,b''.join(kdc.pa(t,v) for t,v in pa.items()))
try:server.handle(kdc.tl(0x6c,xetgs.rebuild(changed)))
except ValueError as error:assert 'body checksum' in str(error);print('rejected modified request body')
else:raise RuntimeError('modified body accepted')
