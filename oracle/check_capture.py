#!/usr/bin/env python3
"""Verify retained request and reject tampering; --repair-signature is offline only."""
import argparse
from pathlib import Path
import kdc
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
p=argparse.ArgumentParser();p.add_argument('capture');p.add_argument('--repair-signature',action='store_true');a=p.parse_args()
d=Path(a.capture).read_bytes();priv=serialization.load_pem_private_key((kdc.ROOT/'keys/xmacs-dev-private.pem').read_bytes(),None);ca=serialization.load_pem_public_key((kdc.ROOT/'keys/console-ca-public.pem').read_bytes())
f=kdc.fields(kdc.unwrap(kdc.unwrap(d)));pa={}
for _,v in kdc.parse(f[3][1]):
 q=kdc.fields(v);pa[kdc.num(q[1][1])]=q[2][1]
b=pa[219]
if a.repair_signature:
 from cryptography.hazmat.primitives import hashes
 from cryptography.hazmat.primitives.asymmetric import padding
 key=priv.decrypt(b[:256][::-1],padding.OAEP(mgf=padding.MGF1(hashes.SHA1()),algorithm=hashes.SHA1(),label=None))
 ident=dict(l.split('=',1) for l in (kdc.ROOT/'edge/build/bin/Linux/Release/wharf-console/identity.txt').read_text().splitlines() if '=' in l)
 digest=kdc.hashlib.sha1(b[256:276]+kdc.hashlib.sha1(key).digest()).digest();tail=bytes.fromhex('3021300906052b0e03021a05000414')+digest
 em=b'\0\1'+b'\xff'*(128-3-len(tail))+b'\0'+tail
 sig=pow(int.from_bytes(em,'big'),int(ident['d'],16),int(ident['n'],16)).to_bytes(128,'big');replacement=b[:276]+sig+b[404:];d=d.replace(b,replacement);b=replacement
result=kdc.request(d,priv,ca);print('valid request accepted',result[1:5])
for label,offset in [('RSA',0),('serial',264),('console signature',276),('certificate body',406),('CA signature',572)]:
 damaged=bytearray(b);damaged[offset]^=1
 try:kdc.request(d.replace(b,bytes(damaged)),priv,ca)
 except (AssertionError,InvalidSignature,ValueError):print('rejected',label)
 else:raise RuntimeError('accepted '+label)
other=kdc.rsa.generate_private_key(public_exponent=65537,key_size=2048).public_key()
try:kdc.request(d,priv,other)
except InvalidSignature:print('rejected untrusted CA')
else:raise RuntimeError('untrusted CA accepted')
rep=kdc.reply(result[0],result[1],result[2],result[3],result[5]);r=kdc.fields(kdc.unwrap(kdc.unwrap(rep)));part=kdc.dec(result[0],8,kdc.fields(r[6][1])[2][1]);assert kdc.parse(part)[0][0]==0x79
print('AS-REP crypto roundtrip',len(rep))
