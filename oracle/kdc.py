#!/usr/bin/env python3
"""Local x360 MACS protocol experiment; trusts only the configured dev CA."""
import argparse, hashlib, hmac, json, os, socket, struct, time
from pathlib import Path
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
ROOT=Path(__file__).resolve().parents[1]
def hm(k,b):return hmac.new(k,b,hashlib.md5).digest()
def rc4(k,b):
 s=list(range(256));j=0
 for i in range(256):
  j=(j+s[i]+k[i%len(k)])%256;s[i],s[j]=s[j],s[i]
 i=j=0;o=bytearray()
 for x in b:
  i=(i+1)%256;j=(j+s[i])%256;s[i],s[j]=s[j],s[i];o.append(x^s[(s[i]+s[j])%256])
 return bytes(o)
def enc(k,u,b):
 k=hm(k,struct.pack('<I',u));p=os.urandom(8)+b;c=hm(k,p);return c+rc4(hm(k,c),p)
def dec(k,u,b):
 k=hm(k,struct.pack('<I',u));p=rc4(hm(k,b[:16]),b[16:]);assert hmac.compare_digest(hm(k,p),b[:16]),'RC4 checksum';return p[8:]
def tl(t,b):return bytes([t])+ (bytes([len(b)]) if len(b)<128 else bytes([0x80+(len(b).bit_length()+7)//8])+len(b).to_bytes((len(b).bit_length()+7)//8,'big'))+b
def seq(*b):return tl(0x30,b''.join(b))
def cx(n,b):return tl(0xa0+n,b)
def integer(n):return tl(2,n.to_bytes(max(1,(n.bit_length()+8)//8),'big'))
def nonce_integer(n):
 b=struct.pack('>I',n)
 while len(b)>1 and b[0]==(255 if b[1]&128 else 0):b=b[1:]
 return tl(2,b)
def st(s):return tl(27,s.encode())
def octet(b):return tl(4,b)
def parse(b):
 out=[];i=0
 while i<len(b):
  t=b[i];n=b[i+1];i+=2
  if n&128:
   z=n&127;n=int.from_bytes(b[i:i+z],'big');i+=z
  assert i+n<=len(b),'DER length';out.append((t,b[i:i+n]));i+=n
 return out
def fields(b):return {t-0xa0:parse(v)[0] for t,v in parse(b)}
def unwrap(b):return parse(b)[0][1]
def num(v):return int.from_bytes(v,'big')
def princ(parts):return seq(cx(0,integer(2)),cx(1,seq(*(st(p) for p in parts))))
def ed(b):return seq(cx(0,integer(23)),cx(2,octet(b)))
def pa(t,b):return seq(cx(1,integer(t)),cx(2,octet(b)))
def derive(k,n):return hm(hm(k,b'signaturekey\0'),hashlib.md5(bytes.fromhex('02040000')+struct.pack('<I',n)).digest())
def request(d,priv,ca):
 f=fields(unwrap(unwrap(d)));p={}
 for _,v in parse(f[3][1]):
  q=fields(v);p[num(q[1][1])]=q[2][1]
 b=p[219];assert len(b)==828
 secret=priv.decrypt(b[:256][::-1],padding.OAEP(mgf=padding.MGF1(hashes.SHA1()),algorithm=hashes.SHA1(),label=None));assert len(secret)==16
 cert=b[404:];assert len(cert)==424 and cert[:2]==b'\x01\xa8','certificate header'
 ca.verify(cert[168:],cert[:168],padding.PSS(mgf=padding.MGF1(hashes.SHA1()),salt_length=10),hashes.SHA1())
 pub=rsa.RSAPublicNumbers(num(cert[36:40]),num(cert[40:168])).public_key()
 digest=hashlib.sha1(b[256:276]+hashlib.sha1(secret).digest()).digest()
 pub.verify(b[276:404],digest,padding.PKCS1v15(),utils.Prehashed(hashes.SHA1()))
 body=fields(f[4][1]);nonce=num(body[7][1]);realm=body[2][1].decode();assert realm=='MACS.XBOX.COM','record-only: subsequent realm';name=fields(body[1][1]);names=[v.decode() for _,v in parse(name[1][1])]
 cid=int.from_bytes(cert[2:7],'big')%1000000000000
 assert names==['XE.%012d'%cid], 'console id/cname mismatch'
 ce=p[206];assert hmac.compare_digest(ce[:20],hmac.new(derive(secret,0),ce[20:],hashlib.sha1).digest()),'CE checksum'
 ts=fields(unwrap(p[2]));timestamp=dec(secret,1,ts[2][1])
 return secret,nonce,realm,names,ce[20:],cert,timestamp
def reply(k,n,realm,names,cert=None,account=None,macs=True):
 now=time.strftime('%Y%m%d%H%M%SZ',time.gmtime());end=time.strftime('%Y%m%d%H%M%SZ',time.gmtime(time.time()+3600))
 gt=lambda s:tl(24,s.encode())
 service=princ(['krbtgt',realm]);session=os.urandom(16)
 ticket=tl(0x61,seq(cx(0,integer(5)),cx(1,st(realm)),cx(2,service),cx(3,ed(os.urandom(32)))))
 part=tl(0x79,seq(cx(0,seq(cx(0,integer(23)),cx(1,octet(session)))),cx(1,seq(seq(cx(0,integer(0)),cx(1,gt(now))))),cx(2,nonce_integer(n)),cx(4,tl(3,b'\0\0\0\0\0')),cx(5,gt(now)),cx(6,gt(now)),cx(7,gt(end)),cx(9,st(realm)),cx(10,service)))
 account_realm=realm.removeprefix('MACS.')
 if macs and account is None:
  account=struct.pack('<Q',0x0009000000000000|int.from_bytes(cert[2:7],'big'))+names[0][3:].encode().ljust(16,b'\0')+account_realm.lower().encode().ljust(20,b'\0')+account_realm.encode().ljust(24,b'\0')+os.urandom(16)
 pdata=cx(2,seq(pa(203,ed(enc(derive(k,n),1203,account))))) if macs else b''
 return tl(0x6b,seq(cx(0,integer(5)),cx(1,integer(11)),pdata,cx(3,st(realm)),cx(4,princ(names)),cx(5,ticket),cx(6,ed(enc(k,8,part)))))
def main():
 a=argparse.ArgumentParser();a.add_argument('--capture');a.add_argument('--port',type=int,default=18088);a.add_argument('--out',default=str(ROOT/'run/logs/kdc-asrep'));args=a.parse_args()
 priv=serialization.load_pem_private_key((ROOT/'keys/xmacs-dev-private.pem').read_bytes(),None);ca=serialization.load_pem_public_key((ROOT/'keys/console-ca-public.pem').read_bytes());out=Path(args.out);out.mkdir(parents=True,exist_ok=True)
 def handle(d):
  outer=fields(unwrap(unwrap(d)));body=fields(outer[4][1]);realm=body[2][1].decode()
  if realm!='MACS.XBOX.COM':
   print(json.dumps(dict(event='record-only',realm=realm,nonce=num(body[7][1]),bytes=len(d))),flush=True);return None
  k,n,r,names,ce,c,ts=request(d,priv,ca);print(json.dumps(dict(event='verified',nonce=n,realm=r,cname=names,title=ce.decode(),console_id=c[2:7].hex(),timestamp=ts.hex())),flush=True);return reply(k,n,r,names,c)
 if args.capture:handle(Path(args.capture).read_bytes());return
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',args.port));i=0;print('listening',s.getsockname(),flush=True)
 while True:
  d,addr=s.recvfrom(65535);(out/f'req-{i:03}.bin').write_bytes(d);print(time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'RX',addr,len(d),flush=True)
  try:
   b=handle(d)
   if b is not None:
    (out/f'rep-{i:03}.bin').write_bytes(b);s.sendto(b,addr);print('AS-REP',addr,len(b),flush=True)
  except Exception as e:print('REJECT',addr,type(e).__name__,str(e),flush=True)
  i+=1
if __name__=='__main__':main()
