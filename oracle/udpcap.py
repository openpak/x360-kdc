#!/usr/bin/env python3
# udpcap.py <port> <logfile> [echo]: log every UDP datagram received on 127.0.0.1:<port> (hex + ascii);
# with "echo" it sends each datagram back unchanged (stand-in for the XEXDS MTU/echo test the dashboard runs).
# with "xexds" it answers in the layout the dashboard's own validator accepts (internal research notes, 2026-10-16 XEXDS section):
#   request: u16le type, u16le sub, u16le total_len, u16le body_len, 41/42-byte text ("...MTU Test" total 0x538, "...ICMP Test" total 200), type 3 = 32 bytes
#   reply  : 36-byte header + the request text; length must equal the request total length; for type 3 any datagram completes the step.
import socket, sys, time, struct, hmac, hashlib, os
from pathlib import Path
KEY = os.urandom(16)  # stand-in per-run key for the 8-byte tag in the reply header (a real x360-xexds owns its key)

def xexds_reply(data, addr):
    if len(data) < 8:
        return None
    typ, sub, total, body = struct.unpack('<HHHH', data[:8])
    if typ != 1:
        return None
    ip = socket.inet_aton(addr[0]); port = struct.pack('>H', addr[1])
    if sub == 3:
        # follow-up (32 bytes): [01 00][03 00][28 bytes of the type-1 reply header, echoed]; verify our tag, then any datagram completes the dash step
        hdr = data[4:32]
        want = hmac.new(KEY, hdr[:20] + ip + port, hashlib.sha1).digest()[:8]
        ok = hdr[20:28] == want
        return (struct.pack('<HHHH', 1, 4, 36, 0) + os.urandom(28) + b'\0\0')[:36], ok
    text = data[8:8 + (0x29 if total == 0x538 else 0x2a)]
    nonce = os.urandom(12)
    h = struct.pack('<HHHH', typ, sub, total, body) + nonce            # 20 bytes
    tag = hmac.new(KEY, h + ip + port, hashlib.sha1).digest()[:8]        # 8 bytes   -> reply[0x00..0x1c)
    reply = h + tag + ip + port + b'\0\0' + text                         # +4 ip, +2 port, +2 pad = 0x24; text at 0x24
    return reply.ljust(total, b'\0')[:total], True
def main():
    port, log = int(sys.argv[1]), sys.argv[2]
    mode = sys.argv[3] if len(sys.argv) > 3 else ''
    echo = mode == 'echo'
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('127.0.0.1', port))
    with open(log, 'a') as f:
        f.write('%s listening on 127.0.0.1:%d echo=%s\n' % (time.strftime('%H:%M:%S'), port, echo)); f.flush()
        while True:
            data, addr = s.recvfrom(65535)
            Path(log + '.' + str(time.time_ns()) + '.bin').write_bytes(data)
            if echo:
                s.sendto(data, addr)
            if mode == 'xexds':
                r = xexds_reply(data, addr)
                if r:
                    s.sendto(r[0], addr)
                    f.write('%s xexds reply len %d tag_ok=%s\n' % (time.strftime('%H:%M:%S'), len(r[0]), r[1]))
            f.write('%s from %s:%d len %d%s\n' % (time.strftime('%H:%M:%S'), addr[0], addr[1], len(data), ' (echoed)' if echo else ''))
            for o in range(0, min(len(data), 64), 16):
                chunk = data[o:o + 16]
                f.write('  %04x: %-48s %s\n' % (o, ' '.join('%02x' % b for b in chunk),
                                               ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)))
            f.flush()

if __name__ == '__main__':
    main()
