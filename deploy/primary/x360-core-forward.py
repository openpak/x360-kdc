#!/usr/bin/env python3
"""Plain TCP forwarder: ZeroTier 10.212.63.196:20001 -> 127.0.0.1:20001 (account core gRPC) for the
secondary host (x360-kdc). The account core only publishes on loopback; this avoids restarting it."""
import asyncio
async def pipe(r, w):
    try:
        while data := await r.read(65536):
            w.write(data); await w.drain()
    except Exception:
        pass
    finally:
        w.close()
async def handle(cr, cw):
    try:
        sr, sw = await asyncio.open_connection("127.0.0.1", 20001)
    except Exception:
        cw.close(); return
    await asyncio.gather(pipe(cr, sw), pipe(sr, cw))
async def main():
    server = await asyncio.start_server(handle, "10.212.63.196", 20001)
    async with server: await server.serve_forever()
asyncio.run(main())
