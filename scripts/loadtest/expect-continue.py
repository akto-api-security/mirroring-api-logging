#!/usr/bin/env python3
# expect-continue.py host port conns reqs_per_conn body_bytes idle_s tag [tls]
# Keep-alive POSTs with "Expect: 100-continue" (the client waits for the 100,
# as curl, .NET and many Java clients do), then the connection idles before closing.
import socket, ssl, sys, threading, time

host, port, conns, reqs, size, idle, tag = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5]), float(sys.argv[6]), sys.argv[7]
use_tls = len(sys.argv) > 8 and sys.argv[8] == "tls"
body = b"e" * size
stats = {"ok": 0, "continue": 0, "err": 0}
lock = threading.Lock()

def read_head(f):
    line = f.readline()
    if not line:
        raise EOFError("closed")
    status = int(line.split()[1])
    h = {}
    while True:
        l = f.readline()
        if l in (b"\r\n", b"\n", b""):
            break
        k, _, v = l.decode().partition(":")
        h[k.strip().lower()] = v.strip()
    return status, h

def read_body(f, h):
    if h.get("transfer-encoding", "").lower() == "chunked":
        while True:
            n = int(f.readline().split(b";")[0], 16)
            f.read(n + 2)
            if n == 0:
                break
    else:
        f.read(int(h.get("content-length", "0")))

def worker(w):
    try:
        s = socket.create_connection((host, port), timeout=30)
        if use_tls:
            ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s)
        f = s.makefile("rb")
        for i in range(reqs):
            rid = f"{tag}-{w}-{i}"
            s.sendall((f"POST /up HTTP/1.1\r\nHost: {host}\r\nX-Request-Id: {rid}\r\n"
                       f"Content-Length: {len(body)}\r\nExpect: 100-continue\r\n\r\n").encode())
            st, h = read_head(f)
            if st == 100:
                with lock: stats["continue"] += 1
                s.sendall(body)
                st, h = read_head(f)
            read_body(f, h)
            with lock: stats["ok"] += 1
        time.sleep(idle)
        s.close()
    except Exception as e:
        with lock: stats["err"] += 1

ts = [threading.Thread(target=worker, args=(w,)) for w in range(conns)]
[t.start() for t in ts]; [t.join() for t in ts]
print(f"sent conns={conns} reqs={conns*reqs} ok={stats['ok']} got_100={stats['continue']} errors={stats['err']}")
