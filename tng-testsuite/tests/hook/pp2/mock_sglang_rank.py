#!/usr/bin/env python3
"""Mock sglang pp2 rank for TNG hook-mode integration tests.

Replicates the bind()/connect() pattern sglang uses on the captured PP staging
ports (31000-31015) and TCPStore rendezvous port (32000), plus length-prefixed
data exchange, with no GPU/model dependency. Run under `tng exec` so
libtng_hook.so intercepts bind()/connect() and routes them through the
rats-tls tunnel.

Exit codes: 0 = all assertions passed; 2 = assertion failure; 1 = usage/runtime.
"""
import argparse
import hashlib
import socket
import struct
import sys
import threading
import time

DEFAULT_STAGING_BASE = 31000
DEFAULT_STAGING_END = 31005
STORE_PORT = 32000
PLAIN_PORT = 31010  # outside the captured range; proves no over-capture


def recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def send_frame(sock, payload):
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def recv_frame(sock):
    hdr = recv_exact(sock, 4)
    if hdr is None:
        return None
    (n,) = struct.unpack(">I", hdr)
    if n == 0:
        return b""
    return recv_exact(sock, n)


def make_payload(conn_id, size):
    body = bytes(((conn_id + i) & 0xFF) for i in range(max(0, size - 36)))
    digest = hashlib.sha256(struct.pack(">I", conn_id) + body).digest()
    return struct.pack(">I", conn_id) + digest + body


def verify_payload(payload, conn_id, size):
    if payload is None or len(payload) != size:
        return False
    (got_id,) = struct.unpack(">I", payload[:4])
    if got_id != conn_id:
        return False
    body = payload[36:]
    return hashlib.sha256(payload[:4] + body).digest() == payload[4:36]


def bind_echo(port, stop):
    """Bind 0.0.0.0:port, accept connections, echo each framed payload back."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(128)
    s.settimeout(0.5)
    threading.Thread(target=_accept_loop, args=(s, port, stop), daemon=True).start()
    return s


def _accept_loop(srv, port, stop):
    while not stop.is_set():
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        threading.Thread(target=_echo_loop, args=(conn,), daemon=True).start()


def _echo_loop(conn):
    try:
        while True:
            payload = recv_frame(conn)
            if payload is None:
                return
            send_frame(conn, payload)
    except OSError:
        pass
    finally:
        conn.close()


def connect_one(peer_ip, port, payload_size, timeout=10.0, conn_id=0):
    """Connect, send one framed payload, recv echo, verify. Returns (ok, err)."""
    try:
        c = socket.create_connection((peer_ip, port), timeout=timeout)
    except OSError as e:
        return False, f"connect {peer_ip}:{port} failed: {e}"
    try:
        payload = make_payload(conn_id, payload_size)
        send_frame(c, payload)
        got = recv_frame(c)
        ok = verify_payload(got, conn_id, payload_size)
        return ok, None if ok else f"verify failed on {peer_ip}:{port}"
    except OSError as e:
        return False, f"exchange {peer_ip}:{port} failed: {e}"
    finally:
        c.close()


def staging_ports(base, end):
    return list(range(base, end + 1))


def cmd_serve(args):
    """Bind staging range (+store if --store-server) (+plain), echo; connect to
    peer staging (+plain) (+store if --connect-store), exchange+verify; then
    --hold <sec> (sleep+exit 0) or block forever. --wait <sec> = retry window."""
    stop = threading.Event()
    ports = staging_ports(args.staging_base, args.staging_end)
    bound = [bind_echo(p, stop) for p in ports]
    if args.store_server:
        bind_echo(args.store_port, stop)
    if args.plain_port:
        bind_echo(args.plain_port, stop)
    # Give the peer's hook listeners a moment to come up.
    deadline = time.monotonic() + args.wait
    failures = []
    # Connect to peer staging ports (bidirectional exchange).
    for p in ports:
        ok = False
        while time.monotonic() < deadline:
            ok, _ = connect_one(args.peer_ip, p, args.payload_size,
                                timeout=2.0, conn_id=(p * 1000 + 1) & 0xFFFFFFFF)
            if ok:
                break
            time.sleep(0.3)
        if not ok:
            failures.append(f"staging {p}")
    # Out-of-range plain port: must be reachable directly (NOT captured).
    if args.plain_port:
        ok, _ = connect_one(args.peer_ip, args.plain_port, args.payload_size,
                            timeout=2.0, conn_id=(args.plain_port * 1000) & 0xFFFFFFFF)
        if not ok:
            failures.append(f"plain {args.plain_port} (over-capture?)")
    # Optional rendezvous connect to peer store.
    if args.connect_store:
        ok, _ = connect_one(args.peer_ip, args.store_port, args.payload_size,
                            timeout=2.0, conn_id=(args.store_port * 1000) & 0xFFFFFFFF)
        if not ok:
            failures.append(f"store {args.store_port}")
    if failures:
        print(f"FAIL: {', '.join(failures)}", flush=True)
        return 2
    print(f"OK: serve rank exchange done (peer={args.peer_ip})", flush=True)
    if args.hold is not None:
        time.sleep(args.hold)
        return 0
    # Block until killed (server side, stop_after_exit=false).
    while not stop.is_set():
        time.sleep(3600)
    return 0


def cmd_connect_once(args):
    """Single connect+exchange to peer:port. --expect-fail asserts the connect
    fails within --timeout (race window); otherwise asserts success."""
    if args.expect_fail:
        try:
            socket.create_connection((args.peer_ip, args.port), timeout=args.timeout)
            print(f"FAIL: connect {args.peer_ip}:{args.port} unexpectedly succeeded", flush=True)
            return 2
        except OSError:
            print(f"OK: connect {args.peer_ip}:{args.port} failed cleanly (race window)", flush=True)
            return 0
    ok, err = connect_one(args.peer_ip, args.port, args.payload_size,
                           timeout=args.timeout, conn_id=args.port)
    if not ok:
        print(f"FAIL: {err}", flush=True)
        return 2
    print(f"OK: connect-once {args.peer_ip}:{args.port}", flush=True)
    return 0


def cmd_bench(args):
    """rank0: bind+echo staging range, block. rank1: open --concurrency conns
    per port, stream --payload-size frames for --duration sec, verify, print
    throughput/latency, exit 0."""
    ports = staging_ports(args.staging_base, args.staging_end)
    if args.rank == 0:
        stop = threading.Event()
        for p in ports:
            bind_echo(p, stop)
        print("OK: bench server bound", flush=True)
        while not stop.is_set():
            time.sleep(3600)
        return 0
    # rank1: client
    deadline = time.monotonic() + args.duration
    conns = []
    for p in ports:
        for _ in range(args.concurrency):
            try:
                c = socket.create_connection((args.peer_ip, p), timeout=10.0)
                c.settimeout(2.0)
                conns.append((p, c))
            except OSError as e:
                print(f"FAIL: connect {p}: {e}", flush=True)
                return 2
    sent = 0
    failures = []
    idx = 0
    start = time.monotonic()
    while time.monotonic() < deadline:
        for i, (p, c) in enumerate(conns):
            conn_id = (p * 1000 + i + idx) & 0xFFFFFFFF
            payload = make_payload(conn_id, args.payload_size)
            try:
                send_frame(c, payload)
                got = recv_frame(c)
                if not verify_payload(got, conn_id, args.payload_size):
                    failures.append(f"verify {p}#{i}")
            except OSError as e:
                failures.append(f"exchange {p}#{i}: {e}")
            sent += 1
            if time.monotonic() >= deadline:
                break
        idx += 1
    elapsed = time.monotonic() - start
    mb = sent * args.payload_size / (1024 * 1024)
    for _, c in conns:
        c.close()
    if failures:
        print(f"FAIL: {len(failures)} failures e.g. {failures[:3]}", flush=True)
        return 2
    print(f"OK: bench sent={sent} frames {mb:.1f}MB in {elapsed:.2f}s "
          f"throughput={mb/elapsed:.1f}MB/s payload={args.payload_size}B", flush=True)
    return 0


def main():
    # NOTE: do not use add_subparsers(required=True) — that kwarg is Python 3.7+
    # and the test runtime may be 3.6. Check dest manually instead.
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd")
    sp = sub.add_parser("serve")
    sp.add_argument("--rank", type=int, required=True)
    sp.add_argument("--peer-ip", required=True)
    sp.add_argument("--staging-base", type=int, default=DEFAULT_STAGING_BASE)
    sp.add_argument("--staging-end", type=int, default=DEFAULT_STAGING_END)
    sp.add_argument("--store-port", type=int, default=STORE_PORT)
    sp.add_argument("--store-server", action="store_true")
    sp.add_argument("--connect-store", action="store_true")
    sp.add_argument("--plain-port", type=int, default=PLAIN_PORT)
    sp.add_argument("--payload-size", type=int, default=256)
    sp.add_argument("--wait", type=float, default=30.0)
    sp.add_argument("--hold", type=float, default=None)
    sp.set_defaults(func=cmd_serve)
    cp = sub.add_parser("connect-once")
    cp.add_argument("--peer-ip", required=True)
    cp.add_argument("--port", type=int, required=True)
    cp.add_argument("--payload-size", type=int, default=256)
    cp.add_argument("--timeout", type=float, default=10.0)
    cp.add_argument("--expect-fail", action="store_true")
    cp.set_defaults(func=cmd_connect_once)
    bp = sub.add_parser("bench")
    bp.add_argument("--rank", type=int, required=True)
    bp.add_argument("--peer-ip", required=True)
    bp.add_argument("--staging-base", type=int, default=DEFAULT_STAGING_BASE)
    bp.add_argument("--staging-end", type=int, default=DEFAULT_STAGING_END)
    bp.add_argument("--payload-size", type=int, default=1_048_576)
    bp.add_argument("--concurrency", type=int, default=4)
    bp.add_argument("--duration", type=float, default=10.0)
    bp.set_defaults(func=cmd_bench)
    args = p.parse_args()
    if not args.cmd:
        p.error("a subcommand (serve|connect-once|bench) is required")
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
