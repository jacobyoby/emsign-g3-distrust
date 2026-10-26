#!/usr/bin/env python3
"""Record a real TLS 1.2 handshake with a public host as a pcap fixture, without root.

openssl s_client talks to a local relay; the relay forwards bytes to the real host and
logs every chunk. The chunks are then written as one TCP session (synthetic Ethernet/IP/TCP
headers with valid checksums) between a documentation-range client (192.0.2.10) and the
server's real address. Payload bytes are exactly what the server sent; nothing is signed
or minted here.

Usage: record_handshake_fixture.py HOST OUT.pcap
"""
import argparse
import socket
import struct
import subprocess
import threading
import time
from dataclasses import dataclass

CLIENT_IP = "192.0.2.10"
CLIENT_PORT = 50000
SERVER_PORT = 443
MSS = 1460


@dataclass(frozen=True)
class Chunk:
    ts: float
    from_client: bool
    data: bytes


def pump(src: socket.socket, dst: socket.socket, from_client: bool, log: list[Chunk], lock: threading.Lock) -> None:
    while True:
        data = src.recv(65536)
        if not data:
            dst.shutdown(socket.SHUT_WR)
            return
        with lock:
            log.append(Chunk(time.time(), from_client, data))
        dst.sendall(data)


def relay_handshake(host: str, server_ip: str) -> list[Chunk]:
    listener = socket.create_server(("127.0.0.1", 0))
    lport = listener.getsockname()[1]
    client = subprocess.Popen(
        ["openssl", "s_client", "-tls1_2", "-servername", host, "-connect", f"127.0.0.1:{lport}"],
        stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    local, _ = listener.accept()
    upstream = socket.create_connection((server_ip, SERVER_PORT), timeout=20)
    log: list[Chunk] = []
    lock = threading.Lock()
    threads = [
        threading.Thread(target=pump, args=(local, upstream, True, log, lock)),
        threading.Thread(target=pump, args=(upstream, local, False, log, lock)),
    ]
    for t in threads:
        t.start()
    time.sleep(3)  # handshake completes well inside this window
    client.communicate(input=b"Q\n", timeout=20)
    for t in threads:
        t.join(timeout=20)
    if client.returncode != 0:
        raise RuntimeError(f"openssl s_client to {host} via relay exited {client.returncode}")
    if not any(not c.from_client for c in log):
        raise RuntimeError(f"no bytes received from {host} ({server_ip}:{SERVER_PORT})")
    return log


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def frame(src: str, dst: str, sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes) -> bytes:
    s, d = socket.inet_aton(src), socket.inet_aton(dst)
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
    pseudo = s + d + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0x4000, 64, 6, 0, s, d)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    eth = b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + b"\x08\x00"
    return eth + ip + tcp


def tcp_session(log: list[Chunk], server_ip: str) -> list[tuple[float, bytes]]:
    syn, fin, ack, psh = 0x02, 0x01, 0x10, 0x08
    cseq, sseq = 1000, 5000
    t0 = log[0].ts - 0.002
    c2s = (CLIENT_IP, server_ip, CLIENT_PORT, SERVER_PORT)
    s2c = (server_ip, CLIENT_IP, SERVER_PORT, CLIENT_PORT)
    pkts = [
        (t0, frame(*c2s, cseq, 0, syn, b"")),
        (t0 + 0.001, frame(*s2c, sseq, cseq + 1, syn | ack, b"")),
        (t0 + 0.0015, frame(*c2s, cseq + 1, sseq + 1, ack, b"")),
    ]
    cseq, sseq = cseq + 1, sseq + 1
    for c in log:
        for off in range(0, len(c.data), MSS):
            seg = c.data[off:off + MSS]
            if c.from_client:
                pkts.append((c.ts, frame(*c2s, cseq, sseq, psh | ack, seg)))
                cseq += len(seg)
            else:
                pkts.append((c.ts, frame(*s2c, sseq, cseq, psh | ack, seg)))
                sseq += len(seg)
    tend = log[-1].ts + 0.001
    pkts += [
        (tend, frame(*c2s, cseq, sseq, fin | ack, b"")),
        (tend + 0.001, frame(*s2c, sseq, cseq + 1, fin | ack, b"")),
        (tend + 0.002, frame(*c2s, cseq + 1, sseq + 1, ack, b"")),
    ]
    return pkts


def write_pcap(path: str, pkts: list[tuple[float, bytes]]) -> None:
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, data in pkts:
            f.write(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(data), len(data)))
            f.write(data)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("host")
    ap.add_argument("out")
    args = ap.parse_args()
    server_ip = socket.gethostbyname(args.host)
    log = relay_handshake(args.host, server_ip)
    pkts = tcp_session(log, server_ip)
    write_pcap(args.out, pkts)
    print(f"wrote {args.out}: {len(pkts)} packets, {server_ip}:{SERVER_PORT} ({args.host})")


if __name__ == "__main__":
    main()
