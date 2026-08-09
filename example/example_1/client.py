#!/usr/bin/env python3
"""Linux peer for the NetFast example_1 1 GiB TCP/UDP server test."""

import os
import socket
import sys
import time


HOST = sys.argv[1] if len(sys.argv) > 1 else "192.168.61.132"
SOURCE = sys.argv[2] if len(sys.argv) > 2 else None
TCP_PORT = 12345
UDP_PORT = 12346
TOTAL = 1 << 30
TCP_CHUNK = 64 * 1024
UDP_CHUNK = 1400
UDP_RATE_MIB = float(os.environ.get("NETFAST_UDP_RATE_MIB", "0"))


def report(label, complete, started, packets=None):
    elapsed = max(time.monotonic() - started, 0.001)
    suffix = "" if packets is None else f", {packets} packets"
    print(f"{label}: {complete} bytes in {elapsed:.2f}s "
          f"({complete / elapsed / 1024 / 1024:.1f} MiB/s{suffix})",
          flush=True)


def tcp_test():
    payload = b"\0" * TCP_CHUNK
    started = time.monotonic()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        if SOURCE:
            sock.bind((SOURCE, 0))
        sock.settimeout(20)
        sock.connect((HOST, TCP_PORT))
        sock.settimeout(30)
        remaining = TOTAL
        while remaining:
            chunk = payload if remaining >= len(payload) else payload[:remaining]
            sock.sendall(chunk)
            remaining -= len(chunk)
        sock.shutdown(socket.SHUT_WR)

        received = 0
        while received < TOTAL:
            data = sock.recv(min(TCP_CHUNK, TOTAL - received))
            if not data:
                raise RuntimeError(f"TCP echo ended at {received}/{TOTAL} bytes")
            received += len(data)
    report("TCP echo", received, started)


def udp_test():
    payload = b"\0" * UDP_CHUNK
    started = time.monotonic()
    packets = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        if SOURCE:
            sock.bind((SOURCE, 0))
        remaining = TOTAL
        while remaining:
            chunk = payload if remaining >= len(payload) else payload[:remaining]
            sent = sock.sendto(chunk, (HOST, UDP_PORT))
            if sent != len(chunk):
                raise RuntimeError(f"short UDP send: {sent}/{len(chunk)}")
            remaining -= sent
            packets += 1
            if UDP_RATE_MIB > 0:
                target_elapsed = (TOTAL - remaining) / (UDP_RATE_MIB * 1024 * 1024)
                delay = target_elapsed - (time.monotonic() - started)
                if delay > 0:
                    time.sleep(delay)
    report("UDP send", TOTAL, started, packets)


if __name__ == "__main__":
    rate = "unlimited" if UDP_RATE_MIB <= 0 else f"{UDP_RATE_MIB:g} MiB/s"
    print(f"Peer test target: {HOST}, source: {SOURCE or 'auto'}, UDP rate: {rate}",
          flush=True)
    tcp_test()
    udp_test()
    print("Peer test complete", flush=True)
