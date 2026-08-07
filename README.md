# NetFast

[English](./README.md) | [简体中文](./README_zh.md)

A high-performance userspace TCP/IP networking stack built on AF_XDP (eXpress Data Path), designed for low-latency, high-throughput scenarios. NetFast bypasses the kernel network stack entirely for data-plane operations while providing a POSIX-compatible socket API.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Application                       │
│         (net_socket / net_connect / net_read ...)    │
├─────────────────────────────────────────────────────┤
│                  Public API (api/netfast.h)           │
│   ┌──────────┬──────────┬──────────┬──────────┐     │
│   │  Socket  │  Epoll   │  Async   │  Fcntl   │     │
│   │   API    │   API    │   API    │   API    │     │
│   └──────────┴──────────┴──────────┴──────────┘     │
├─────────────────────────────────────────────────────┤
│               Request Layer (main/req*.c)            │
│   ┌──────────────┬──────────────┬────────────────┐  │
│   │  req_socket  │  req_epoll   │   req_async    │  │
│   │  (blocking)  │  (event poll)│  (completion Q) │  │
│   └──────────────┴──────────────┴────────────────┘  │
├─────────────────────────────────────────────────────┤
│             Protocol Stack (main/)                    │
│   ┌──────────────────────────────────────────────┐  │
│   │  TCP (tcp.c)          UDP (udp.c)             │  │
│   │  ├─ Congestion Ctrl  ├─ Sendto/Recvfrom      │  │
│   │  ├─ Retransmit       ├─ Connect              │  │
│   │  ├─ Timers           └───────────────────────┘  │
│   │  └─ State Machine                               │  │
│   ├──────────────────────────────────────────────┤  │
│   │  IP (ip.c)           IPv6 (ipv6.c)            │  │
│   │  ├─ Fragmentation    ├─ Extension Headers     │  │
│   │  └─ Forwarding       └─ IPv6 Frag            │  │
│   ├──────────────────────────────────────────────┤  │
│   │  ICMP (icmp.c)        ARP/NDP (route_arp_ndp) │  │
│   ├──────────────────────────────────────────────┤  │
│   │  Socket Layer (socket.c)                      │  │
│   │  ├─ Bind/Unbind        ├─ Tuple Hash         │  │
│   │  └─ Auto-bind          └─ SO_REUSEPORT       │  │
│   ├──────────────────────────────────────────────┤  │
│   │  skbuff (skbuff.c) — Zero-copy buffer mgmt   │  │
│   ├──────────────────────────────────────────────┤  │
│   │  Loopback (loopback.c)                        │  │
│   └──────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────┤
│                 Worker Layer (main/worker.c)          │
│   ┌──────────┬──────────┬──────────┬──────────┐     │
│   │ Worker 0 │ Worker 1 │ Worker 2 │   ...    │     │
│   │ (CPU 0)  │ (CPU 1)  │ (CPU 2)  │          │     │
│   │ ┌──────┐ │ ┌──────┐ │ ┌──────┐ │          │     │
│   │ │AF_XDP│ │ │AF_XDP│ │ │AF_XDP│ │          │     │
│   │ │  XSK │ │ │  XSK │ │ │  XSK │ │          │     │
│   │ └──────┘ │ └──────┘ │ └──────┘ │          │     │
│   └──────────┴──────────┴──────────┴──────────┘     │
│         ▲                    ▲                       │
│         │  Toeplitz RSS     │                        │
│         │  select_worker_by_tuple()                  │
├─────────────────────────────────────────────────────┤
│             Base Library (lib/)                       │
│   ┌─────────┬─────────┬──────────┬──────────────┐   │
│   │  hash   │  list   │  queue   │ frame_cache  │   │
│   │ (MPMC)  │(doubly) │(lockfree)│ (UMEM mgmt)  │   │
│   ├─────────┼─────────┼──────────┼──────────────┤   │
│   │  rss    │  trie   │  thread  │    base      │   │
│   │(Toeplitz)│(radix) │ (utils)  │  (helpers)   │   │
│   └─────────┴─────────┴──────────┴──────────────┘   │
├─────────────────────────────────────────────────────┤
│              AF_XDP Data Plane (lib/xdp.c)            │
│   ┌──────────────────────────────────────────────┐  │
│   │  UMEM (XDP_UMEM_FRAME_CNT × 4KB = 256 MB)    │  │
│   │  ├─ Fill Ring (RX buffers)                    │  │
│   │  ├─ RX Ring    (incoming packets)             │  │
│   │  ├─ TX Ring    (outgoing packets)             │  │
│   │  └─ Completion Ring (TX done)                 │  │
│   └──────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────┤
│         eBPF Program (lib/xdp_redirect.bpf.c)         │
│     XDP_REDIRECT to userspace AF_XDP socket          │
└─────────────────────────────────────────────────────┘
```

## Key Design Concepts

### Multi-Worker Architecture

Each worker thread is pinned to a dedicated CPU core, owning its own AF_XDP socket (XSK). Packets are steered to the correct worker using **Toeplitz RSS hashing** on the 5-tuple `(sip, sport, dip, dport, protocol)`. This ensures all packets for a connection land on the same worker, enabling lock-free per-connection processing.

### Zero-Copy Data Path

- **UMEM-backed frame cache**: All packet buffers reside in a shared UMEM region mapped by AF_XDP, eliminating kernel-to-userspace copies.
- **skbuff (socket buffer)**: A lightweight buffer abstraction supporting scatter-gather I/O, clone-on-write, and reference counting.
- **XDP redirect**: The eBPF program `xdp_redirect.bpf.c` redirects packets directly into the userspace UMEM via `XDP_REDIRECT`.

### Lock-Free Socket Tables

- **MPMC hash tables** (`lib/hash.c`): Concurrent lock-free hash maps for socket tuple lookups.
- **Bind tables**: Track address/port bindings per protocol family (IPv4/IPv6).
- **SO_REUSEPORT**: Multiple sockets can bind the same port; RSS distributes incoming connections.

### Protocol Virtual Table

Each protocol (TCP, UDP) implements `protocol_ops` — a virtual function table with callbacks for `connect`, `bind`, `listen`, `accept`, `read`, `write`, `sendto`, `recvfrom`, `poll`, `shutdown`, etc. The socket layer dispatches through these ops, making the stack extensible.

### Async & Sync Request Model

- **Blocking (req_socket)**: Traditional blocking socket calls with timeout support.
- **Non-blocking**: `O_NONBLOCK` flag returns `EAGAIN` immediately.
- **Epoll (req_epoll)**: Full `epoll_create`/`epoll_ctl`/`epoll_wait` integration.
- **Async CQ (req_async)**: Completion-queue based async API for batch submission and completion.

### Connection Migration

When a socket's addresses change (e.g., `connect()` finalizes the 5-tuple, or `sendto()` picks a source IP for a wildcard bind), the RSS hash may map to a different worker. NetFast handles this by **migrating the socket and pending request** (`change_req_worker`) to the correct worker transparently.

## Project Structure

```
.
├── api/
│   └── netfast.h              # Public C API header
├── lib/                       # Base library
│   ├── base.c/h               # Helper utilities, time, reference counting
│   ├── frame_cache.c/h        # UMEM-backed frame allocator
│   ├── hash.c/h               # Lock-free MPMC hash table
│   ├── list.c/h               # Doubly-linked list
│   ├── log.c/h                # Logging subsystem
│   ├── queue.c/h              # Lock-free MPSC queue
│   ├── rss.c/h                # Toeplitz RSS hash & worker selection
│   ├── thread.c/h             # Thread utilities
│   ├── trie.c/h               # Radix trie (routing table)
│   ├── xdp.c/h                # AF_XDP setup, UMEM, RX/TX rings
│   └── xdp_redirect.bpf.c     # eBPF XDP redirect program
├── main/                      # Core protocol stack
│   ├── ether.c/h              # Ethernet frame handling
│   ├── fd_entry.c/h           # File descriptor management
│   ├── icmp.c/h               # ICMP error processing
│   ├── if.c/h                 # Network interface management
│   ├── init.c/h               # Stack initialization & configuration
│   ├── ip.c/h                 # IPv4 input/output/fragmentation
│   ├── ip_frag.c/h            # IPv4 fragment reassembly
│   ├── ipv6.c/h               # IPv6 input/output
│   ├── ipv6_ext.c/h           # IPv6 extension headers
│   ├── ipv6_frag.h            # IPv6 fragment reassembly
│   ├── loopback.c/h           # Loopback device
│   ├── netlink.c/h            # Netlink (route/addr monitoring)
│   ├── req.c/h                # Request infrastructure
│   ├── req_async.c/h          # Async completion queue API
│   ├── req_epoll.c/h          # Epoll integration
│   ├── req_socket.c/h         # Blocking socket request handling
│   ├── route_arp_ndp.c/h      # Route lookup, ARP, NDP
│   ├── skbuff.c/h             # Socket buffer (zero-copy, scatter-gather)
│   ├── socket.c/h             # Socket layer (bind, tuple install, auto-bind)
│   ├── stack.c/h              # Per-worker stack instance
│   ├── tcp.c/h                # TCP protocol (state machine, timers, retransmit)
│   ├── tcp_congestion.c       # TCP congestion control (Reno/CUBIC)
│   ├── tcp_metrics.c/h        # TCP metrics & RTT estimation
│   ├── udp.c/h                # UDP protocol
│   └── worker.c/h             # Worker thread & cross-worker communication
├── docs/                      # Design documentation
│   ├── tcp_sack_design.md     # TCP SACK design notes
│   └── tcp_sack_tested_diff.md
├── example/                   # Example applications
├── test/                      # Test & benchmark suite
│   ├── tcp_stream_perf.c      # TCP throughput benchmark
│   ├── bench_*.c              # Micro-benchmarks
│   └── integration_*.c        # Integration tests
├── Makefile                   # Build system
└── config.json                # Runtime configuration
```

## Build

### Prerequisites

- Linux kernel ≥ 5.4 with AF_XDP support
- `libbpf`, `libxdp`, `libelf`, `libz`, `libcjson`
- Clang (for eBPF compilation)

### Compile

```bash
# Debug build
make PROFILE=debug -j$(nproc)

# Release build
make PROFILE=release -j$(nproc)

# Release with debug info
make PROFILE=relwithdebinfo -j$(nproc)
```

Output: `build/libnetfast.so`

### Configuration

Edit `config.json` or place at `/usr/local/etc/netfast/config.json`:

```json
{
    "thread_num": 4,
    "ifs": [
        { "name": "eth0", "queues": 4 }
    ],
    "logfile": "/var/log/netfast.log",
    "ipv4_forward": false,
    "ipv6_forward": false
}
```

## Quick Start

```c
#include <netfast.h>

int main() {
    // Create a TCP socket
    int fd = net_socket(AF_INET, SOCK_STREAM, 0);

    // Connect to remote
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(8080)
    };
    inet_pton(AF_INET, "192.168.1.1", &addr.sin_addr);
    net_connect(fd, (struct sockaddr*)&addr, sizeof(addr));

    // Send data
    net_write(fd, "hello", 5);

    // Receive response
    char buf[1024];
    int n = net_read(fd, buf, sizeof(buf));

    net_close(fd);
    return 0;
}
```

## Features

- **TCP**: Full state machine (RFC 793), retransmission with exponential backoff, keepalive, delayed ACK, Nagle, window scaling, timestamps (PAWS), SACK, congestion control (Reno/CUBIC), FIN-WAIT-2/TIME-WAIT timeouts
- **UDP**: Connectionless datagrams, `sendto`/`recvfrom`, implicit connect
- **IPv4/IPv6**: Fragmentation/reassembly, extension headers, ICMP error processing
- **ARP/NDP**: Address resolution and neighbor discovery
- **Socket options**: `SO_REUSEADDR`, `SO_REUSEPORT`, `SO_KEEPALIVE`, `SO_RCVBUF`, `SO_SNDBUF`, `SO_RCVTIMEO`, `SO_SNDTIMEO`, `TCP_NODELAY`, `TCP_CORK`, `TCP_QUICKACK`
- **Epoll**: Level-triggered `EPOLLIN`/`EPOLLOUT`/`EPOLLERR`/`EPOLLHUP`/`EPOLLRDHUP`
- **Non-blocking I/O**: `O_NONBLOCK` via `net_fcntl`
- **Async API**: Completion-queue based with batch submit/completion
- **Loopback**: Direct intra-stack delivery without hitting AF_XDP
- **Netlink**: Route and address monitoring for dynamic configuration
