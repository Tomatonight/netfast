# NetFast

[English](./README.md) | [简体中文](./README_zh.md)

NetFast is an experimental userspace TCP/IP stack built on Linux AF_XDP. It
combines a worker-owned network stack, UMEM-backed packet buffers, an epoll-like
readiness API, and a completion-queue-based asynchronous API in one C library.

The asynchronous API is the primary high-throughput interface: applications can
submit many socket operations in one batch, keep multiple requests in flight,
and consume completions in batches without running one blocking call per
operation.

> NetFast is under active development. Use it on dedicated test interfaces
> before considering production deployment.

## Highlights

- **Asynchronous completion queues** with single and batch submission.
- **Batched completion waits** with `min_complete`, `max_complete`, and an
  overall timeout.
- **Multiple waiters per CQ**; each completion is delivered to exactly one
  waiter.
- **AF_XDP data plane** with copy and zero-copy modes, depending on driver and
  device support.
- **Multi-worker ownership** and Toeplitz RSS steering for connection affinity.
- **TCP and UDP over IPv4/IPv6**, including routing, ARP/NDP, ICMP, timers,
  retransmission, fragmentation, and reassembly.
- **POSIX-style synchronous and non-blocking APIs**, plus an epoll-compatible
  readiness interface.
- **UMEM-aware frame caches** and scatter-gather-capable socket buffers.
- **Netlink integration** for routes, addresses, and neighbor state.

## Async API at a Glance

```c
#include <errno.h>
#include <stdint.h>
#include <netfast.h>

enum { BATCH = 64 };

int submit_writes(int socket_fd, const void *buffers[BATCH],
                  const uint32_t lengths[BATCH])
{
    int cq_fd = net_async_create();
    if (cq_fd < 0)
        return -1;

    net_async_req *submitted[BATCH];
    for (uint32_t i = 0; i < BATCH; ++i) {
        submitted[i] = net_async_req_create(socket_fd, NET_ASYNC_WRITE,
                                             buffers[i], lengths[i]);
        if (!submitted[i])
            return -1;
    }

    int accepted = net_async_submit_batch(cq_fd, submitted, BATCH);
    if (accepted != BATCH)
        return -1;

    uint32_t remaining = BATCH;
    while (remaining) {
        net_async_req *completed[BATCH];
        uint32_t desired = remaining < 16 ? remaining : 16;
        int count = net_async_wait(cq_fd, completed,
                                   desired,  /* desired completion batch */
                                   BATCH,    /* output array capacity */
                                   250);     /* overall timeout in ms */
        if (count < 0)
            return -1;
        if (count == 0)
            continue;

        for (int i = 0; i < count; ++i) {
            int request_errno = 0;
            int result = net_async_req_result(completed[i], &request_errno);
            if (result < 0)
                errno = request_errno;
            net_async_req_destroy(completed[i]);
        }
        remaining -= (uint32_t)count;
    }

    return net_async_close(cq_fd);
}
```

Async ownership rules:

1. `net_async_req_create()` returns a request owned by the application.
2. A successful `net_async_submit()` transfers ownership to the CQ.
3. A positive `net_async_submit_batch()` result transfers only the accepted
   prefix of the request array.
4. `net_async_wait()` returns ownership of completed requests to the caller.
5. Inspect each result, then release it with `net_async_req_destroy()`.
6. Buffers and address objects referenced by a request must stay valid until
   that request completes.

`net_async_wait()` may return a partial batch when its overall timeout expires.
Concurrent threads may wait on the same CQ with different `min_complete`
values.

## Architecture

```text
Application
  |-- synchronous socket API
  |-- epoll-compatible readiness API
  `-- async submit / completion queues
                 |
          request routing
                 |
      +----------+----------+
      |          |          |
   Worker 0   Worker 1   Worker N
      |          |          |
      +---- TCP / UDP -------+
            IPv4 / IPv6
          routing + ARP/NDP
                 |
        skbuff + frame cache
                 |
       AF_XDP RX/TX/CQ rings
                 |
      XDP_REDIRECT / network
```

Each socket is owned by a worker. Requests are routed to that worker instead of
letting application threads manipulate socket state directly. RSS keeps a flow
on a stable worker, while connection migration handles tuple changes such as an
automatic bind followed by `connect()`.

## Build

### Guided setup (Debian/Ubuntu)

For a first installation, use the guided setup script:

```bash
./setup.sh
```

It checks or installs build dependencies, avoids active/primary default-route
and SSH interfaces, detects the selected interface's current queue count, writes a
local `config.json`, builds the release profile, and installs NetFast under
`/usr/local`. It does not attach XDP during installation; XDP is attached when a
root process first loads `libnetfast.so`.

For an unattended lab installation, specify the dedicated interface explicitly:

```bash
./setup.sh --interface ens192 --queues 2 --workers 2 --yes
```

Use `./setup.sh --help` for safety overrides and `--dry-run` to inspect the plan
without changing the system. The script deliberately refuses to select the
active management interface unless `--allow-management-interface` is supplied.

### Requirements

- Linux with AF_XDP support
- C compiler and Clang for the eBPF program
- `libbpf`, `libxdp`, `libelf`, `zlib`, `libcjson`, and pthreads
- Root privileges when attaching XDP and configuring the runtime

Build one of the supported profiles:

```bash
make debug -j$(nproc)
make release -j$(nproc)
make relwithdebinfo -j$(nproc)
```

The shared library is written to `build/libnetfast.so`. Install a release build
with:

```bash
sudo make PROFILE=release install
```

This installs the library, public header, XDP redirect object, and configuration
under `/usr/local` by default.

## Configuration

The versioned [`config.example.json`](./config.example.json) is the installation
template; a local `config.json` is ignored by Git so that machine-specific
settings stay private. A default build loads
`/usr/local/etc/netfast/config.json` when `libnetfast.so` is loaded and does not
search the application's current working directory.

Create a local configuration and install it with the library:

```bash
cp config.example.json config.json
editor config.json
sudo make PROFILE=release install
```

The Makefile uses the local `config.json` when it exists, otherwise it installs
`config.example.json`. Use `CONFIG_FILE=/path/to/config.json` to select another
source file explicitly.

Example configuration:

```json
{
  "thread_num": 2,
  "open_if": [
    { "name": "ens192", "queues": 2 }
  ],
  "ipv4_forward": true,
  "ipv6_forward": true,
  "toeplitz_rss_key": "6d5a56da255b0ec24167253d43a38fb0d0ca2bcbae7b30b477cb2da38030f20c6a42b73bbeac01fa",
  "logfile": "/tmp/user_stack.log"
}
```

### Configuration fields

| Field | Required | Meaning |
| --- | --- | --- |
| `thread_num` | Yes | Number of worker threads, from 1 to 64. Workers are pinned to CPUs on a best-effort basis. |
| `open_if` | Yes | Non-empty array of interfaces owned by NetFast. Interface names must be unique. Interfaces omitted from this list do not get AF_XDP sockets. |
| `open_if[].name` | Yes | Linux interface name, for example `ens192`. Check it with `ip -br link`. Do not select the interface used for SSH or desktop management. |
| `open_if[].queues` | No | Number of AF_XDP RX/TX queues, from 1 to 32. Missing or `0` means `thread_num`. The NIC must expose all requested queue IDs. |
| `ipv4_forward` | No | Enables forwarding of non-local IPv4 packets. Defaults to `true`. |
| `ipv6_forward` | No | Enables forwarding of non-local IPv6 packets. Defaults to `true`. |
| `toeplitz_rss_key` | No | 40-byte Toeplitz key encoded as 80 hexadecimal characters. If omitted, the compiled-in key is used. The same key drives hardware RSS setup and software worker selection. |
| `logfile` | Yes | Non-empty log path shorter than 256 bytes. NetFast creates the file if its parent directory exists and permissions allow it. |

`queues` describes hardware queue IDs, not a per-worker queue count. Queue `q`
is assigned to worker `q % thread_num`; a multi-queue configuration therefore
normally uses at least as many queues as workers. Inspect the device before
choosing the value:

```bash
ethtool -l ens192
ethtool -x ens192
```

For a one-queue NIC, set `queues` to `1`; NetFast skips RSS programming. With
multiple queues it attempts to install a Toeplitz indirection table. An RSS
ioctl failure is logged and initialization continues, but traffic may not be
distributed evenly.

The configuration is parsed once by the shared-library constructor. Invalid
JSON, a missing required field, an out-of-range value, an unavailable queue, or
an unwritable log path makes initialization fail. Restart the application after
editing the installed file. Running `make install` again overwrites the
installed configuration with the selected `CONFIG_FILE`.

### Network safety

- Do **not** attach NetFast to the interface carrying your SSH, desktop, or web
  management connection. XDP redirection takes that traffic away from the
  kernel stack and may disconnect the machine.
- Routes and neighbors are learned through Netlink; interfaces not listed in
  `open_if` are filtered from the NetFast data plane.
- Packets redirected by XDP are not visible to a normal `tcpdump` capture on
  the kernel network stack.
- AF_XDP zero-copy availability depends on the NIC driver. Unsupported devices
  fall back to copy mode unless zero-copy is forced.

## Synchronous and Epoll APIs

The public header also exposes familiar calls such as:

```c
int fd = net_socket(AF_INET, SOCK_STREAM, 0);
net_connect(fd, (struct sockaddr *)&peer, sizeof(peer));
net_write(fd, request, request_len);
net_read(fd, response, response_capacity);
net_close(fd);
```

For readiness-driven programs, use `net_epoll_create()`, `net_epoll_ctl()`, and
`net_epoll_wait()`.

## Testing and Analysis

```bash
make test
make static-analysis
```

The test target covers the base library, Netlink behavior, TCP/UDP loopback,
epoll-related protocol paths, and asynchronous CQ concurrency. Static-analysis
reports are stored under `build/test/static-analysis/`.

## Repository Layout

```text
lib/       AF_XDP, queues, RSS, frame cache, and base utilities
main/      TCP/IP stack, sockets, workers, epoll, and async requests
docs/      protocol design notes
example/   example programs and test resources
test/      unit, integration, stress, and analysis tooling
```

The public API source is [`main/netfast.h`](./main/netfast.h).
