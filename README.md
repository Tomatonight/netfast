# NetFast

[English](./README.md) | [简体中文](./README_zh.md)

NetFast is an experimental userspace TCP/IP stack built on Linux AF_XDP. It
combines a worker-owned network stack, UMEM-backed packet buffers, and a
completion-queue-based asynchronous API in one C library.

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
- **POSIX-style synchronous and non-blocking socket APIs**.
- **UMEM-aware frame caches** and scatter-gather-capable socket buffers.
- **Netlink integration** for routes, addresses, and neighbor state.

## Async API at a Glance

The asynchronous interface has three main objects:

- A **completion queue (CQ)** receives requests and returns completed work.
- A **request (`req`)** describes an operation and its target fd.
- A **completed request** is the original request pointer returned by
  `net_async_wait()`, with the result stored directly in the request.

The following example performs one asynchronous write on an already connected
TCP socket. It intentionally submits only one request to make the complete flow
easy to follow:

```c
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <netfast.h>

int async_write_once(int socket_fd, const void *buffer, uint32_t length)
{
    /* 1. Create a completion queue. */
    int cq_fd = net_async_create();
    if (cq_fd < 0)
        return -1;

    /* 2. Create a write request. buffer must remain valid until completion. */
    req *request = net_async_req_create(
        socket_fd, REQ_WRITE, buffer, length);
    if (!request) {
        int saved_errno = errno;
        net_async_close(cq_fd);
        errno = saved_errno;
        return -1;
    }

    /* 3. After a successful submit, the CQ temporarily owns the request. */
    if (net_async_submit(cq_fd, request) < 0) {
        int saved_errno = errno;
        net_async_req_destroy(request);
        net_async_close(cq_fd);
        errno = saved_errno;
        return -1;
    }

    /* 4. Wait for one completion; -1 means wait indefinitely. */
    req *completed = NULL;
    if (net_async_wait(cq_fd, &completed, 1, 1, -1) != 1) {
        int saved_errno = errno;
        net_async_close(cq_fd);
        errno = saved_errno;
        return -1;
    }

    req_type type;
    int result = net_async_result(completed, &type);
    net_async_req_destroy(completed);
    net_async_close(cq_fd);

    if (result < 0) {
        errno = -result;
        return -1;
    }
    return result;
}
```

Common request forms are:

```c
net_async_req_create(-1, REQ_SOCKET, family, type, protocol);
net_async_req_create(fd, REQ_CONNECT, addr, addrlen);
net_async_req_create(fd, REQ_ACCEPT, addr, addrlen_ptr);
net_async_req_create(fd, REQ_READ, buffer, length);
net_async_req_create(fd, REQ_WRITE, buffer, length);
net_async_req_create(fd, REQ_CLOSE);
```

After completion, call `net_async_result()`. It returns the operation result;
the nullable output pointer returns the request type:

```c
int result = net_async_result(completed, NULL);
int result_with_type = net_async_result(completed, &type);
```

Request parameters are read through `net_async_argv()` instead of being
returned by `net_async_result()`:

```c
req_argv *argv = net_async_argv(completed);
struct sockaddr *client_addr = argv->accept.addr;
socklen_t client_addr_len = *argv->accept.addrlen;
```

- `type` identifies the operation that completed.
- The returned result is non-negative on success and `-errno` on failure. Successful
  `SOCKET` and `ACCEPT` operations return a new fd; successful `READ` and
  `WRITE` operations return a byte count. A `READ` result of `0` means the peer
  has cleanly closed its sending side.

To keep several operations in flight, call `net_async_submit()` once for each
request. A typical wait that collects up to 64 completions is:

```c
req *completed[64];
int count = net_async_wait(cq_fd, completed,
                           1,     /* wait for at least one completion */
                           64,    /* capacity of completed[] */
                           1000); /* total timeout for this wait, in ms */
```

Request ownership rules:

1. `net_async_req_create()` returns a request owned by the application.
2. A successful `net_async_submit()` transfers ownership to the CQ.
3. `net_async_wait()` returns ownership of completed requests to the caller.
4. Read the result with `net_async_result()`.  The returned request can then
   be submitted again, to the same or another CQ, or released with
   `net_async_req_destroy()`.
5. An in-flight request cannot be submitted again; `net_async_submit()` fails
   with `EBUSY` until `net_async_wait()` returns that request.
6. A resubmission uses the current values in `net_async_argv()`.  Update them,
   if needed, only after the request is returned and before resubmitting it.
7. Buffers and address objects referenced by a request must stay valid until
   that request completes.

`net_async_wait()` may return a partial batch when its overall timeout expires.
Concurrent threads may wait on the same CQ with different `min_complete`
values.

## Architecture

```text
Application
  |-- synchronous socket API
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

### Setup script (Debian/Ubuntu)

For a first installation, use the setup script:

```bash
./setup.sh
```

The script only checks or installs build dependencies, then runs the default
release `make` and `make install`. It does not select an interface, calculate
queue or worker counts, or generate a configuration. If a local
`netfast_config.json` exists it is installed; otherwise `config.example.json`
is installed. Setup does not attach XDP; XDP is attached when a root process
first loads `libnetfast.so`.

Use `./setup.sh --help` to list all options and `--dry-run` to check dependencies
and print the commands that would run.

### Requirements

- Linux with AF_XDP support
- C compiler and Clang for the eBPF program
- `libbpf`, `libxdp`, `libelf`, `zlib`, `libcjson`, and pthreads
- Root privileges when attaching XDP and configuring the runtime

Build one of the supported profiles:

```bash
make -j$(nproc)                  # Release by default
make debug -j$(nproc)
make relwithdebinfo -j$(nproc)
```

The shared library is written to `build/libnetfast.so`. Install a release build
with:

```bash
sudo make install
```

This installs the library, public header, XDP redirect object, and configuration
under `/usr/local` by default.

## Configuration

The versioned [`config.example.json`](./config.example.json) is the installation
template; a local `netfast_config.json` is ignored by Git so that machine-specific
settings stay private. When `libnetfast.so` is loaded, a default build first
looks for `netfast_config.json` in the process's current working directory and
falls back to `/usr/local/etc/netfast/netfast_config.json` when it is absent.

Create a local configuration and install it with the library:

```bash
cp config.example.json netfast_config.json
editor netfast_config.json
sudo make install
```

The Makefile uses the local `netfast_config.json` when it exists, otherwise it installs
`config.example.json`. Use `CONFIG_FILE=/path/to/netfast_config.json` to select another
source file explicitly.

Example configuration:

```json
{
  "thread_num": 2,
  "open_if": [
    { "name": "ens192", "queues": 2 }
  ],
  "source_port_range": [1024, 32767],
  "redirect_fragments": false,
  "logfile": "/tmp/user_stack.log"
}
```

### Configuration fields

| Field | Required | Meaning |
| --- | --- | --- |
| `thread_num` | Yes | Number of worker threads, from 1 to 64. Workers are pinned to CPUs on a best-effort basis. |
| `open_if` | Yes | Non-empty array of interfaces owned by NetFast. Interface names must be unique. Interfaces omitted from this list do not get AF_XDP sockets. |
| `open_if[].name` | Yes | Linux interface name, for example `ens192`. Check it with `ip -br link`. |
| `open_if[].queues` | No | Number of AF_XDP RX/TX queues, from 1 to 32. Missing or `0` means `thread_num`. The NIC must expose all requested queue IDs. |
| `source_port_range` | No | Inclusive source-port range shared by TCP and UDP. Automatic binds select only this range, and explicit non-zero binds outside it fail. The default is `[1024, 32767]`. |
| `redirect_fragments` | No | Redirect fragmented IPv4/IPv6 packets to NetFast when `true`; leave them in the kernel when `false` (the default). |
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
multiple queues it attempts to install a Toeplitz indirection table using the
compiled-in symmetric key, so both directions of one IPv4/IPv6 TCP or UDP flow
select the same queue and worker. An RSS ioctl failure is logged and
initialization continues, but traffic may not be distributed evenly.
Forwarding non-local IPv4 and IPv6 packets is disabled.

The configuration is parsed once by the shared-library constructor. Invalid
JSON, a missing required field, an out-of-range value, an unavailable queue, or
an unwritable log path makes initialization fail. Restart the application after
editing the installed file. Running `make install` again overwrites the
installed configuration with the selected `CONFIG_FILE`.

During initialization NetFast merges `source_port_range` into Linux
`net.ipv4.ip_local_reserved_ports`. This prevents the kernel TCP/UDP stack from
automatically allocating a port owned by NetFast while preserving existing
system reservations. Updating this per-network-namespace sysctl requires the
same administrative privileges normally needed to attach XDP. On normal
shutdown NetFast restores this range to its pre-initialization reservation
state while leaving reservations outside the range unchanged. Initialization
failures after the reservation was installed perform the same cleanup; abrupt
termination that skips library destructors cannot clean it up automatically.

### XDP traffic ownership

After XDP is attached, TCP and UDP packets are redirected only when their
destination port is inside `source_port_range`. Fragmented packets have no
reliably available transport destination port, so `redirect_fragments` controls
them separately.

## Synchronous API

The public header also exposes familiar calls such as:

```c
int fd = net_socket(AF_INET, SOCK_STREAM, 0);
net_connect(fd, (struct sockaddr *)&peer, sizeof(peer));
net_write(fd, request, request_len);
net_read(fd, response, response_capacity);
net_close(fd);
```

### Socket callbacks

Applications that already have an event loop can register one callback for a
socket instead of submitting a readiness request for every event:

```c
static void on_socket_event(Socket *sock, net_event_mask events, void *arg)
{
    struct app_state *state = arg;

    if (events & NET_EVENT_READ)
        handle_readable(state, sock);
    if (events & NET_EVENT_WRITE)
        handle_writable(state, sock);
    if (events & NET_EVENT_ERROR)
        handle_error(state, sock);
}

net_set_callback(fd, NET_EVENT_READ | NET_EVENT_WRITE |
                       NET_EVENT_ERROR, on_socket_event, state);
```

The callback runs on the worker that owns the socket, so socket state and
protocol processing remain serialized with packet handling. Notifications are
coalesced until the worker runs the callback; the `events` mask can contain
multiple bits. The callback receives the opaque `Socket *` associated with the
event and the application-provided `arg`. Call `net_clear_callback(fd)` to
remove it.

Synchronous `net_*` calls made from the owning worker execute inline and never
wait for that worker. If an operation would block, it returns `EAGAIN` or
`EINPROGRESS`. A worker callback cannot synchronously operate on a socket owned
by another worker; that call returns `EAGAIN`. Keep the callback short and use
the asynchronous request API or an application queue for work that needs to
run elsewhere. `net_async_wait()` and `net_async_close()` are lifecycle calls
that may wait for other workers and must be called outside a worker callback.

## Repository Layout

```text
lib/       AF_XDP, queues, RSS, frame cache, and base utilities
main/      TCP/IP stack, sockets, workers, and async requests
docs/      protocol design notes
example/   example programs and test resources
test/      unit, integration, stress, and analysis tooling
```

The public API source is [`main/netfast.h`](./main/netfast.h).

## Project article

- [Building a userspace TCP/IP stack with C and AF_XDP (Chinese)](./docs/introducing_netfast_zh.md)
