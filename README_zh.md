# NetFast

[English](./README.md) | 简体中文

基于 AF_XDP（eXpress Data Path）构建的高性能用户态 TCP/IP 网络协议栈，专为低延迟、高吞吐场景设计。NetFast 在数据面完全绕过内核网络栈，同时提供兼容 POSIX 的 socket API。

## 架构

```
┌─────────────────────────────────────────────────────┐
│                     应用程序                         │
│         (net_socket / net_connect / net_read ...)    │
├─────────────────────────────────────────────────────┤
│                  公共 API (api/netfast.h)             │
│   ┌──────────┬──────────┬──────────┬──────────┐     │
│   │  Socket  │  Epoll   │  Async   │  Fcntl   │     │
│   │   API    │   API    │   API    │   API    │     │
│   └──────────┴──────────┴──────────┴──────────┘     │
├─────────────────────────────────────────────────────┤
│                请求层 (main/req*.c)                   │
│   ┌──────────────┬──────────────┬────────────────┐  │
│   │  req_socket  │  req_epoll   │   req_async    │  │
│   │   (同步阻塞)  │  (事件轮询)   │   (完成队列)    │  │
│   └──────────────┴──────────────┴────────────────┘  │
├─────────────────────────────────────────────────────┤
│               协议栈 (main/)                          │
│   ┌──────────────────────────────────────────────┐  │
│   │  TCP (tcp.c)          UDP (udp.c)             │  │
│   │  ├─ 拥塞控制          ├─ Sendto/Recvfrom      │  │
│   │  ├─ 重传              ├─ Connect              │  │
│   │  ├─ 定时器            └───────────────────────┘  │
│   │  └─ 状态机                                     │  │
│   ├──────────────────────────────────────────────┤  │
│   │  IP (ip.c)           IPv6 (ipv6.c)            │  │
│   │  ├─ 分片重组          ├─ 扩展头                │  │
│   │  └─ 转发             └─ IPv6 分片             │  │
│   ├──────────────────────────────────────────────┤  │
│   │  ICMP (icmp.c)        ARP/NDP (route_arp_ndp) │  │
│   ├──────────────────────────────────────────────┤  │
│   │  Socket 层 (socket.c)                         │  │
│   │  ├─ Bind/Unbind        ├─ 五元组哈希          │  │
│   │  └─ 自动绑定            └─ SO_REUSEPORT       │  │
│   ├──────────────────────────────────────────────┤  │
│   │  skbuff (skbuff.c) — 零拷贝缓冲区管理          │  │
│   ├──────────────────────────────────────────────┤  │
│   │  Loopback (loopback.c)                        │  │
│   └──────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────┤
│                  Worker 层 (main/worker.c)            │
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
│               基础库 (lib/)                           │
│   ┌─────────┬─────────┬──────────┬──────────────┐   │
│   │  hash   │  list   │  queue   │ frame_cache  │   │
│   │ (MPMC)  │ (双向)   │ (无锁)    │ (UMEM 管理)  │   │
│   ├─────────┼─────────┼──────────┼──────────────┤   │
│   │  rss    │  trie   │  thread  │    base      │   │
│   │(Toeplitz)│(基数树) │ (线程工具) │  (辅助函数)   │   │
│   └─────────┴─────────┴──────────┴──────────────┘   │
├─────────────────────────────────────────────────────┤
│              AF_XDP 数据面 (lib/xdp.c)                │
│   ┌──────────────────────────────────────────────┐  │
│   │  UMEM (XDP_UMEM_FRAME_CNT × 4KB = 256 MB)    │  │
│   │  ├─ Fill Ring (RX 缓冲区)                     │  │
│   │  ├─ RX Ring    (入站数据包)                    │  │
│   │  ├─ TX Ring    (出站数据包)                    │  │
│   │  └─ Completion Ring (TX 完成)                 │  │
│   └──────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────┤
│         eBPF 程序 (lib/xdp_redirect.bpf.c)            │
│     XDP_REDIRECT → 用户态 AF_XDP socket              │
└─────────────────────────────────────────────────────┘
```

## 核心设计

### 多 Worker 架构

每个 worker 线程绑定到独立的 CPU 核心，拥有自己的 AF_XDP socket（XSK）。数据包通过 **Toeplitz RSS 哈希** 对五元组 `(sip, sport, dip, dport, protocol)` 进行路由，确保同一连接的所有数据包落在同一个 worker 上，从而实现无锁的逐连接处理。

### 零拷贝数据路径

- **UMEM 帧缓存**：所有数据包缓冲区位于 AF_XDP 映射的共享 UMEM 区域中，消除了内核到用户态的拷贝。
- **skbuff（socket 缓冲区）**：轻量级缓冲区抽象，支持 scatter-gather I/O、写时复制和引用计数。
- **XDP 重定向**：eBPF 程序 `xdp_redirect.bpf.c` 通过 `XDP_REDIRECT` 将数据包直接重定向到用户态 UMEM。

### 无锁 Socket 表

- **MPMC 哈希表**（`lib/hash.c`）：并发的无锁哈希表，用于 socket 五元组查找。
- **绑定表**：按协议族（IPv4/IPv6）跟踪地址/端口绑定。
- **SO_REUSEPORT**：多个 socket 可绑定同一端口；RSS 分发入站连接。

### 协议虚表

每种协议（TCP、UDP）实现 `protocol_ops`——一个虚函数表，包含 `connect`、`bind`、`listen`、`accept`、`read`、`write`、`sendto`、`recvfrom`、`poll`、`shutdown` 等回调。Socket 层通过这些 ops 进行分发，使协议栈易于扩展。

### 同步与异步请求模型

- **同步阻塞（req_socket）**：传统的阻塞 socket 调用，支持超时。
- **非阻塞**：`O_NONBLOCK` 标志立即返回 `EAGAIN`。
- **Epoll（req_epoll）**：完整的 `epoll_create`/`epoll_ctl`/`epoll_wait` 集成。
- **异步完成队列（req_async）**：基于完成队列的异步 API，支持批量提交和完成。

### 连接迁移

当 socket 的地址发生变化时（例如 `connect()` 确定五元组，或 `sendto()` 为通配符绑定选择源 IP），RSS 哈希可能映射到不同的 worker。NetFast 通过 **迁移 socket 和挂起的请求**（`change_req_worker`）透明地处理此问题。

## 项目结构

```
.
├── api/
│   └── netfast.h              # 公共 C API 头文件
├── lib/                       # 基础库
│   ├── base.c/h               # 辅助工具、时间、引用计数
│   ├── frame_cache.c/h        # 基于 UMEM 的帧分配器
│   ├── hash.c/h               # 无锁 MPMC 哈希表
│   ├── list.c/h               # 双向链表
│   ├── log.c/h                # 日志子系统
│   ├── queue.c/h              # 无锁 MPSC 队列
│   ├── rss.c/h                # Toeplitz RSS 哈希与 worker 选择
│   ├── thread.c/h             # 线程工具
│   ├── trie.c/h               # 基数树（路由表）
│   ├── xdp.c/h                # AF_XDP 设置、UMEM、RX/TX 环
│   └── xdp_redirect.bpf.c     # eBPF XDP 重定向程序
├── main/                      # 核心协议栈
│   ├── ether.c/h              # 以太网帧处理
│   ├── fd_entry.c/h           # 文件描述符管理
│   ├── icmp.c/h               # ICMP 错误处理
│   ├── if.c/h                 # 网络接口管理
│   ├── init.c/h               # 协议栈初始化与配置
│   ├── ip.c/h                 # IPv4 输入/输出/分片
│   ├── ip_frag.c/h            # IPv4 分片重组
│   ├── ipv6.c/h               # IPv6 输入/输出
│   ├── ipv6_ext.c/h           # IPv6 扩展头
│   ├── ipv6_frag.h            # IPv6 分片重组
│   ├── loopback.c/h           # 回环设备
│   ├── netlink.c/h            # Netlink（路由/地址监控）
│   ├── req.c/h                # 请求基础设施
│   ├── req_async.c/h          # 异步完成队列 API
│   ├── req_epoll.c/h          # Epoll 集成
│   ├── req_socket.c/h         # 同步阻塞 socket 请求处理
│   ├── route_arp_ndp.c/h      # 路由查找、ARP、NDP
│   ├── skbuff.c/h             # Socket 缓冲区（零拷贝、scatter-gather）
│   ├── socket.c/h             # Socket 层（bind、五元组安装、自动绑定）
│   ├── stack.c/h              # 每个 worker 的协议栈实例
│   ├── tcp.c/h                # TCP 协议（状态机、定时器、重传）
│   ├── tcp_congestion.c       # TCP 拥塞控制（Reno/CUBIC）
│   ├── tcp_metrics.c/h        # TCP 指标与 RTT 估算
│   ├── udp.c/h                # UDP 协议
│   └── worker.c/h             # Worker 线程与跨 worker 通信
├── docs/                      # 设计文档
│   ├── tcp_sack_design.md     # TCP SACK 设计笔记
│   └── tcp_sack_tested_diff.md
├── example/                   # 示例应用
├── test/                      # 测试与基准测试
│   ├── tcp_stream_perf.c      # TCP 吞吐量基准测试
│   ├── bench_*.c              # 微基准测试
│   └── integration_*.c        # 集成测试
├── Makefile                   # 构建系统
└── config.json                # 运行时配置
```

## 构建

### 前置依赖

- Linux 内核 ≥ 5.4，支持 AF_XDP
- `libbpf`、`libxdp`、`libelf`、`libz`、`libcjson`
- Clang（用于 eBPF 编译）

### 编译

```bash
# Debug 构建（开发调试）
make PROFILE=debug -j$(nproc)

# Release 构建（生产部署）
make PROFILE=release -j$(nproc)

# 带调试符号的 Release 构建（支持 perf/profile 分析）
make PROFILE=relwithdebinfo -j$(nproc)
```

产物：`build/libnetfast.so`

### 配置

编辑 `config.json` 或放置在 `/usr/local/etc/netfast/config.json`：

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

## 快速开始

```c
#include <netfast.h>

int main() {
    // 创建 TCP socket
    int fd = net_socket(AF_INET, SOCK_STREAM, 0);

    // 连接到远程
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(8080)
    };
    inet_pton(AF_INET, "192.168.1.1", &addr.sin_addr);
    net_connect(fd, (struct sockaddr*)&addr, sizeof(addr));

    // 发送数据
    net_write(fd, "hello", 5);

    // 接收响应
    char buf[1024];
    int n = net_read(fd, buf, sizeof(buf));

    net_close(fd);
    return 0;
}
```

## 特性

- **TCP**：完整状态机（RFC 793），指数退避重传，Keepalive，延迟 ACK，Nagle 算法，窗口缩放，时间戳（PAWS），SACK，拥塞控制（Reno/CUBIC），FIN-WAIT-2/TIME-WAIT 超时
- **UDP**：无连接数据报，`sendto`/`recvfrom`，隐式 connect
- **IPv4/IPv6**：分片与重组，扩展头，ICMP 错误处理
- **ARP/NDP**：地址解析与邻居发现
- **Socket 选项**：`SO_REUSEADDR`、`SO_REUSEPORT`、`SO_KEEPALIVE`、`SO_RCVBUF`、`SO_SNDBUF`、`SO_RCVTIMEO`、`SO_SNDTIMEO`、`TCP_NODELAY`、`TCP_CORK`、`TCP_QUICKACK`
- **Epoll**：水平触发 `EPOLLIN`/`EPOLLOUT`/`EPOLLERR`/`EPOLLHUP`/`EPOLLRDHUP`
- **非阻塞 I/O**：通过 `net_fcntl` 设置 `O_NONBLOCK`
- **异步 API**：基于完成队列，支持批量提交与完成
- **Loopback**：协议栈内部直接交付，无需经过 AF_XDP
- **Netlink**：路由与地址监控，支持动态配置
