# NetFast

[English](./README.md) | 简体中文

NetFast 是一个基于 Linux AF_XDP 的实验性用户态 TCP/IP 协议栈。它将
worker 独占的网络协议栈、UMEM 数据缓冲、类 epoll 就绪接口和基于完成
队列（CQ）的异步接口整合为一个 C 动态库。

异步 CQ 是 NetFast 面向高吞吐的核心接口：应用可以批量提交 socket
操作、保持多个请求同时在途，并一次取回多个完成，避免每个操作都
执行一次阻塞系统调用。

> NetFast 仍在快速开发中。请先在独立的测试网卡和可控网络中验证。

## 核心特性

- **异步完成队列**：支持单请求和批量提交。
- **批量等待**：同时支持 `min_complete`、`max_complete` 和整体超时。
- **多线程等待同一 CQ**：每个完成只会交给其中一个 waiter。
- **AF_XDP 数据面**：根据网卡和驱动能力运行 copy 或 zero-copy 模式。
- **多 worker 所有权模型**：通过 Toeplitz RSS 让同一连接稳定落到同一 worker。
- **IPv4/IPv6 上的 TCP/UDP**：包含路由、ARP/NDP、ICMP、定时器、重传、分片与重组。
- **POSIX 风格 API**：同时提供同步、非阻塞和类 epoll 就绪接口。
- **UMEM 缓存体系**：线程级和全局 frame cache，skbuff 支持 scatter-gather。
- **Netlink 集成**：动态获取路由、地址和邻居信息。

## 异步 API 快速上手

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
                                   desired,  /* 期望的完成批次 */
                                   BATCH,    /* completed 数组容量 */
                                   250);     /* 整体最多等待 250 ms */
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

异步请求所有权规则：

1. `net_async_req_create()` 返回由应用持有的请求。
2. `net_async_submit()` 成功后，请求所有权转移给 CQ。
3. `net_async_submit_batch()` 返回正数时，只转移数组前缀中已接受的请求。
4. `net_async_wait()` 把已完成请求的所有权交回调用者。
5. 读取结果后，调用 `net_async_req_destroy()` 释放请求。
6. 请求引用的数据缓冲和地址对象必须保持有效，直到请求完成。

`net_async_wait()` 在整体超时到期时可以返回不足 `min_complete` 的部分批次。
多个线程可以在同一 CQ 上使用不同的 `min_complete`。

## 架构

```text
应用程序
  |-- 同步 socket API
  |-- 类 epoll 就绪 API
  `-- 异步提交 / 完成队列
                 |
              请求路由
                 |
      +----------+----------+
      |          |          |
   Worker 0   Worker 1   Worker N
      |          |          |
      +---- TCP / UDP -------+
            IPv4 / IPv6
          路由 + ARP/NDP
                 |
        skbuff + frame cache
                 |
       AF_XDP RX/TX/CQ rings
                 |
      XDP_REDIRECT / 物理网络
```

每个 socket 由一个 worker 独占管理。应用线程不直接修改 socket 状态，而是把请求
路由给对应 worker。RSS 保持连接亲和性；自动 bind、`connect()` 等操作改变五元
组时，连接迁移机制会将 socket 和待处理请求移到新 worker。

## 构建

### 依赖

- 支持 AF_XDP 的 Linux
- C 编译器，以及用于编译 eBPF 程序的 Clang
- `libbpf`、`libxdp`、`libelf`、`zlib`、`libcjson` 和 pthread
- 挂载 XDP 和初始化运行时所需的 root 权限

```bash
make debug -j$(nproc)
make release -j$(nproc)
make relwithdebinfo -j$(nproc)
```

动态库位于 `build/libnetfast.so`。安装 Release 版本：

```bash
sudo make PROFILE=release install
```

默认安装到 `/usr/local`，包含动态库、公共头文件、XDP 重定向程序和配置文件。

## 配置

NetFast 读取当前目录的 `config.json`，或安装后的
`/usr/local/etc/netfast/config.json`。

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

修改安装配置后，需要重新执行安装命令，或手动将配置复制到安装路径。

### 网络安全注意事项

- **不要**在承载 SSH、桌面或 Web 管理连接的网卡上挂载 NetFast。XDP 重定向会使
  这些流量离开内核协议栈，可能立即断开连接。
- 路由和邻居信息由 Netlink 获取；未列入 `open_if` 的网卡不会进入 NetFast 数据面。
- XDP 重定向后的报文不会出现在内核协议栈的普通 `tcpdump` 抓包中。
- AF_XDP zero-copy 取决于网卡驱动；不支持时会回退到 copy mode，除非强制要求 zero-copy。

## 同步与 Epoll 接口

公共头文件同时提供熟悉的 socket 风格调用：

```c
int fd = net_socket(AF_INET, SOCK_STREAM, 0);
net_connect(fd, (struct sockaddr *)&peer, sizeof(peer));
net_write(fd, request, request_len);
net_read(fd, response, response_capacity);
net_close(fd);
```

就绪驱动程序可以使用 `net_epoll_create()`、`net_epoll_ctl()` 和 `net_epoll_wait()`。

## 测试与静态分析

```bash
make test
make static-analysis
```

测试覆盖基础库、Netlink、TCP/UDP loopback、epoll 相关协议路径和异步 CQ 并发。
静态分析报告保存在 `build/test/static-analysis/`。

## 目录结构

```text
lib/       AF_XDP、队列、RSS、frame cache 和基础组件
main/      TCP/IP 协议栈、socket、worker、epoll 和异步请求
docs/      协议设计文档
example/   示例程序和测试资源
test/      单元、集成、压力和静态分析工具
```

公共 API 源文件为 [`main/netfast.h`](./main/netfast.h)。
