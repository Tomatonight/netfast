# NetFast

[English](./README.md) | 简体中文

NetFast 是一个基于 Linux AF_XDP 的实验性用户态 TCP/IP 协议栈。它将
worker 独占的网络协议栈、UMEM 数据缓冲和基于完成队列（CQ）的异步接口
整合为一个 C 动态库。

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
- **POSIX 风格 API**：提供同步和非阻塞 socket 接口。
- **UMEM 缓存体系**：线程级和全局 frame cache，skbuff 支持 scatter-gather。
- **Netlink 集成**：动态获取路由、地址和邻居信息。

## 异步 API 快速上手

异步接口可以理解为三个对象：

- **CQ（完成队列）**：应用提交请求、接收完成结果的队列。
- **请求（`req`）**：描述要对哪个 fd 执行什么操作。
- **完成请求**：操作结束后，`net_async_wait()` 返回原来的请求指针，结果
  直接保存在请求中。

下面的例子向一个已经连接的 TCP socket 异步写入一次数据。它刻意只提交
一个请求，便于看清完整流程：

```c
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <netfast.h>

int async_write_once(int socket_fd, const void *buffer, uint32_t length)
{
    /* 1. 创建完成队列。 */
    int cq_fd = net_async_create();
    if (cq_fd < 0)
        return -1;

    /* 2. 创建写请求。buffer 在请求完成前必须保持有效。 */
    req *request = net_async_req_create(
        socket_fd, REQ_WRITE, buffer, length);
    if (!request) {
        int saved_errno = errno;
        net_async_close(cq_fd);
        errno = saved_errno;
        return -1;
    }

    /* 3. 提交成功后，请求暂时归 CQ 管理。 */
    if (net_async_submit(cq_fd, request) < 0) {
        int saved_errno = errno;
        net_async_req_destroy(request);
        net_async_close(cq_fd);
        errno = saved_errno;
        return -1;
    }

    /* 4. 等待一个完成；-1 表示一直等待。 */
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

常用调用的参数形式如下：

```c
net_async_req_create(-1, REQ_SOCKET, family, type, protocol);
net_async_req_create(fd, REQ_CONNECT, addr, addrlen);
net_async_req_create(fd, REQ_ACCEPT, addr, addrlen_ptr);
net_async_req_create(fd, REQ_READ, buffer, length);
net_async_req_create(fd, REQ_WRITE, buffer, length);
net_async_req_create(fd, REQ_CLOSE);
```

完成后调用 `net_async_result()`。其返回操作结果，可为 `NULL` 的输出
指针用来获取请求类型：

```c
int result = net_async_result(completed, NULL);
int result_with_type = net_async_result(completed, &type);
```

请求参数不再由 `net_async_result()` 返回，需要时通过
`net_async_argv()` 访问：

```c
req_argv *argv = net_async_argv(completed);
struct sockaddr *client_addr = argv->accept.addr;
socklen_t client_addr_len = *argv->accept.addrlen;
```

- `type` 表示完成的请求类型。
- 返回值成功时是非负结果，失败时是 `-errno`。`SOCKET` 和 `ACCEPT`
  成功时返回新 fd，`READ` 和 `WRITE` 成功时返回处理的字节数；`READ`
  返回 `0` 表示对端已经正常关闭发送方向。

需要并发处理多个操作时，对每个请求调用一次 `net_async_submit()`。一次最多
取回 64 个完成的典型写法是：

```c
req *completed[64];
int count = net_async_wait(cq_fd, completed,
                           1,     /* 至少等待 1 个完成 */
                           64,    /* 数组最多容纳 64 个 */
                           1000); /* 整批最多等待 1000 ms */
```

请求所有权规则：

1. `net_async_req_create()` 返回由应用持有的请求。
2. `net_async_submit()` 成功后，请求所有权转移给 CQ。
3. `net_async_wait()` 把已完成请求的所有权交回调用者。
4. 完成后使用 `net_async_result()` 读取结果。取回的请求可以再次
   提交到相同或其他 CQ，也可以调用 `net_async_req_destroy()` 释放。
5. 在途请求不能重复提交；在 `net_async_wait()` 返回该请求前，
   `net_async_submit()` 会失败并设置 `errno = EBUSY`。
6. 重新提交使用 `net_async_argv()` 中的当前参数；如需修改，只能在
   请求被取回后、下一次提交前修改。
7. 请求引用的数据缓冲和地址对象必须保持有效，直到请求完成。

`net_async_wait()` 在整体超时到期时可以返回不足 `min_complete` 的部分批次。
多个线程可以在同一 CQ 上使用不同的 `min_complete`。

## 架构

```text
应用程序
  |-- 同步 socket API
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

### 安装脚本（Debian/Ubuntu）

首次安装可以直接运行：

```bash
./setup.sh
```

脚本只检查或安装构建依赖，然后依次执行默认的 Release 版 `make` 和
`make install`。它不选择接口、不计算队列或 worker，也不生成配置文件。
本地存在 `netfast_config.json` 时安装该文件，否则安装
`config.example.json`。安装过程不会挂载 XDP；第一个以 root 身份加载
`libnetfast.so` 的进程才会挂载。

使用 `./setup.sh --help` 查看所有选项，使用 `--dry-run` 只检查依赖并显示
将要执行的命令。

### 依赖

- 支持 AF_XDP 的 Linux
- C 编译器，以及用于编译 eBPF 程序的 Clang
- `libbpf`、`libxdp`、`libelf`、`zlib`、`libcjson` 和 pthread
- 挂载 XDP 和初始化运行时所需的 root 权限

```bash
make -j$(nproc)                  # 默认 Release
make debug -j$(nproc)
make relwithdebinfo -j$(nproc)
```

动态库位于 `build/libnetfast.so`。安装 Release 版本：

```bash
sudo make install
```

默认安装到 `/usr/local`，包含动态库、公共头文件、XDP 重定向程序和配置文件。

## 配置

版本库跟踪的 [`config.example.json`](./config.example.json) 是安装模板；本机
`netfast_config.json` 被 Git 忽略，避免上传网卡名、日志路径等机器专用设置。
默认构建的 `libnetfast.so` 在被加载时优先读取进程当前工作目录下的
`netfast_config.json`；文件不存在时再读取
`/usr/local/etc/netfast/netfast_config.json`。

复制模板、按实际环境修改，然后随动态库一起安装：

```bash
cp config.example.json netfast_config.json
editor netfast_config.json
sudo make install
```

Makefile 在本地 `netfast_config.json` 存在时优先安装它，否则安装
`config.example.json`。也可用 `CONFIG_FILE=/path/to/netfast_config.json` 显式选择
其他源配置。

配置示例：

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

### 配置字段

| 字段 | 是否必填 | 说明 |
| --- | --- | --- |
| `thread_num` | 是 | worker 线程数，范围为 1～64。worker 会尽力绑定到 CPU。 |
| `open_if` | 是 | NetFast 接管的网卡数组，不能为空，网卡名不能重复。未列入的网卡不会创建 AF_XDP socket。 |
| `open_if[].name` | 是 | Linux 网卡名，例如 `ens192`，可用 `ip -br link` 查看。 |
| `open_if[].queues` | 否 | AF_XDP RX/TX 队列数，范围为 1～32。省略或填 `0` 时等于 `thread_num`；网卡必须实际提供这些队列 ID。 |
| `source_port_range` | 否 | TCP 和 UDP 共用的源端口闭区间。自动绑定只从该范围选端口；显式绑定非零端口时，范围外端口会失败。默认值为 `[1024, 32767]`。 |
| `redirect_fragments` | 否 | 为 `true` 时把 IPv4/IPv6 分片报文重定向给 NetFast；为 `false`（默认值）时留给内核。 |
| `logfile` | 是 | 非空日志路径，长度小于 256 字节。父目录存在且权限允许时，NetFast 会创建该文件。 |

`queues` 表示硬件队列 ID 数量，不是每个 worker 的队列数。队列 `q` 分配给
worker `q % thread_num`，因此多队列配置通常至少使用与 worker 数相同的
队列数。配置前先查看网卡能力：

```bash
ethtool -l ens192
ethtool -x ens192
```

单队列网卡应设置 `"queues": 1`，NetFast 会跳过 RSS 配置。多队列时
NetFast 会使用编译内置的双向一致 key 写入 Toeplitz RSS 间接表，使同一
IPv4/IPv6 TCP 或 UDP 流的两个方向进入相同队列和 worker；RSS ioctl 失败
会记录日志并继续初始化，但流量可能无法均匀分配。非本机 IPv4 和 IPv6
报文转发默认关闭。

配置在动态库构造阶段只解析一次。JSON 格式错误、缺少必填字段、数值
越界、队列不存在或日志路径不可写都会导致初始化失败。修改安装配置
后必须重启应用。重新执行 `make install` 会用当前选中的 `CONFIG_FILE`
覆盖已安装配置。

初始化期间，NetFast 会把 `source_port_range` 合并写入 Linux 的
`net.ipv4.ip_local_reserved_ports`，保留系统已有配置，同时阻止内核 TCP/UDP
协议栈自动分配 NetFast 接管的端口。该 sysctl 属于当前网络命名空间，修改它
需要与挂载 XDP 通常相同的管理权限。NetFast 正常退出时会把该范围恢复为
初始化前的保留状态，范围外的保留配置保持不变。完成端口保留后的初始化失败
也会执行相同清理；不会运行动态库析构流程的异常终止无法自动清理。

### XDP 流量接管

XDP 挂载后，只重定向目的端口落在 `source_port_range` 内的 TCP/UDP 报文。
分片报文无法可靠取得传输层目的端口，因此由 `redirect_fragments` 单独控制。

## 同步接口

公共头文件同时提供熟悉的 socket 风格调用：

```c
int fd = net_socket(AF_INET, SOCK_STREAM, 0);
net_connect(fd, (struct sockaddr *)&peer, sizeof(peer));
net_write(fd, request, request_len);
net_read(fd, response, response_capacity);
net_close(fd);
```

### Socket callback

如果应用已经有自己的事件循环，可以为 socket 注册一个 callback，直接接收
就绪通知，而不必为每次事件提交一个等待请求：

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

callback 在 socket 所属的 worker 线程上执行，因此 socket 状态和报文处理仍然
由同一个 worker 串行化。worker 执行 callback 前会合并已经产生的通知，
`events` 可能同时包含多个位。callback 会收到对应的 opaque `Socket *` 和
应用传入的 `arg`。使用 `net_clear_callback(fd)` 可以移除 callback。

在所属 worker 中调用同步 `net_*` API 时会直接执行，不会再次等待该 worker。
如果操作需要等待数据或发送空间，会返回 `EAGAIN` 或 `EINPROGRESS`。worker
callback 不能同步操作其他 worker 所属的 socket，此时会返回 `EAGAIN`。callback
应尽量保持简短；需要在其他线程执行的工作，请使用异步请求 API 或应用自己的
任务队列。`net_async_wait()` 和 `net_async_close()` 可能需要等待其他 worker，
必须在 worker callback 外调用。

## 目录结构

```text
lib/       AF_XDP、队列、RSS、frame cache 和基础组件
main/      TCP/IP 协议栈、socket、worker 和异步请求
docs/      协议设计文档
example/   示例程序和测试资源
test/      单元、集成、压力和静态分析工具
```

公共 API 源文件为 [`main/netfast.h`](./main/netfast.h)。

## 项目文章

- [我用 C 和 AF_XDP 写了一个用户态 TCP/IP 协议栈：NetFast](./docs/introducing_netfast_zh.md)
