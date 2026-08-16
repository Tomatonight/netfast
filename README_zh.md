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
- **请求（`net_async_req`）**：描述要对哪个 fd 执行什么操作。
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
    net_async_req *request = net_async_req_create(
        socket_fd, NET_ASYNC_WRITE, buffer, length);
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
    net_async_req *completed = NULL;
    if (net_async_wait(cq_fd, &completed, 1, 1, -1) != 1) {
        int saved_errno = errno;
        net_async_close(cq_fd);
        errno = saved_errno;
        return -1;
    }

    /*
     * completed 就是上面提交的 request：
     *   completed->type     == NET_ASYNC_WRITE
     *   completed->async_fd == socket_fd
     *   completed->ret      == 写入字节数，失败时为 -errno
     */
    int result = completed->ret;
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
net_async_req_create(-1, NET_ASYNC_SOCKET, family, type, protocol);
net_async_req_create(fd, NET_ASYNC_CONNECT, addr, addrlen);
net_async_req_create(fd, NET_ASYNC_ACCEPT, addr, addrlen_ptr);
net_async_req_create(fd, NET_ASYNC_READ, buffer, length);
net_async_req_create(fd, NET_ASYNC_WRITE, buffer, length);
net_async_req_create(fd, NET_ASYNC_CLOSE);
```

完成后直接访问 `req->type`、`req->async_fd` 和 `req->ret`：

- `type` 表示完成的请求类型。
- `async_fd` 是创建请求时传入的 fd。
- `ret` 成功时是非负结果，失败时是 `-errno`。`SOCKET` 和 `ACCEPT`
  成功时返回新 fd，`READ` 和 `WRITE` 成功时返回处理的字节数；`READ`
  返回 `0` 表示对端已经正常关闭发送方向。

需要并发处理多个操作时，可以连续调用 `net_async_submit()`，或者使用
`net_async_submit_batch()` 批量提交。一次最多取回 64 个完成的典型写法是：

```c
net_async_req *completed[64];
int count = net_async_wait(cq_fd, completed,
                           1,     /* 至少等待 1 个完成 */
                           64,    /* 数组最多容纳 64 个 */
                           1000); /* 整批最多等待 1000 ms */
```

请求所有权规则：

1. `net_async_req_create()` 返回由应用持有的请求。
2. `net_async_submit()` 成功后，请求所有权转移给 CQ。
3. `net_async_submit_batch()` 返回正数时，只转移数组前缀中已接受的请求。
4. `net_async_wait()` 把已完成请求的所有权交回调用者。
5. 完成后直接读取请求的 `type`、`async_fd` 和 `ret`，再调用
   `net_async_req_destroy()` 释放请求。
6. 请求引用的数据缓冲和地址对象必须保持有效，直到请求完成。

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

### 引导式安装（Debian/Ubuntu）

首次安装可以直接运行：

```bash
./setup.sh
```

脚本会检查或安装构建依赖，读取所选网卡的当前队列数，生成本机
`netfast_config.json`，构建 Release 版并安装到 `/usr/local`。安装过程不会
挂载 XDP；第一个以 root 身份加载 `libnetfast.so` 的进程才会挂载。

在可控实验环境中可以显式指定参数：

```bash
./setup.sh --interface ens192 --queues 2 --workers 2 --yes
```

使用 `./setup.sh --help` 查看所有选项，使用 `--dry-run` 只检查而不修改系统。

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

版本库跟踪的 [`config.example.json`](./config.example.json) 是安装模板；本机
`netfast_config.json` 被 Git 忽略，避免上传网卡名、日志路径等机器专用设置。
默认构建的 `libnetfast.so` 在被加载时优先读取进程当前工作目录下的
`netfast_config.json`；文件不存在时再读取
`/usr/local/etc/netfast/netfast_config.json`。

复制模板、按实际环境修改，然后随动态库一起安装：

```bash
cp config.example.json netfast_config.json
editor netfast_config.json
sudo make PROFILE=release install
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
| `logfile` | 是 | 非空日志路径，长度小于 256 字节。父目录存在且权限允许时，NetFast 会创建该文件。 |

`queues` 表示硬件队列 ID 数量，不是每个 worker 的队列数。队列 `q` 分配给
worker `q % thread_num`，因此多队列配置通常至少使用与 worker 数相同的
队列数。配置前先查看网卡能力：

```bash
ethtool -l ens192
ethtool -x ens192
```

单队列网卡应设置 `"queues": 1`，NetFast 会跳过 RSS 配置。多队列时
NetFast 会使用编译内置的默认 key 写入 Toeplitz RSS 间接表；RSS ioctl
失败会记录日志并继续初始化，但流量可能无法均匀分配。非本机 IPv4 和
IPv6 报文转发默认关闭。

配置在动态库构造阶段只解析一次。JSON 格式错误、缺少必填字段、数值
越界、队列不存在或日志路径不可写都会导致初始化失败。修改安装配置
后必须重启应用。重新执行 `make install` 会用当前选中的 `CONFIG_FILE`
覆盖已安装配置。

### XDP 流量接管

XDP 挂载后，`open_if` 中配置的接口上的所有 TCP 和 UDP 流量都会由
NetFast 接管。

## 同步接口

公共头文件同时提供熟悉的 socket 风格调用：

```c
int fd = net_socket(AF_INET, SOCK_STREAM, 0);
net_connect(fd, (struct sockaddr *)&peer, sizeof(peer));
net_write(fd, request, request_len);
net_read(fd, response, response_capacity);
net_close(fd);
```

## 目录结构

```text
lib/       AF_XDP、队列、RSS、frame cache 和基础组件
main/      TCP/IP 协议栈、socket、worker 和异步请求
docs/      协议设计文档
example/   示例程序和测试资源
test/      单元、集成、压力和静态分析工具
```

公共 API 源文件为 [`main/netfast.h`](./main/netfast.h)。
