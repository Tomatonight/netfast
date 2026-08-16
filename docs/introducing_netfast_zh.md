# 我用 C 和 AF_XDP 写了一个用户态 TCP/IP 协议栈：NetFast

Linux 已经有非常成熟的网络协议栈，为什么还要在用户态重新实现一遍 TCP/IP？

这是我开发 NetFast 时经常被问到的问题。对我来说，答案不是“重新发明一个
Linux”，而是想把网卡队列、数据包内存、协议状态机和应用异步接口放进同一个
可以观察、修改和测试的系统中，真正理解一个数据包从网卡到 socket 请求完成
之间发生了什么。

NetFast 是一个使用 C 编写、基于 Linux AF_XDP 的实验性用户态 TCP/IP 协议栈。
它目前支持 IPv4/IPv6、TCP/UDP、多 worker RSS 分流，以及基于完成队列（CQ）的
异步 socket API。项目已经开源：

<https://github.com/Tomatonight/netfast>

## 为什么选择 AF_XDP

传统 socket API 简单、成熟，但应用看到的主要是文件描述符和字节流，协议栈
内部的数据包组织、状态迁移和定时器都在内核中。要研究或定制这些行为，通常
需要修改内核，开发和验证周期比较长。

AF_XDP 提供了另一种路径：XDP 程序可以把网卡收到的数据包重定向到用户态的
RX ring，应用通过 UMEM 管理数据包内存，再通过 TX ring 发回网卡。这样既保留
Linux 提供的驱动和 XDP 基础设施，又能在用户态实现传输层和 socket 语义。

NetFast 会在配置的接口上挂载 XDP。挂载后，该接口上的全部 TCP 和 UDP 流量
由 NetFast 接管，不再交给内核 TCP/IP 数据路径处理。

## NetFast 现在包含什么

项目已经不只是一个收发包示例，而是形成了一个可以运行应用的协议栈：

- IPv4 和 IPv6 上的 TCP、UDP；
- ARP、NDP、ICMP、路由、分片与重组；
- TCP 握手、重传、拥塞控制、窗口扩大、persist 和常用 socket 选项；
- 基于 Netlink 的地址、路由和邻居动态更新；
- AF_XDP copy、zero-copy、UMEM frame cache 和 scatter-gather skbuff；
- Toeplitz RSS 与多 worker 连接所有权；
- 同步 socket 风格 API 和异步完成队列 API；
- 异步 HTTP Server、HTTP 代理、FTP Server 和短连接测试程序。

它仍然是实验性项目。现阶段更适合协议研究、AF_XDP 实验、性能分析和学习，
还不能把它描述成可直接替换 Linux 网络栈的生产组件。

## 整体架构

NetFast 的数据路径可以概括为：

```text
应用程序
  |-- 同步 socket API
  `-- 异步请求 / 完成队列
                 |
              请求路由
                 |
      +----------+----------+
      |          |          |
   Worker 0   Worker 1   Worker N
      |          |          |
      +----- TCP / UDP ------+
             IPv4 / IPv6
           路由 + ARP/NDP
                 |
         skbuff + frame cache
                 |
        AF_XDP RX/TX/CQ rings
                 |
             物理网卡
```

每个 socket 在任意时刻只归一个 worker 管理。应用线程不会直接修改 TCP PCB
或 socket 队列，而是把请求发送给 socket 所属的 worker。网卡 RSS 使用五元组
计算队列，使同一条连接稳定进入同一个 worker。

这套所有权模型减少了数据面共享状态，但也带来了一个实际问题：自动 bind 或
`connect()` 会改变连接五元组，新五元组可能属于另一个 worker。NetFast 为此
实现了 socket 和待处理请求的迁移，而不是假定 socket 创建后永远不会改变归属。

## 为什么又设计了一套异步 API

同步接口很容易使用，但一次调用通常只描述一个操作。高并发服务更希望一次
提交多个 accept、read、write，再批量取得已经完成的请求。

NetFast 的异步接口围绕完成队列工作：

1. 使用 `net_async_create()` 创建 CQ；
2. 使用 `net_async_req_create()` 描述操作；
3. 使用 `net_async_submit()` 或 `net_async_submit_batch()` 提交；
4. 使用 `net_async_wait()` 批量取得完成请求；
5. 直接读取 `req->type`、`req->async_fd` 和 `req->ret`；
6. 使用 `net_async_req_destroy()` 释放请求。

下面是一次最小的异步写入：

```c
net_async_req *request = net_async_req_create(
    socket_fd, NET_ASYNC_WRITE, buffer, length);

net_async_submit(cq_fd, request);

net_async_req *completed = NULL;
if (net_async_wait(cq_fd, &completed, 1, 1, -1) == 1) {
    int operation = completed->type;
    int fd = completed->async_fd;
    int result = completed->ret;

    /* result 成功时为写入字节数，失败时为 -errno。 */
    net_async_req_destroy(completed);
}
```

`net_async_wait()` 返回的是应用之前提交的请求指针，而不是另外构造的结果对象。
因此应用可以通过请求地址关联自己的连接状态，也能直接知道完成的是哪个 fd、
哪种请求以及返回值是什么。

异步 HTTP Server 使用的就是这套模型。从 socket、bind、listen、accept，到
read、write 和 close，全部作为异步请求提交，主循环只负责批量处理完成项。

## 实现过程中最容易出错的地方

真正实现协议栈后，我发现困难往往不在“能不能收到 SYN”，而在各种边界语义。

### 1. TCP 不是简单的序号递增

TCP 序号是 32 位的，长连接传输超过 4 GiB 后会发生回绕。比较 ACK、判断重传
区间、释放发送队列时都不能直接使用普通整数大小关系。FTP 大文件测试很适合
发现这类问题，因为数据正确性和最终文件长度都可以直接校验。

### 2. write 完成不等于数据已经被 ACK

应用写入、协议栈接收数据、报文发到网卡以及对端确认，是不同的完成时刻。
关闭连接时还要处理发送队列、FIN、`SO_LINGER` 和异常退出。把这些语义混在
一起，很容易造成尾部数据丢失，或者 close 永远无法结束。

### 3. 邻居解析是动态过程

路由存在不代表下一跳 MAC 已经可用。当前实现会通过内核邻居机制触发解析，
并通过 Netlink 获取邻居状态。解析中的报文可以丢弃但不立即向 socket 返回
错误；只有邻居进入 `NUD_FAILED` 后才报告不可达。

### 4. 性能优化必须建立在正确性之上

tuple hash、frame cache、TX completion、fd 引用和完成通知都可能成为热点，
但每次简化都可能引入 ABA、生命周期或并发问题。因此项目同时保留协议回环、
异步多 waiter、Netlink 事件、静态分析和长时间传输测试。

## 如何运行

在 Debian/Ubuntu 环境中，可以从引导脚本开始：

```bash
git clone https://github.com/Tomatonight/netfast.git
cd netfast
./setup.sh
```

也可以指定接口、队列数和 worker 数：

```bash
./setup.sh --interface <interface> --queues 2 --workers 2 --yes
```

构建并启动异步 HTTP Server：

```bash
make PROFILE=release -j$(nproc) http-async
sudo ./build/example/http_async_server
```

服务器监听 `0.0.0.0:8888`，提供主页、`/api/status` 和 `/healthz`。配置文件、
依赖和接口队列要求可以在项目 README 中查看。

## 接下来准备做什么

NetFast 后续仍有很多工作：继续完善 TCP 边界行为，建立不同网卡和队列配置下
可复现的性能基线，补充故障注入测试，并进一步降低短连接场景中的 fd、请求和
完成通知开销。

我也希望得到几类反馈：

- 在不同 AF_XDP 驱动和网卡上的运行结果；
- TCP/UDP 语义或边界条件方面的问题；
- 异步完成队列 API 是否足够直观；
- 可复现的 Linux socket 对比数据；
- 代码审查、测试用例和功能贡献。

如果你也对 Linux 网络、AF_XDP、TCP 状态机或用户态协议栈感兴趣，欢迎查看
代码、运行示例并提交 Issue：

<https://github.com/Tomatonight/netfast>
