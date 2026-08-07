# NetFast TCP SACK 实现设计（参考 Linux）

## 1. 文档状态

本文档只描述实现方案，当前 NetFast 源码中不包含 SACK 实现。

Linux 对照基线为 `torvalds/linux` 的 commit `f5098b6bae761e346ebcd9da7f95622c04733cff`。设计遵循 RFC 2018（SACK 选项）和 RFC 6675（基于 SACK 的丢包恢复），D-SACK 作为后续阶段按 RFC 2883 实现。

## 2. 目标与边界

第一阶段完成：

- SYN/SYN-ACK 中的 `SACK Permitted` 协商。
- 接收端根据乱序队列生成 SACK blocks。
- 发送端验证 SACK 选项并更新 scoreboard。
- 使用 scoreboard 判定丢包、选择重传 hole，并与拥塞恢复协同。
- 正确处理累计 ACK、部分 ACK、序号回绕、RTO 和 SACK reneging。

第一阶段不实现 D-SACK、RACK/TLP、FACK、SACK compression 和 TSO/GSO 级别的 SACK shift/merge。但数据结构不应阻碍后续加入这些功能。

## 3. Linux 实现中需要借鉴的核心思路

Linux 不是只保存“最高 SACK 序号”，而是在每个重传队列 skb 上保存状态。`TCPCB_SACKED_ACKED` 表示已被 SACK，`TCPCB_SACKED_RETRANS` 表示已重传，`TCPCB_LOST` 表示已判定丢失。见 [include/net/tcp.h](https://github.com/torvalds/linux/blob/f5098b6bae761e346ebcd9da7f95622c04733cff/include/net/tcp.h#L1089-L1100)。

ACK 输入路径由 `tcp_sacktag_write_queue()` 解析、验证 SACK blocks，再遍历重传队列标记区间。Linux 同时保存接收 SACK cache，避免每个 ACK 都从队头扫描全部队列。见 [tcp_sacktag_write_queue()](https://github.com/torvalds/linux/blob/f5098b6bae761e346ebcd9da7f95622c04733cff/net/ipv4/tcp_input.c#L2220-L2389)。

Linux 把“更新状态/拥塞恢复”和“决定重传哪个 skb”分开：`tcp_fastretrans_alert()` 维护恢复状态，`tcp_xmit_retransmit_queue()` 才从队列中跳过已 SACK/已重传的 skb，发送被标记为 lost 的 hole。见 [tcp_fastretrans_alert()](https://github.com/torvalds/linux/blob/f5098b6bae761e346ebcd9da7f95622c04733cff/net/ipv4/tcp_input.c#L3328-L3454) 和 [tcp_xmit_retransmit_queue()](https://github.com/torvalds/linux/blob/f5098b6bae761e346ebcd9da7f95622c04733cff/net/ipv4/tcp_output.c#L3725-L3790)。

接收端保存最多 4 个 `selective_acks`。新到的乱序区间会合并到旧 block，并把包含最新报文的 block 旋转到第 1 个位置；`RCV.NXT` 推进时删除已被累计 ACK 覆盖的 block。见 [tcp_sack_new_ofo_skb() / tcp_sack_remove()](https://github.com/torvalds/linux/blob/f5098b6bae761e346ebcd9da7f95622c04733cff/net/ipv4/tcp_input.c#L5094-L5229)。

## 4. NetFast 数据结构设计

### 4.1 每个发送 skb 的状态

在 `skbuff.l4_private.tcp` 中增加一个位图，不要用两个彼此独立的 bool：

```c
enum tcp_sack_state {
    TCP_SACKED_ACKED  = 1u << 0,
    TCP_SACKED_RETRANS = 1u << 1,
    TCP_LOST          = 1u << 2,
    TCP_EVER_RETRANS  = 1u << 3,
};
```

每个 skb 必须有准确的 `[seq, end_seq)`，`end_seq` 必须包括 SYN/FIN 消耗的序号空间。SACK 只能确认数据范围，不能把 SYN/FIN 当作普通数据 block。

重要不变式：被 `TCP_SACKED_ACKED` 标记的 skb 仍留在重传队列，只有累计 ACK 覆盖它后才能释放内存并减少 `send_buffer_len`。RFC 6675 明确规定 SACK 信息只是 advisory。

### 4.2 PCB 状态

`tcp_pcb` 建议增加：

```c
bool sack_permitted_sent;
bool sack_permitted_received;

uint32_t sacked_out;       /* 已 SACK 的数据量，第一版可按字节 */
uint32_t lost_out;         /* 已判定丢失的数据量 */
uint32_t retrans_out;      /* 恢复期仍在网络中的重传数据 */
uint32_t highest_sack_seq;
uint32_t recovery_point;   /* 进入 Recovery 时的 snd_nxt */
uint32_t high_retrans_seq;

tcp_sack_block recv_sacks[4];
uint8_t recv_sack_count;
```

第一版可以不实现 Linux 的所有 hint/cache，但应预留 `highest_sack` 或队列遍历 hint，否则大窗口时每个 ACK 都会全队列扫描。Linux 的 PCB 中同时保存 4 个接收 SACK block 和 4 个 cache block，见 [struct tcp_sock](https://github.com/torvalds/linux/blob/f5098b6bae761e346ebcd9da7f95622c04733cff/include/linux/tcp.h#L437-L444)。

## 5. 选项协商和编解码

1. 定义 `SACK Permitted: kind=4, len=2` 和 `SACK: kind=5, len=2+8*N`。
2. 本端只在 SYN 中发送 `SACK Permitted`。被动打开的 SYN-ACK 只在收到的 SYN 包含该选项时回送它。
3. 只有当双方完成协商时，建连后才可发送或使用 SACK 选项。
4. SACK block 的网络格式是大端序 `[left_edge, right_edge)`，长度必须满足 `len >= 10 && (len - 2) % 8 == 0`。
5. 先验证 TCP `doff`、选项边界和 ACK 可接受性，再更新 scoreboard。每个 block 必须满足 `left < right`，且不能覆盖从未发送的序号。所有比较必须使用 `SEQ_LT/SEQ_LEQ/...`，不得直接比较 `uint32_t`。
6. TCP 选项总长最多 40 字节。没有 Timestamp 时最多放 4 个 SACK blocks；有 Timestamp 时最多放 3 个。Linux 在 [tcp_options_write()](https://github.com/torvalds/linux/blob/f5098b6bae761e346ebcd9da7f95622c04733cff/net/ipv4/tcp_output.c#L745-L789) 中编码这两种选项。

`tcp_predict_options_len()` 和 `make_tcp_options()` 必须调用同一个“选项计划”函数，保证预留长度与实际写入完全一致。不要分别重新扫描乱序队列，否则并发收包可使两次结果不同。

## 6. 接收端：生成 SACK blocks

当报文不能推进 `RCV.NXT` 而进入 `unordered_skb_list` 时：

1. 先按现有逻辑修剪接收窗口外和重复部分。
2. 将新范围与已有 block 重叠/相邻的部分合并。
3. 包含“触发本次 ACK 的最新报文”的 block 必须放在第 1 个位置，而不是简单按序号升序输出。Linux 会将命中的 block 旋转到数组首位。
4. 超过 4 个 block 时丢弃最旧/最不重要的 block，不得丢弃本次最新 block。
5. `RCV.NXT` 推进后删除完全落在它左边的 block，若乱序队列为空则清空所有 block。
6. 乱序数据通常应立即 ACK，不应等待普通 delayed-ACK 超时，否则发送端无法及时得到 scoreboard 信息。

## 7. 发送端：scoreboard 更新

处理顺序建议为：

1. 验证 ACK 和所有 SACK blocks。非法 block 单独忽略，不要让一个非法 block 破坏整条连接。Linux 的 `tcp_is_sackblock_valid()` 就是按 block 验证。
2. 先用 SACK 范围标记重传队列，再处理累计 ACK 删除队头。
3. SACK block 可能只覆盖一个 skb 的中间部分。NetFast 的重传入队会合并小 skb，因此“只标记完全被 block 覆盖的 skb”是不正确的。第一版应在 SACK 边界分割 skb，使每个节点均匀地处于已 SACK 或未 SACK 状态；或者额外维护范围 scoreboard。
4. 重复的 SACK block 必须幂等，不能重复增加 `sacked_out`。
5. 累计 ACK 覆盖 skb 后才释放它，同时准确减少 `sacked_out/lost_out/retrans_out`。部分 ACK 需修剪队头并同步修正状态计数。

## 8. 丢包判定与重传选择

不要仅用 `highest_sack_seq - snd_una >= 3*MSS` 就把第一个 hole 判丢。RFC 6675 `IsLost()` 的两个判定是：

- 目标序号之后已有至少 `DupThresh` 个不连续的 SACKed 段；或
- 目标序号之后已 SACK 的字节数超过 `(DupThresh - 1) * SMSS`。

详见 [RFC 6675 的 scoreboard/IsLost/NextSeg](https://www.rfc-editor.org/rfc/rfc6675.html#section-4)。

进入 Recovery 时记录 `recovery_point = snd_nxt`，调用现有拥塞控制的 recovery 入口，并保存独立状态，不要把快速重传伪装成 RTO 超时。

每次 ACK/SACK 更新后，按以下顺序选择下一段：

1. 低于最高 SACK、已判定 lost、未 SACK、未在本轮重传的最小 hole。
2. 拥塞窗口和对端接收窗口允许时的新数据。
3. RFC 6675 允许的保守 hole/rescue retransmission，防止 ACK clock 停顿。

每次发送都要更新 pipe/in-flight 估算和 `TCP_SACKED_RETRANS`，并受 `cwnd - pipe` 限制。单纯“收到一个 SACK 就立即不受 cwnd 限制地重传”会破坏拥塞控制。

## 9. RTO、reneging 和状态恢复

接收端因内存压力丢弃已 SACK 的乱序数据是允许的，因此发送端绝不能因 SACK 而释放重传数据。

Linux 在 RTO 丢包入口检查重传队头是否仍标记为 SACKed；若是，将其视为 reneging，清除队列的 `SACKED_ACKED` 标记并重新标记 lost。见 [tcp_timeout_mark_lost()](https://github.com/torvalds/linux/blob/f5098b6bae761e346ebcd9da7f95622c04733cff/net/ipv4/tcp_input.c#L2520-L2551)。

NetFast 第一版建议采用更保守的做法：真正 RTO 到期时清空旧 scoreboard 标记，从 `snd_una` 重建丢包状态；后续收到新 SACK 时再重建 scoreboard。快速重传不得增加 `retries_out`、执行 RTO 指数退避或进入 RTO Loss 状态。

## 10. 与 NetFast 现有代码的建议接入点

| 文件/函数 | 建议改动 |
|---|---|
| `main/tcp.h` | 增加协商位、Recovery/scoreboard 计数、接收端 block 数组 |
| `main/skbuff.h` | 增加每 skb SACK/lost/retrans 位图，明确 `end_seq` 计算 |
| `parse_tcp_options()` | 仅解析与验证；输出规范化 SACK block 列表 |
| `tcp_input()` ACK 路径 | 按顺序调用 scoreboard update、累计 ACK 清理、丢包判定、Recovery 状态机 |
| `tcp_recv_data()` | 乱序插入/合并时维护 `recv_sacks[]` |
| `tcp_predict_options_len()` / `make_tcp_options()` | 共用一份 options plan，协商并编码 SACK |
| `tcp_output()` | 由 NextSeg 选择 lost hole，跳过 SACKed/已重传 skb |
| `tcp_timer_cb()` | 明确区分 fast recovery 与真正 RTO；RTO 处理 reneging |

所有 scoreboard 改动必须在 socket 所属 worker 中串行执行。API 线程不得直接修改重传队列或 SACK 计数；与现有 timer/output 路径一样，应通过 worker task 调度。

## 11. 建议实现顺序

1. 只加协商和选项长度测试，暂不发 SACK blocks。
2. 实现接收端 block 生成，用抓包验证 newest-first、合并和 Timestamp 长度限制。
3. 实现 scoreboard 标记和累计 ACK 清理，暂不改变重传选择。
4. 加入 RFC 6675 `IsLost/pipe/NextSeg` 和独立 Recovery 状态。
5. 加入 RTO/reneging 处理。
6. 完成与 Linux 双向互操作和长时压力测试后再默认启用。开发期增加每 socket 开关，便于 A/B 对比。

## 12. 必须覆盖的测试

### 选项和非法输入

- SYN/SYN-ACK 的协商四种组合：双方支持、仅主动方、仅被动方、双方都不支持。
- SACK 长度 0…9、非 `2+8*N`、block 反向、越过 `snd_nxt`、过旧 ACK、重叠 block、重复 block。
- Timestamp 开/关时选项总长分别不超过 40 字节，TCP `doff` 正确。
- `snd_una/snd_nxt/RCV.NXT` 跨过 `UINT32_MAX` 时的 block 验证与队列遍历。

### 接收端

- 单个 hole、多个 hole、block 左/右扩展、两个 block 合并、超过 4 个 block。
- 最新乱序段所属 block 始终是第 1 个。
- 缺失段到达并推进 `RCV.NXT` 后，被吃掉的 block 立即删除。
- 乱序 skb 由于接收缓冲压力被删除后，后续 ACK 不再声明它。

### 发送端恢复

- 一个窗口中丢 1、2、3 个段，确认只重传 hole，不重传已 SACK 数据。
- SACK block 只覆盖一个合并 skb 的部分时，分割/范围 scoreboard 正确。
- 纯乱序但不丢包时不应发生伪重传或错误缩减 cwnd。
- 部分 ACK 在 Recovery 期间持续选择下一 hole，累计 ACK 越过 `recovery_point` 后正常退出。
- RTO 时清理/重建 scoreboard，reneging 后数据仍可完整交付。
- 重复 SACK、ACK 重排、重传包的 ACK 不会破坏 `sacked_out/lost_out/retrans_out` 不变式。

### 互操作和稳定性

- NetFast client ↔ Linux server 以及 Linux client ↔ NetFast server 双向测试。
- 用 `tc netem` 分别施加丢包、重排、重复和延迟，对比 SACK 开/关的数据正确性、RTO 数量和吞吐。
- ASan/UBSan 长时运行，重点检查 skb 分割、累计 ACK 释放、scoreboard cache 失效和 socket 关闭。
- 每次测试结束后确认无残留进程、XDP 程序、skb/frame 引用或临时日志。

## 13. 完成标准

实现只有同时满足以下条件才可视为完成：

- SACK 协商与 wire format 通过 Linux 双向互操作。
- 已 SACK 数据在累计 ACK 前从不被释放。
- scoreboard 能表示 skb 的部分范围，不会因 skb 合并丢失精度。
- 丢包判定使用完整 `IsLost` 语义，重传受 cwnd/pipe 限制。
- fast recovery 与 RTO 是两条独立状态路径。
- 序号回绕、部分 ACK、多丢包、纯重排和 reneging 测试全部通过。

## 14. 参考资料

- [RFC 2018: TCP Selective Acknowledgment Options](https://www.rfc-editor.org/rfc/rfc2018.html)
- [RFC 6675: SACK-based Loss Recovery Algorithm](https://www.rfc-editor.org/rfc/rfc6675.html)
- [RFC 2883: D-SACK](https://www.rfc-editor.org/rfc/rfc2883.html)
- [Linux `tcp_input.c`](https://github.com/torvalds/linux/blob/f5098b6bae761e346ebcd9da7f95622c04733cff/net/ipv4/tcp_input.c)
- [Linux `tcp_output.c`](https://github.com/torvalds/linux/blob/f5098b6bae761e346ebcd9da7f95622c04733cff/net/ipv4/tcp_output.c)
- [Linux `include/net/tcp.h`](https://github.com/torvalds/linux/blob/f5098b6bae761e346ebcd9da7f95622c04733cff/include/net/tcp.h)
- [Linux SACK 相关 SNMP 计数器说明](https://docs.kernel.org/networking/snmp_counter.html#sack)
