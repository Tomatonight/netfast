# NetFast TCP SACK：隔离实现、测试结果与完整 diff

## 状态

本文件包含一份已经在临时工作副本中编译和测试的 SACK 实现 diff。按照要求，这份 diff **没有应用到当前源代码**；当前 `main/`、`lib/`、`example/`、`test/` 仍保持无 SACK 实现的状态。

设计背景和 Linux 对照见 [tcp_sack_design.md](./tcp_sack_design.md)。

## 隔离验证结果

临时工作副本：`/tmp/netfast-sack.Ppuf7T/work`（仅用于本次验证，不是交付源码）。

- `make -j1 PROFILE=debug build`：通过。
- TCP 单元测试：39/39 通过。
- 确定性丢包测试：连续 5 次通过；最终代码调整后又复测 1 次通过。
- 每次测试发送 24,000 字节，主动丢弃首个 TCP 数据段。
- 每次均完成 SACK Permitted 协商、发送和解析 SACK block，并发生 1 次选择性 hole 重传。
- 每次 `rto-events=0`，证明恢复没有等待真正 RTO。
- 数据逐字节校验通过，单次耗时 0 ms（虚拟 IPv6 loopback）。
- BTF `-EINVAL` 是项目现有的可选 BTF 加载警告，不影响测试。

测试输出：

```text
PASS tcp-sack blocks-sent=1 blocks-received=1 selective-retransmits=1 rto-events=0 bytes=24000 elapsed-ms=0
```

## 实现范围

- SYN/SYN-ACK 的 SACK Permitted 协商。
- 接收端最多 4 个 newest-first `[left,right)` block，支持相邻/重叠区间合并和 `RCV.NXT` 推进清理。
- 无 Timestamp 时最多编码 4 个 block；有 Timestamp 时最多 3 个，TCP options 不超过 40 字节。
- 发送端每 skb 的 SACKED/RETRANS/LOST/EVER_RETRANS 状态。
- 在 SACK 边界处分割已合并的纯数据 skb，保证部分覆盖精度。
- 基于已 SACK 字节数的保守丢包判断、选择性 hole 重传和显式 fast-recovery 状态。
- 快速重传与真实 RTO 分离；真实 RTO 清除旧 scoreboard，处理 receiver reneging。
- SACK ACK 在修改 scoreboard 前检查 ACK 范围和接收序号窗口。
- 确定性 loopback 丢包测试钩子及端到端测试。

## 使用方法

由于当前 `main/tcp.h` 混有不同换行格式，下方针对该文件使用零上下文 addition hunks。建议提取 diff 后先执行：

```bash
git apply --check --ignore-space-change --ignore-whitespace tcp-sack.diff
git apply --ignore-space-change --ignore-whitespace tcp-sack.diff
```

文档中的 diff 已实际通过上述 `git apply --check` 和标准 `patch --dry-run -p1`。

## 完整 unified diff

```diff
--- a/main/tcp.h
+++ b/main/tcp.h
@@ -20,0 +21,16 @@
+#define TCP_OPTION_SACK_PERMITTED 4
+#define TCP_OPTION_SACK           5
+#define TCP_MAX_SACK_BLOCKS       4
+
+typedef struct tcp_sack_block {
+    uint32_t left;
+    uint32_t right;
+} tcp_sack_block;
+
+enum tcp_sack_state {
+    TCP_SACKED_ACKED  = 1u << 0,
+    TCP_SACKED_RETRANS = 1u << 1,
+    TCP_LOST          = 1u << 2,
+    TCP_EVER_RETRANS  = 1u << 3,
+};
+
@@ -135,0 +152,13 @@
+    /* Receiver SACK blocks are newest-first, as required by RFC 2018. */
+    tcp_sack_block recv_sacks[TCP_MAX_SACK_BLOCKS];
+    uint8_t recv_sack_count;
+
+    /* Sender scoreboard summary and diagnostics. */
+    uint32_t sack_highest;
+    uint32_t sack_blocks_sent;
+    uint32_t sack_blocks_received;
+    uint32_t sack_retransmits;
+    uint32_t sack_rto_events;
+    uint32_t recovery_point;
+    bool sack_in_recovery;
+
@@ -161,0 +191 @@
+                uint32_t fast_retransmit_trigger:1;
@@ -173,0 +204 @@
+        uint32_t peer_sack_ok:1; // peer advertised SACK Permitted in SYN
--- a/main/skbuff.h
+++ b/main/skbuff.h
@@ -37,6 +37,7 @@
 		struct {
 			uint32_t seq;
 			uint8_t flag;
+			uint8_t sack_state;
 		} tcp;
 		struct {
 			union {
--- a/main/tcp.c
+++ b/main/tcp.c
@@ -34,6 +34,13 @@
 static int parse_tcp_options(tcp_pcb* pcb, tcp_hdr* hdr);
 static int set_tcp_socket_route(Socket* sock, const uint8_t* dip, uint32_t scope_id);
 static skbuff* tcp_retransmit_enqueue(tcp_pcb* pcb, skbuff* skb);
+static void tcp_sack_receiver_update(tcp_pcb* pcb, uint32_t left, uint32_t right);
+static void tcp_sack_receiver_prune(tcp_pcb* pcb);
+static bool tcp_sack_split_queue_at(tcp_pcb* pcb, uint32_t seq);
+static void tcp_sack_process_option(tcp_pcb* pcb, const uint8_t *data,
+                                    uint8_t len);
+static skbuff* tcp_sack_next_hole(tcp_pcb* pcb);
+static void tcp_sack_clear_scoreboard(tcp_pcb* pcb);
 
 static inline void tcp_recv_queue_change(tcp_pcb* pcb)
 {
@@ -138,6 +145,209 @@
     return skb;
 }
 
+static inline uint32_t tcp_skb_seq_len(const skbuff *skb)
+{
+    return skb_data_len((skbuff *)skb)
+         + ((skb->l4_private.tcp.flag & TCP_FLAG_SYN) ? 1u : 0u)
+         + ((skb->l4_private.tcp.flag & TCP_FLAG_FIN) ? 1u : 0u);
+}
+
+static inline bool tcp_sack_blocks_touch(const tcp_sack_block *a,
+                                         const tcp_sack_block *b)
+{
+    return SEQ_LEQ(a->left, b->right) && SEQ_GEQ(a->right, b->left);
+}
+
+static void tcp_sack_receiver_update(tcp_pcb* pcb, uint32_t left, uint32_t right)
+{
+    if (!pcb->tcp_flag.peer_sack_ok || !SEQ_LT(left, right))
+        return;
+
+    tcp_sack_block merged = { .left = left, .right = right };
+    bool changed;
+    do {
+        changed = false;
+        for (uint32_t i = 0; i < pcb->recv_sack_count; i++) {
+            tcp_sack_block *old = &pcb->recv_sacks[i];
+            if (!tcp_sack_blocks_touch(&merged, old))
+                continue;
+            uint32_t old_left = merged.left;
+            uint32_t old_right = merged.right;
+            if (SEQ_LT(old->left, merged.left))
+                merged.left = old->left;
+            if (SEQ_GT(old->right, merged.right))
+                merged.right = old->right;
+            changed |= old_left != merged.left || old_right != merged.right;
+        }
+    } while (changed);
+
+    tcp_sack_block next[TCP_MAX_SACK_BLOCKS];
+    uint32_t count = 1;
+    next[0] = merged; /* RFC 2018: block containing newest segment first. */
+    for (uint32_t i = 0; i < pcb->recv_sack_count &&
+                         count < TCP_MAX_SACK_BLOCKS; i++) {
+        if (!tcp_sack_blocks_touch(&merged, &pcb->recv_sacks[i]))
+            next[count++] = pcb->recv_sacks[i];
+    }
+    memcpy(pcb->recv_sacks, next, count * sizeof(next[0]));
+    pcb->recv_sack_count = (uint8_t)count;
+}
+
+static void tcp_sack_receiver_prune(tcp_pcb* pcb)
+{
+    uint32_t count = 0;
+    for (uint32_t i = 0; i < pcb->recv_sack_count; i++) {
+        tcp_sack_block block = pcb->recv_sacks[i];
+        if (!SEQ_GT(block.right, pcb->rcv_nxt))
+            continue;
+        if (SEQ_LT(block.left, pcb->rcv_nxt))
+            block.left = pcb->rcv_nxt;
+        pcb->recv_sacks[count++] = block;
+    }
+    pcb->recv_sack_count = (uint8_t)count;
+}
+
+static void tcp_sack_mark_lost(tcp_pcb* pcb)
+{
+    uint32_t byte_threshold = pcb->snd_mss > UINT32_MAX / 2u
+                            ? UINT32_MAX : pcb->snd_mss * 2u;
+
+    QUEUE_FOR_EACH(&pcb->retransmit_queue, node) {
+        skbuff *candidate = SKB_FROM_QUEUE_NODE(node);
+        uint32_t state = candidate->l4_private.tcp.sack_state;
+        if ((state & (TCP_SACKED_ACKED | TCP_SACKED_RETRANS)) ||
+            !SEQ_LT(candidate->l4_private.tcp.seq, pcb->sack_highest))
+            continue;
+
+        uint32_t sacked_bytes = 0;
+        bool after_candidate = false;
+        QUEUE_FOR_EACH(&pcb->retransmit_queue, later_node) {
+            skbuff *later = SKB_FROM_QUEUE_NODE(later_node);
+            if (later == candidate) {
+                after_candidate = true;
+                continue;
+            }
+            if (!after_candidate)
+                continue;
+            if (!SEQ_LT(later->l4_private.tcp.seq, pcb->sack_highest))
+                break;
+            if (later->l4_private.tcp.sack_state & TCP_SACKED_ACKED) {
+                sacked_bytes += tcp_skb_seq_len(later);
+            }
+        }
+        if (sacked_bytes > byte_threshold)
+            candidate->l4_private.tcp.sack_state |= TCP_LOST;
+    }
+}
+
+static bool tcp_sack_split_queue_at(tcp_pcb* pcb, uint32_t seq)
+{
+    QUEUE_FOR_EACH(&pcb->retransmit_queue, node) {
+        skbuff *skb = SKB_FROM_QUEUE_NODE(node);
+        uint8_t flags = skb->l4_private.tcp.flag;
+        if (flags & (TCP_FLAG_SYN | TCP_FLAG_FIN))
+            continue; /* Control sequence space is never SACKed. */
+
+        uint32_t start = skb->l4_private.tcp.seq;
+        uint32_t end = start + skb_data_len(skb);
+        if (!SEQ_GT(seq, start) || !SEQ_LT(seq, end))
+            continue;
+
+        skbuff *tail = skb_split(skb, seq - start);
+        if (!tail)
+            return false;
+        tail->l4_private.tcp.seq = seq;
+        add_list_node(&skb->queue_node, &tail->queue_node);
+        pcb->retransmit_queue.element_number++;
+        return true;
+    }
+    return true;
+}
+
+static void tcp_sack_process_option(tcp_pcb* pcb, const uint8_t *data,
+                                    uint8_t len)
+{
+    if (!pcb->tcp_flag.peer_sack_ok || len < 10 || ((len - 2u) % 8u) != 0)
+        return;
+
+    uint32_t block_count = (len - 2u) / 8u;
+    uint32_t accepted = 0;
+    for (uint32_t b = 0; b < block_count; b++) {
+        uint32_t left_n, right_n;
+        memcpy(&left_n, data + b * 8u, sizeof(left_n));
+        memcpy(&right_n, data + b * 8u + 4u, sizeof(right_n));
+        uint32_t left = ntohl(left_n);
+        uint32_t right = ntohl(right_n);
+
+        if (!SEQ_LT(left, right) || SEQ_LEQ(right, pcb->snd_una) ||
+            SEQ_GEQ(left, pcb->snd_nxt) || SEQ_GT(right, pcb->snd_nxt))
+            continue;
+
+        if (!accepted || SEQ_GT(right, pcb->sack_highest))
+            pcb->sack_highest = right;
+        accepted++;
+
+        /* NetFast can coalesce writes in the retransmit queue. Split at SACK
+         * boundaries so a per-skb state bit still represents an exact range. */
+        if (!tcp_sack_split_queue_at(pcb, left) ||
+            !tcp_sack_split_queue_at(pcb, right))
+            continue;
+
+        QUEUE_FOR_EACH(&pcb->retransmit_queue, node) {
+            skbuff *skb = SKB_FROM_QUEUE_NODE(node);
+            uint32_t start = skb->l4_private.tcp.seq;
+            uint32_t end = start + tcp_skb_seq_len(skb);
+            if (!(skb->l4_private.tcp.flag & (TCP_FLAG_SYN | TCP_FLAG_FIN)) &&
+                SEQ_GEQ(start, left) && SEQ_LEQ(end, right)) {
+                skb->l4_private.tcp.sack_state |= TCP_SACKED_ACKED;
+                skb->l4_private.tcp.sack_state &= ~TCP_LOST;
+            }
+        }
+    }
+
+    if (!accepted)
+        return;
+    pcb->sack_blocks_received += accepted;
+    tcp_sack_mark_lost(pcb);
+    if (tcp_sack_next_hole(pcb)) {
+        if (!pcb->sack_in_recovery) {
+            pcb->sack_in_recovery = true;
+            pcb->recovery_point = pcb->snd_nxt;
+            tcp_cong_enter_recovery(pcb);
+        }
+        pcb->tcp_flag.fast_retransmit_trigger = 1;
+        tcp_update_timer(pcb, &pcb->retransmit_deadline_ms,
+                         get_current_time_ms(), true);
+    }
+}
+
+static skbuff* tcp_sack_next_hole(tcp_pcb* pcb)
+{
+    if (!pcb->tcp_flag.peer_sack_ok ||
+        !SEQ_GT(pcb->sack_highest, pcb->snd_una))
+        return NULL;
+
+    QUEUE_FOR_EACH(&pcb->retransmit_queue, node) {
+        skbuff *skb = SKB_FROM_QUEUE_NODE(node);
+        uint8_t state = skb->l4_private.tcp.sack_state;
+        if (!SEQ_LT(skb->l4_private.tcp.seq, pcb->sack_highest))
+            break;
+        if ((state & TCP_LOST) &&
+            !(state & (TCP_SACKED_ACKED | TCP_SACKED_RETRANS)))
+            return skb;
+    }
+    return NULL;
+}
+
+static void tcp_sack_clear_scoreboard(tcp_pcb* pcb)
+{
+    pcb->sack_highest = 0;
+    QUEUE_FOR_EACH(&pcb->retransmit_queue, node) {
+        skbuff *skb = SKB_FROM_QUEUE_NODE(node);
+        skb->l4_private.tcp.sack_state = 0;
+    }
+}
+
 static inline uint32_t tcp_predict_options_len(const tcp_pcb* pcb, uint8_t flags)
 {
     uint32_t opt_len = 0;
@@ -148,6 +358,10 @@
         /* MSS(4) */
         opt_len += 4u;
 
+        /* Initial SYN always advertises SACK. SYN-ACK only echoes support. */
+        if (!(flags & TCP_FLAG_ACK) || pcb->tcp_flag.peer_sack_ok)
+            opt_len += 4u; /* SACK Permitted(2) + NOP padding(2) */
+
         /* WS：kind=3,len=3，通常用 NOP 补齐到 4 */
         opt_len += 4u;
 
@@ -158,6 +372,12 @@
         if (pcb->tcp_flag.peer_ts_ok)
             opt_len += 12u;
 
+        if ((flags & TCP_FLAG_ACK) && pcb->tcp_flag.peer_sack_ok &&
+            pcb->recv_sack_count) {
+            uint32_t max_blocks = pcb->tcp_flag.peer_ts_ok ? 3u : 4u;
+            uint32_t count = min((uint32_t)pcb->recv_sack_count, max_blocks);
+            opt_len += 2u + count * 8u;
+        }
     }
 
     /* 防御性对齐（虽然上述都是 4 的倍数） */
@@ -284,10 +504,14 @@
             return false; /* entirely outside window */
         }
         skb_truncate(skb, skb_data_len(skb) - overlap);
+        data_len = skb_data_len(skb);
     }
 
+    bool out_of_order = SEQ_GT(seq, pcb->rcv_nxt);
+
     skbuff* queue_skb = skb;
     INC_REF(queue_skb);
+    queue_skb->l4_private.tcp.seq = seq;
     queue_skb->tcp_list.element = (uint64_t)queue_skb;
 
     /* Insert into unordered list, ordered by tcp.seq.  Equal sequence
@@ -301,6 +525,9 @@
         return false;
     }
 
+    if (out_of_order)
+        tcp_sack_receiver_update(pcb, seq, seq + data_len);
+
     /* Move in-order segments from unordered list to recv queue */
     skbuff* it;
     list_node* tmp;
@@ -331,6 +558,7 @@
         pcb->sock->recv_buffer_len += it_data_len;
         pcb->rcv_nxt += it_data_len;
     }
+    tcp_sack_receiver_prune(pcb);
     socket_notify_event(pcb->sock, notify_data_read);
     tcp_recv_queue_change(pcb);
     return true;
@@ -425,8 +653,16 @@
                 pcb->connect_timeout *= 2;
                 tcp_update_timer(pcb, &pcb->retransmit_deadline_ms,
                                 get_current_time_ms() + pcb->connect_timeout, true);
+            } else if (pcb->tcp_flag.fast_retransmit_trigger) {
+                /* Fast/SACK recovery is not an RTO. Keep the real RTO armed
+                 * without consuming retry budget or applying backoff. */
+                tcp_update_timer(pcb, &pcb->retransmit_deadline_ms,
+                                 get_current_time_ms() + pcb->retransmit_timeout,
+                                 false);
             } else {
                 /* Data retransmit: exponential backoff + limit */
+                pcb->sack_rto_events++;
+                pcb->sack_in_recovery = false;
                 if (pcb->retries_out++ >= pcb->retries_max) {
                     sock->error = ETIMEDOUT;
                     destroy_tcp_socket(sock);
@@ -435,6 +671,9 @@
                 /* Enter loss on first RTO retransmit */
                 if (pcb->retries_out == 1)
                     tcp_cong_enter_loss(pcb);
+                /* The receiver may renege on SACKed data under memory
+                 * pressure. A real RTO no longer trusts the old scoreboard. */
+                tcp_sack_clear_scoreboard(pcb);
                 pcb->retransmit_timeout = min(pcb->retransmit_timeout * 2,
                                             TCP_RETRANSMIT_TIMEOUT_MS_MAX);
                 tcp_update_timer(pcb, &pcb->retransmit_deadline_ms,
@@ -732,6 +971,7 @@
                     pcb->sock->send_buffer_len -= consumed;
                 }
                 skb->l4_private.tcp.seq = ack;
+                skb->l4_private.tcp.sack_state = 0;
                 break;
             }
         }
@@ -744,6 +984,8 @@
         pcb->retransmit_timeout = tcp_metrics_rto(pcb->metrics);
         socket_notify_event(pcb->sock, notify_data_write);
     }
+    if (pcb->sack_highest && !SEQ_GT(pcb->sack_highest, ack))
+        tcp_sack_clear_scoreboard(pcb);
     /* Stop retransmit timer if queue is now empty */
     if (pcb->retransmit_queue.element_number == 0) {
         tcp_update_timer(pcb, &pcb->retransmit_deadline_ms, TCP_TIMER_STOP, true);
@@ -1341,11 +1583,16 @@
             if(SEQ_LT(pcb->snd_una, ack)){
                 //ack new data
                 uint32_t acked_bytes = ack - pcb->snd_una;
+                bool was_recovery = pcb->sack_in_recovery;
+                bool recovery_complete = was_recovery &&
+                    SEQ_GEQ(ack, pcb->recovery_point);
                 pcb->snd_una = ack;
                 tcp_update_retransmit_queue(pcb);
                 /* Reset duplicate ACK tracking on new data ACK */
-                if (pcb->last_ack_repeat >= 3)
+                if (recovery_complete) {
                     tcp_cong_leave_recovery(pcb);
+                    pcb->sack_in_recovery = false;
+                }
                 pcb->last_ack = ack;
                 pcb->last_ack_repeat = 0;
 
@@ -1395,6 +1642,15 @@
                  * ACK input path. */
                 tcp_maybe_schedule_output(pcb);
 
+                if (was_recovery && !recovery_complete) {
+                    tcp_sack_mark_lost(pcb);
+                    if (tcp_sack_next_hole(pcb)) {
+                        pcb->tcp_flag.fast_retransmit_trigger = 1;
+                        tcp_update_timer(pcb, &pcb->retransmit_deadline_ms,
+                                         get_current_time_ms(), true);
+                    }
+                }
+
             }else{
                 //ack is repeat (duplicate ACK) — fast retransmit detection
                 uint32_t new_wnd = window << pcb->snd_wnd_scale;
@@ -1410,9 +1666,14 @@
                     pcb->last_ack_repeat++;
                     if (pcb->last_ack_repeat == 3) {
 
+                        if (!pcb->sack_in_recovery) {
+                            pcb->sack_in_recovery = true;
+                            pcb->recovery_point = pcb->snd_nxt;
+                            tcp_cong_enter_recovery(pcb);
+                        }
+                        pcb->tcp_flag.fast_retransmit_trigger = 1;
                         tcp_update_timer(pcb, &pcb->retransmit_deadline_ms,
                                          get_current_time_ms(), false);
-                        tcp_cong_enter_recovery(pcb);
                         DEBUG_LOG("TCP fast retransmit triggered, dupack=%u",
                                  pcb->last_ack_repeat);
                     }
@@ -1495,8 +1756,9 @@
     case TCP_STATE_FIN_WAIT_1:
     case TCP_STATE_FIN_WAIT_2:
         if(data_len > 0){
+            bool out_of_order = SEQ_GT(seq, pcb->rcv_nxt);
             if (tcp_recv_data(pcb, skb)) {
-                if (++pcb->ack_pending_segments >= 3) {
+                if (out_of_order || ++pcb->ack_pending_segments >= 3) {
                     tcp_update_timer(pcb, &pcb->ack_deadline_ms,
                                      get_current_time_ms(), true);
                 } else {
@@ -1627,10 +1889,15 @@
     skbuff* skb=NULL;
     skbuff* send_skb = NULL;
     bool add_retransmit = false;
+    bool sack_retransmit = false;
     uint32_t truncate_skb_len = 0;
 
     if(pcb->tcp_flag.retransmit_trigger){
-        skb = SKB_FROM_QUEUE_NODE(get_queue_first(&pcb->retransmit_queue));
+        skb = tcp_sack_next_hole(pcb);
+        if (skb)
+            sack_retransmit = true;
+        else
+            skb = SKB_FROM_QUEUE_NODE(get_queue_first(&pcb->retransmit_queue));
         if(!skb) {
             return 0;
         }
@@ -1730,6 +1997,11 @@
         ? ipv6_output(send_skb) : ipv4_output(send_skb);
     if(ret >= 0){
         tcp_update_timer(pcb, &pcb->ack_deadline_ms, TCP_TIMER_STOP, false);
+        if (sack_retransmit) {
+            skb->l4_private.tcp.sack_state |=
+                TCP_SACKED_RETRANS | TCP_EVER_RETRANS;
+            pcb->sack_retransmits++;
+        }
     }
     PUT_REF(send_skb);
 
@@ -2762,6 +3034,13 @@
         memcpy(opt_ptr + pos, &mss_n, sizeof(mss_n));
         pos += sizeof(mss_n);
 
+        if (syn_flag || pcb->tcp_flag.peer_sack_ok) {
+            opt_ptr[pos++] = TCP_OPTION_SACK_PERMITTED;
+            opt_ptr[pos++] = 2;
+            opt_ptr[pos++] = 1;
+            opt_ptr[pos++] = 1;
+        }
+
         /* Window Scale（若启用）：根据接收缓冲区大小计算缩放因子 */
         {
             uint32_t rcv_buf = pcb->sock->recv_buffer_len_max;
@@ -2801,6 +3080,23 @@
         pos += sizeof(tsecr_n);
     }
 
+    if (!(flags & TCP_FLAG_SYN) && (flags & TCP_FLAG_ACK) &&
+        pcb->tcp_flag.peer_sack_ok && pcb->recv_sack_count) {
+        uint32_t max_blocks = pcb->tcp_flag.peer_ts_ok ? 3u : 4u;
+        uint32_t count = min((uint32_t)pcb->recv_sack_count, max_blocks);
+        opt_ptr[pos++] = TCP_OPTION_SACK;
+        opt_ptr[pos++] = (uint8_t)(2u + count * 8u);
+        for (uint32_t i = 0; i < count; i++) {
+            uint32_t left = htonl(pcb->recv_sacks[i].left);
+            uint32_t right = htonl(pcb->recv_sacks[i].right);
+            memcpy(opt_ptr + pos, &left, sizeof(left));
+            pos += sizeof(left);
+            memcpy(opt_ptr + pos, &right, sizeof(right));
+            pos += sizeof(right);
+        }
+        pcb->sack_blocks_sent += count;
+    }
+
     /* 最终填充到 4 字节对齐 */
     while (((sizeof(tcp_hdr) + pos) % 4) != 0) {
         opt_ptr[pos++] = 1; /* NOP */
@@ -2862,6 +3158,23 @@
             }
             pcb->snd_wnd_scale = ws;
         }
+        else if (kind == TCP_OPTION_SACK_PERMITTED && len == 2 &&
+                 is_handshake) {
+            pcb->tcp_flag.peer_sack_ok = 1;
+        }
+        else if (kind == TCP_OPTION_SACK && !is_handshake &&
+                 (hdr->flags & TCP_FLAG_ACK)) {
+            uint32_t ack = ntohl(hdr->ack_seq);
+            uint32_t seq = ntohl(hdr->seq);
+            bool seq_ok = seq == pcb->rcv_nxt ||
+                (pcb->rcv_wnd && SEQ_GEQ(seq, pcb->rcv_nxt) &&
+                 SEQ_LT(seq, pcb->rcv_nxt + pcb->rcv_wnd));
+            /* parse_tcp_options() runs before the main segment validation;
+             * do not let an out-of-window segment mutate the scoreboard. */
+            if (seq_ok && SEQ_GEQ(ack, pcb->snd_una) &&
+                SEQ_LEQ(ack, pcb->snd_nxt))
+                tcp_sack_process_option(pcb, &opt[i + 2], len);
+        }
         else if (kind == 8 && len == 10) { /* Timestamps (RFC 7323) */
             /* 格式：kind(1)=8, len(1)=10, TSval(4), TSecr(4) */
             uint32_t tsval_n = 0;
--- a/main/loopback.h
+++ b/main/loopback.h
@@ -21,4 +21,7 @@
 
 int loopback_init(void);
 
+/* Test hook: discard the next outbound loopback TCP data segment. */
+void loopback_test_drop_tcp_data_once(void);
+
 #endif /* LOOPBACK_H */
--- a/main/loopback.c
+++ b/main/loopback.c
@@ -10,11 +10,48 @@
 #include "ipv6.h"
 #include "log.h"
 #include "route_arp.h"
+#include "tcp.h"
+
+static atomic_uint loopback_drop_tcp_data;
+
+void loopback_test_drop_tcp_data_once(void)
+{
+    atomic_store_explicit(&loopback_drop_tcp_data, 1, memory_order_release);
+}
+
+static bool loopback_is_tcp_data(const skbuff *skb)
+{
+    if (!skb || skb->protocol != IPPROTO_TCP)
+        return false;
+
+    uint32_t total = skb_data_len((skbuff *)skb);
+    const uint8_t *start = skb_start((skbuff *)skb);
+    uint32_t ip_len;
+    if (skb->family == AF_INET6) {
+        ip_len = IPV6_HDR_LEN;
+    } else {
+        if (total < sizeof(ipv4_hdr))
+            return false;
+        const ipv4_hdr *ip = (const ipv4_hdr *)start;
+        ip_len = (uint32_t)IPV4_VHL_IHL(ip->vhl) * 4u;
+    }
+    if (total < ip_len + sizeof(tcp_hdr))
+        return false;
+    const tcp_hdr *tcp = (const tcp_hdr *)(start + ip_len);
+    uint32_t tcp_len = (uint32_t)(tcp->doff_res_flags >> 4) * 4u;
+    return tcp_len >= sizeof(tcp_hdr) && total > ip_len + tcp_len;
+}
 
 int loopback_send(if_info* info, skbuff* skb)
 {
     (void)info;
     skb->flag.is_forward = 0;
+    if (loopback_is_tcp_data(skb)) {
+        unsigned armed = 1;
+        if (atomic_compare_exchange_strong_explicit(&loopback_drop_tcp_data,
+                &armed, 0, memory_order_acq_rel, memory_order_relaxed))
+            return 0;
+    }
     return skb->family == AF_INET6 ? ipv6_recv(skb) : ipv4_recv(skb);
 }
 int loopback_recv(if_info* info, skbuff* skb){
--- a/example/example_1/Makefile
+++ b/example/example_1/Makefile
@@ -4,7 +4,7 @@
 LDFLAGS ?= -L../../build "-Wl,-rpath,$(abspath ../../build)"
 LDLIBS ?= -lnetfast -lbpf -lelf -lz -pthread -lxdp -lcjson
 
-all: http_proxy web_server error_code_test api_state_fuzz udp_test udp6_api_test udp6_peer_api_test udp6_frag_real_test tcp6_api_test tcp6_peer_api_test ipv6_1g_test frag_test udp_recv_modes_test udp_epoll_test udp_perf_test tcp_test netfast_bench
+all: http_proxy web_server error_code_test api_state_fuzz udp_test udp6_api_test udp6_peer_api_test udp6_frag_real_test tcp6_api_test tcp6_peer_api_test ipv6_1g_test frag_test udp_recv_modes_test udp_epoll_test udp_perf_test tcp_test tcp_sack_test netfast_bench
 
 http_proxy: http_proxy.c
 	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS) $(LDLIBS)
@@ -54,8 +54,11 @@
 tcp_test: tcp_test.c
 	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS) $(LDLIBS)
 
+tcp_sack_test: tcp_sack_test.c
+	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS) $(LDLIBS)
+
 netfast_bench: netfast_bench.c
 	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS) $(LDLIBS)
 
 clean:
-	rm -f http_proxy web_server error_code_test api_state_fuzz udp_test udp6_api_test udp6_peer_api_test udp6_frag_real_test tcp6_api_test tcp6_peer_api_test ipv6_1g_test frag_test udp_recv_modes_test udp_epoll_test udp_perf_test tcp_test netfast_bench
+	rm -f http_proxy web_server error_code_test api_state_fuzz udp_test udp6_api_test udp6_peer_api_test udp6_frag_real_test tcp6_api_test tcp6_peer_api_test ipv6_1g_test frag_test udp_recv_modes_test udp_epoll_test udp_perf_test tcp_test tcp_sack_test netfast_bench
--- a/example/example_1/tcp_sack_test.c
+++ b/example/example_1/tcp_sack_test.c
@@ -0,0 +1,150 @@
+#include <arpa/inet.h>
+#include <errno.h>
+#include <stdio.h>
+#include <stdlib.h>
+#include <string.h>
+#include <sys/socket.h>
+#include <sys/time.h>
+
+#include "netfast.h"
+#include "base.h"
+#include "fd_entry.h"
+#include "loopback.h"
+#include "socket.h"
+#include "tcp.h"
+
+#define SACK_TEST_PORT 42341
+#define SACK_TEST_MSS 1200u
+#define SACK_TEST_BYTES (SACK_TEST_MSS * 20u)
+
+static int make_listener(void)
+{
+    int fd = net_socket(AF_INET6, SOCK_STREAM, 0);
+    if (fd < 0)
+        return -1;
+    int one = 1;
+    (void)net_setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
+    struct sockaddr_in6 addr = {
+        .sin6_family = AF_INET6,
+        .sin6_port = htons(SACK_TEST_PORT),
+        .sin6_addr = IN6ADDR_LOOPBACK_INIT,
+    };
+    if (net_bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
+        net_listen(fd, 16) < 0) {
+        net_close(fd);
+        return -1;
+    }
+    return fd;
+}
+
+static tcp_pcb *hold_pcb(int fd, fd_entry **held)
+{
+    *held = hold_fd_entry(fd);
+    Socket *sock = *held ? (Socket *)(*held)->value : NULL;
+    return sock ? (tcp_pcb *)sock->pcb : NULL;
+}
+
+static int read_exact(int fd, uint8_t *buf, uint32_t len)
+{
+    uint32_t off = 0;
+    while (off < len) {
+        int n = net_read(fd, buf + off, len - off);
+        if (n <= 0)
+            return -1;
+        off += (uint32_t)n;
+    }
+    return 0;
+}
+
+int main(void)
+{
+    int listener = -1, client = -1, server = -1;
+    fd_entry *client_entry = NULL, *server_entry = NULL;
+    uint8_t *tx = NULL, *rx = NULL;
+    int result = 1;
+
+    listener = make_listener();
+    client = net_socket(AF_INET6, SOCK_STREAM, 0);
+    if (listener < 0 || client < 0)
+        goto out;
+
+    struct sockaddr_in6 addr = {
+        .sin6_family = AF_INET6,
+        .sin6_port = htons(SACK_TEST_PORT),
+        .sin6_addr = IN6ADDR_LOOPBACK_INIT,
+    };
+    if (net_connect(client, (struct sockaddr *)&addr, sizeof(addr)) < 0)
+        goto out;
+    server = net_accept(listener, NULL, NULL);
+    if (server < 0)
+        goto out;
+
+    tcp_pcb *client_pcb = hold_pcb(client, &client_entry);
+    tcp_pcb *server_pcb = hold_pcb(server, &server_entry);
+    if (!client_pcb || !server_pcb ||
+        !client_pcb->tcp_flag.peer_sack_ok ||
+        !server_pcb->tcp_flag.peer_sack_ok) {
+        fprintf(stderr, "SACK negotiation failed client=%u server=%u\n",
+                client_pcb ? client_pcb->tcp_flag.peer_sack_ok : 0,
+                server_pcb ? server_pcb->tcp_flag.peer_sack_ok : 0);
+        goto out;
+    }
+
+    client_pcb->snd_mss = SACK_TEST_MSS;
+    client_pcb->snd_cwnd = SACK_TEST_BYTES * 2u;
+    client_pcb->snd_ssthresh = client_pcb->snd_cwnd;
+    PUT_REF(client_entry);
+    client_entry = NULL;
+    PUT_REF(server_entry);
+    server_entry = NULL;
+
+    tx = malloc(SACK_TEST_BYTES);
+    rx = malloc(SACK_TEST_BYTES);
+    if (!tx || !rx)
+        goto out;
+    for (uint32_t i = 0; i < SACK_TEST_BYTES; i++)
+        tx[i] = (uint8_t)(i * 37u + 11u);
+
+    struct timeval timeout = { .tv_sec = 4, .tv_usec = 0 };
+    if (net_setsockopt(server, SOL_SOCKET, SO_RCVTIMEO,
+                       &timeout, sizeof(timeout)) < 0)
+        goto out;
+
+    loopback_test_drop_tcp_data_once();
+    uint64_t started = get_current_time_ms();
+    if (net_write(client, tx, SACK_TEST_BYTES) != (int)SACK_TEST_BYTES ||
+        read_exact(server, rx, SACK_TEST_BYTES) < 0 ||
+        memcmp(tx, rx, SACK_TEST_BYTES) != 0)
+        goto out;
+    uint64_t elapsed = get_current_time_ms() - started;
+
+    client_pcb = hold_pcb(client, &client_entry);
+    server_pcb = hold_pcb(server, &server_entry);
+    uint32_t blocks_received = client_pcb ? client_pcb->sack_blocks_received : 0;
+    uint32_t retransmits = client_pcb ? client_pcb->sack_retransmits : 0;
+    uint32_t rto_events = client_pcb ? client_pcb->sack_rto_events : UINT32_MAX;
+    uint32_t blocks_sent = server_pcb ? server_pcb->sack_blocks_sent : 0;
+    if (!blocks_sent || !blocks_received || !retransmits || rto_events != 0) {
+        fprintf(stderr,
+                "SACK activity missing sent=%u received=%u retransmits=%u "
+                "rto-events=%u\n",
+                blocks_sent, blocks_received, retransmits, rto_events);
+        goto out;
+    }
+
+    printf("PASS tcp-sack blocks-sent=%u blocks-received=%u "
+           "selective-retransmits=%u rto-events=%u bytes=%u elapsed-ms=%llu\n",
+           blocks_sent, blocks_received, retransmits, rto_events,
+           SACK_TEST_BYTES, (unsigned long long)elapsed);
+    result = 0;
+
+out:
+    if (client_entry) PUT_REF(client_entry);
+    if (server_entry) PUT_REF(server_entry);
+    free(tx);
+    free(rx);
+    if (server >= 0) net_close(server);
+    if (client >= 0) net_close(client);
+    if (listener >= 0) net_close(listener);
+    return result;
+}
--- a/test/main/test_main_tcp.c
+++ b/test/main/test_main_tcp.c
@@ -168,6 +168,9 @@
     TEST_ASSERT_EQ((uint8_t)(TCP_FLAG_RST | TCP_FLAG_ACK), 0x14);
 
     TEST_ASSERT(MAX_TCP_HDR_OPT_LEN >= 40);
+    TEST_ASSERT_EQ(TCP_OPTION_SACK_PERMITTED, 4);
+    TEST_ASSERT_EQ(TCP_OPTION_SACK, 5);
+    TEST_ASSERT_EQ(TCP_MAX_SACK_BLOCKS, 4);
     return 0;
 }
 
@@ -215,15 +218,23 @@
 
 static int test_tcp_predict_options_len(void)
 {
-    /* No TS SYN: MSS(4) + WS(4). */
-    uint32_t len = 4u + 4u;
+    /* No TS SYN: MSS(4) + SACK-permitted/pad(4) + WS(4). */
+    uint32_t len = 4u + 4u + 4u;
     len = (len + 3u) & ~3u;
-    TEST_ASSERT_EQ(len, 8u);
+    TEST_ASSERT_EQ(len, 12u);
 
-    /* TS SYN: MSS(4) + WS(4) + TS(12). */
-    len = 4u + 4u + 12u;
+    /* TS SYN: MSS(4) + SACK-permitted/pad(4) + WS(4) + TS(12). */
+    len = 4u + 4u + 4u + 12u;
     len = (len + 3u) & ~3u;
-    TEST_ASSERT_EQ(len, 20u);
+    TEST_ASSERT_EQ(len, 24u);
+
+    len = 2u + TCP_MAX_SACK_BLOCKS * 8u;
+    len = (len + 3u) & ~3u;
+    TEST_ASSERT_EQ(len, 36u);
+
+    len = 12u + 2u + 3u * 8u;
+    len = (len + 3u) & ~3u;
+    TEST_ASSERT_EQ(len, 40u);
     return 0;
 }
 
```

## 参考的 Linux 路径

- [Linux per-skb SACK 状态位](https://github.com/torvalds/linux/blob/f5098b6bae761e346ebcd9da7f95622c04733cff/include/net/tcp.h#L1089-L1100)
- [tcp_sacktag_write_queue()](https://github.com/torvalds/linux/blob/f5098b6bae761e346ebcd9da7f95622c04733cff/net/ipv4/tcp_input.c#L2220-L2389)
- [tcp_fastretrans_alert()](https://github.com/torvalds/linux/blob/f5098b6bae761e346ebcd9da7f95622c04733cff/net/ipv4/tcp_input.c#L3328-L3454)
- [tcp_xmit_retransmit_queue()](https://github.com/torvalds/linux/blob/f5098b6bae761e346ebcd9da7f95622c04733cff/net/ipv4/tcp_output.c#L3725-L3790)
- [接收端 SACK block 维护](https://github.com/torvalds/linux/blob/f5098b6bae761e346ebcd9da7f95622c04733cff/net/ipv4/tcp_input.c#L5094-L5229)

