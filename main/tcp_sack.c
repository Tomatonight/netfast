#include <arpa/inet.h>
#include <stddef.h>
#include <string.h>

#include <base.h>
#include <skbuff.h>
#include <tcp_sack.h>
#include <tcp.h>

/* 判断两个半开 SACK 区间是否重叠或首尾相邻，可用于合并连续范围。 */
static inline bool tcp_sack_blocks_touch(const tcp_sack_block* a,
                                         const tcp_sack_block* b)
{
    return SEQ_LEQ(a->left, b->right) && SEQ_GEQ(a->right, b->left);
}

/* 判断两个半开 SACK 区间是否存在严格重叠；仅首尾相邻不算重叠。 */
static inline bool tcp_sack_blocks_overlap(const tcp_sack_block* a,
                                           const tcp_sack_block* b)
{
    return SEQ_LT(a->left, b->right) && SEQ_GT(a->right, b->left);
}

/* 将 src 覆盖的序号范围并入 dst，结果取两者的最左和最右边界。 */
static inline void tcp_sack_block_merge(tcp_sack_block* dst,
                                        const tcp_sack_block* src)
{
    if (SEQ_LT(src->left, dst->left))
        dst->left = src->left;
    if (SEQ_GT(src->right, dst->right))
        dst->right = src->right;
}

/* 在按序排列的乱序接收队列中找到 block 对应的 skb，并向前、向后
 * 合并所有相邻或重叠的 skb；找不到实际队列范围时返回 false。 */
static bool tcp_sack_expand_reorder_range(const tcp_pcb* pcb,
                                          tcp_sack_block* block)
{
    const list_node* head = &pcb->unordered_skb_list;
    const list_node* hit = NULL;

    for (const list_node* node = head->next; node; node = node->next) {
        const skbuff* skb = SKB_FROM_NODE((list_node*)node, tcp_list);
        tcp_sack_block queued = {
            .left = skb->l4_private.tcp.seq,
            .right = skb->l4_private.tcp.seq_end,
        };
        if (tcp_sack_blocks_overlap(block, &queued)) {
            tcp_sack_block_merge(block, &queued);
            hit = node;
            break;
        }
    }
    if (!hit)
        return false;

    for (const list_node* node = hit->pre; node && node != head;
         node = node->pre) {
        const skbuff* skb = SKB_FROM_NODE((list_node*)node, tcp_list);
        tcp_sack_block queued = {
            .left = skb->l4_private.tcp.seq,
            .right = skb->l4_private.tcp.seq_end,
        };
        if (!tcp_sack_blocks_touch(block, &queued))
            break;
        tcp_sack_block_merge(block, &queued);
    }
    for (const list_node* node = hit->next; node; node = node->next) {
        const skbuff* skb = SKB_FROM_NODE((list_node*)node, tcp_list);
        tcp_sack_block queued = {
            .left = skb->l4_private.tcp.seq,
            .right = skb->l4_private.tcp.seq_end,
        };
        if (!tcp_sack_blocks_touch(block, &queued))
            break;
        tcp_sack_block_merge(block, &queued);
    }
    return true;
}

/* 以乱序接收队列为真实数据源，重建可发送的 recv_sacks[]。该函数会
 * 删除已被累计 ACK 覆盖或已经不在队列中的旧块、合并连续范围，同时
 * 尽量保留“最近收到的块优先”的报文顺序。 */
static void tcp_sack_receiver_refill(tcp_pcb* pcb)
{
    tcp_sack_block next[TCP_MAX_SACK_BLOCKS] = {0};
    uint32_t count = 0;

    if (!pcb->tcp_flag.peer_sack_ok) {
        return;
    }

    for (uint32_t i = 0; i < pcb->recv_sack_count; i++) {
        tcp_sack_block block = pcb->recv_sacks[i];
        if (!SEQ_GT(block.right, pcb->rcv_nxt))
            continue;
        if (SEQ_LT(block.left, pcb->rcv_nxt))
            block.left = pcb->rcv_nxt;
        if (!SEQ_LT(block.left, block.right) ||
            !tcp_sack_expand_reorder_range(pcb, &block))
            continue;

        bool represented = false;
        for (uint32_t j = 0; j < count; j++) {
            if (tcp_sack_blocks_touch(&next[j], &block)) {
                tcp_sack_block_merge(&next[j], &block);
                represented = true;
                break;
            }
        }
        if (!represented && count < TCP_MAX_SACK_BLOCKS)
            next[count++] = block;
    }

    const list_node* node = pcb->unordered_skb_list.next;
    while (node) {
        const skbuff* skb = SKB_FROM_NODE((list_node*)node, tcp_list);
        tcp_sack_block block = {
            .left = skb->l4_private.tcp.seq,
            .right = skb->l4_private.tcp.seq_end,
        };
        node = node->next;

        while (node) {
            const skbuff* following =
                SKB_FROM_NODE((list_node*)node, tcp_list);
            tcp_sack_block queued = {
                .left = following->l4_private.tcp.seq,
                .right = following->l4_private.tcp.seq_end,
            };
            if (!tcp_sack_blocks_touch(&block, &queued))
                break;
            tcp_sack_block_merge(&block, &queued);
            node = node->next;
        }

        if (!SEQ_GT(block.right, pcb->rcv_nxt))
            continue;
        if (SEQ_LT(block.left, pcb->rcv_nxt))
            block.left = pcb->rcv_nxt;
        if (!SEQ_LT(block.left, block.right))
            continue;

        bool represented = false;
        for (uint32_t i = 0; i < count; i++) {
            if (tcp_sack_blocks_touch(&next[i], &block)) {
                tcp_sack_block_merge(&next[i], &block);
                represented = true;
                break;
            }
        }
        if (!represented && count < TCP_MAX_SACK_BLOCKS)
            next[count++] = block;
    }

    memcpy(pcb->recv_sacks, next, sizeof(next));
    pcb->recv_sack_count = (uint8_t)count;
}

/* 接收端记录一个新到达的乱序半开区间 [left, right)。先依据乱序队列
 * 扩展为完整连续块，再将其放到 recv_sacks[0]，供下一个 ACK 优先携带。 */
void tcp_sack_receiver_update(tcp_pcb* pcb, uint32_t left,
                              uint32_t right)
{
    if (!pcb->tcp_flag.peer_sack_ok)
        return;

    tcp_sack_block merged = {.left = left, .right = right};
    (void)tcp_sack_expand_reorder_range(pcb, &merged);

    tcp_sack_block next[TCP_MAX_SACK_BLOCKS] = {0};
    uint32_t count = 1;
    next[0] = merged;
    for (uint32_t i = 0; i < pcb->recv_sack_count &&
                         count < TCP_MAX_SACK_BLOCKS; i++) {
        if (!tcp_sack_blocks_touch(&merged, &pcb->recv_sacks[i]))
            next[count++] = pcb->recv_sacks[i];
    }
    memcpy(pcb->recv_sacks, next, sizeof(next));
    pcb->recv_sack_count = (uint8_t)count;
    tcp_sack_receiver_refill(pcb);
}

/* RCV.NXT 推进或乱序队列变化后，清除失效的接收端 SACK 块并重新合并。 */
void tcp_sack_receiver_prune(tcp_pcb* pcb)
{
    tcp_sack_receiver_refill(pcb);
}

/* 根据当前报文标志、SACK 协商状态和时间戳占用空间，计算本次 ACK 最多
 * 能写入多少个 SACK block。 */
static uint8_t tcp_sack_option_block_count(const tcp_pcb* pcb,
                                           uint8_t flags)
{
    if ((flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) != TCP_FLAG_ACK ||
        (flags & TCP_FLAG_RST) || !pcb->tcp_flag.peer_sack_ok)
        return 0;

    uint32_t max_blocks = pcb->tcp_flag.peer_ts_ok ? 3u : 4u;
    return (uint8_t)min((uint32_t)pcb->recv_sack_count, max_blocks);
}

/* 返回 SACK TCP 选项写入后的四字节对齐长度；当前报文不能携带时返回 0。 */
uint32_t tcp_sack_option_len(const tcp_pcb* pcb, uint8_t flags)
{
    uint32_t count = tcp_sack_option_block_count(pcb, flags);
    return count ? (2u + count * 8u + 3u) & ~3u : 0u;
}

/* 将接收端保存的 SACK blocks 编码到 TCP 选项缓冲区，转换为网络字节序，
 * 并使用 NOP 补齐到四字节边界；返回实际占用长度。 */
uint32_t tcp_sack_write_option(tcp_pcb* pcb, uint8_t flags,
                               uint8_t* out, uint32_t capacity)
{
    uint32_t count = tcp_sack_option_block_count(pcb, flags);
    if (!count)
        return 0;

    uint32_t option_len = (2u + count * 8u + 3u) & ~3u;
    if (capacity < option_len)
        return 0;

    uint32_t pos = 0;
    out[pos++] = TCP_OPTION_SACK;
    out[pos++] = (uint8_t)(2u + count * 8u);
    for (uint32_t i = 0; i < count; i++) {
        uint32_t left = htonl(pcb->recv_sacks[i].left);
        uint32_t right = htonl(pcb->recv_sacks[i].right);
        memcpy(out + pos, &left, sizeof(left));
        pos += sizeof(left);
        memcpy(out + pos, &right, sizeof(right));
        pos += sizeof(right);
    }
    while (pos < option_len)
        out[pos++] = 1; /* NOP padding */

    pcb->sack_blocks_sent += count;
    return pos;
}

/* 发送端用一个收到的 SACK block 更新重传队列 scoreboard。只有整个 skb
 * 序号范围均被覆盖时才标记 TCP_SACKED_ACKED，部分覆盖保持忽略；返回新
 * 确认的 payload 字节数，FIN 虽参与覆盖判断但不计入字节数。 */
static uint64_t tcp_sack_mark_block(tcp_pcb* pcb, uint32_t ack,
                                    const tcp_sack_block* block,
                                    bool* valid)
{
    if (!SEQ_GEQ(block->left, ack) || !SEQ_LT(block->left, block->right) ||
        !SEQ_LEQ(block->right, pcb->snd_nxt))
        return 0;

    *valid = true;
    uint64_t newly_sacked = 0;
    list_node* node = pcb->retransmit_queue.first.next;
    while (node != &pcb->retransmit_queue.last) {
        skbuff* skb = SKB_FROM_NODE(node, queue_node);
        uint8_t flags = skb->l4_private.tcp.flag;
        uint8_t state = skb->l4_private.tcp.sack_state;
        uint32_t left = skb->l4_private.tcp.seq;
        uint32_t right = skb->l4_private.tcp.seq_end;

        /* SACK state is stored per skb.  Mark only an skb whose complete
         * sequence range is covered; a partial overlap is deliberately
         * ignored.  FIN participates in sequence space, while SYN cannot
         * appear in an established-connection SACK block. */
        if ((state & TCP_SACKED_ACKED) ||
            (flags & TCP_FLAG_SYN) ||
            !SEQ_LT(left, right) || SEQ_GT(block->left, left) ||
            SEQ_LT(block->right, right)) {
            node = node->next;
            continue;
        }

        /* Congestion accounting is in payload bytes; FIN consumes sequence
         * space but is not an application-data byte. */
        newly_sacked += skb_data_len(skb);
        skb->l4_private.tcp.sack_state |= TCP_SACKED_ACKED;
        skb->l4_private.tcp.sack_state &=
            ~(TCP_SACKED_LOST | TCP_SACKED_RETRANS);
        skb->l4_private.tcp.sack_retransmit_high = 0;
        node = node->next;
    }
    return newly_sacked;
}

/* 统计 candidate 之后、threshold 以上已经被 SACK 的 payload 字节数和
 * 不连续块数，为判断原报文或其重传是否丢失提供证据。 */
static void tcp_sack_loss_evidence(const tcp_pcb* pcb,
                                   const skbuff* candidate,
                                   uint32_t threshold,
                                   uint64_t* bytes_out,
                                   uint32_t* runs_out)
{
    uint64_t bytes = 0;
    uint32_t runs = 0;
    bool in_sacked_run = false;
    bool after_candidate = false;

    QUEUE_FOR_EACH(&pcb->retransmit_queue, node) {
        const skbuff* skb = SKB_FROM_NODE(node, queue_node);
        if (!after_candidate) {
            if (skb == candidate)
                after_candidate = true;
            continue;
        }

        uint32_t left = skb->l4_private.tcp.seq;
        uint32_t right = left + skb_data_len(skb);
        bool counted = false;
        if ((skb->l4_private.tcp.sack_state & TCP_SACKED_ACKED) &&
            SEQ_GT(right, threshold)) {
            uint32_t counted_left = SEQ_GT(left, threshold)
                ? left : threshold;
            if (SEQ_LT(counted_left, right)) {
                bytes += right - counted_left;
                counted = true;
                if (!in_sacked_run)
                    runs++;
            }
        }
        in_sacked_run = counted;
    }

    *bytes_out = bytes;
    *runs_out = runs;
}

/* 扫描发送端 scoreboard：当后方存在至少三个 SACK 块或超过两倍 MSS 的
 * SACK 数据时，将尚未确认的候选 skb 标记为 TCP_SACKED_LOST。 */
static void tcp_sack_mark_losses(tcp_pcb* pcb)
{
    uint32_t mss = tcp_data_mss(pcb);
    uint64_t threshold_bytes = 2ull * mss;
    uint64_t suffix_sacked_bytes = 0;
    uint32_t suffix_sacked_runs = 0;
    bool next_is_sacked = false;

    for (list_node* node = pcb->retransmit_queue.last.pre;
         node != &pcb->retransmit_queue.first; node = node->pre) {
        skbuff* skb = SKB_FROM_NODE(node, queue_node);
        uint8_t state = skb->l4_private.tcp.sack_state;

        if (skb_data_len(skb) && !(state & TCP_SACKED_ACKED)) {
            uint64_t bytes;
            uint32_t runs;
            if (state & TCP_SACKED_RETRANS) {
                tcp_sack_loss_evidence(
                    pcb, skb, skb->l4_private.tcp.sack_retransmit_high,
                    &bytes, &runs);
            } else {
                bytes = suffix_sacked_bytes;
                runs = suffix_sacked_runs;
            }
            if (runs >= 3u || bytes > threshold_bytes) {
                skb->l4_private.tcp.sack_state |= TCP_SACKED_LOST;
                if (state & TCP_SACKED_RETRANS)
                    skb->l4_private.tcp.sack_state &=
                        ~TCP_SACKED_RETRANS;
            }
        }

        bool sacked = skb_data_len(skb) &&
            (state & TCP_SACKED_ACKED);
        if (sacked) {
            suffix_sacked_bytes += skb_data_len(skb);
            if (!next_is_sacked)
                suffix_sacked_runs++;
        }
        next_is_sacked = sacked;
    }
}

/* 解析对端 ACK 中的全部 SACK 选项，校验每个 block，更新重传队列的
 * SACK 状态并触发丢包推断。如果出现可重传 hole，则在本函数内通知拥塞
 * 控制或调度快速重传；newly_sacked 可选返回新确认的 payload 字节数。 */
bool tcp_sack_process_options(tcp_pcb* pcb, const tcp_hdr* hdr,
                              uint64_t* newly_sacked)
{
    if (newly_sacked)
        *newly_sacked = 0;
    if (!pcb->tcp_flag.sack_permitted_sent ||
        (hdr->flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) != TCP_FLAG_ACK)
        return false;

    uint32_t ack = ntohl(hdr->ack_seq);
    if (!SEQ_GEQ(ack, pcb->snd_una) || !SEQ_LEQ(ack, pcb->snd_nxt))
        return false;

    uint32_t hdr_len = (uint32_t)(hdr->doff_res_flags >> 4) * 4u;
    if (hdr_len < sizeof(tcp_hdr) || hdr_len > MAX_TCP_HDR_LEN)
        return false;

    uint32_t options_len = hdr_len - sizeof(tcp_hdr);
    const uint8_t* opt = (const uint8_t*)hdr + sizeof(tcp_hdr);
    bool sack_seen = false;
    uint64_t newly = 0;

    for (uint32_t i = 0; i < options_len;) {
        uint8_t kind = opt[i];
        if (kind == 0)
            break;
        if (kind == 1) {
            i++;
            continue;
        }
        if (i + 1u >= options_len)
            break;
        uint8_t len = opt[i + 1u];
        if (len < 2u || i + len > options_len)
            break;

        if (kind == TCP_OPTION_SACK && len >= 10u &&
            ((len - 2u) % 8u) == 0) {
            uint32_t count = min((uint32_t)(len - 2u) / 8u,
                                 (uint32_t)TCP_MAX_SACK_BLOCKS);
            for (uint32_t block_index = 0;
                 block_index < count; block_index++) {
                uint32_t left_n;
                uint32_t right_n;
                memcpy(&left_n, &opt[i + 2u + block_index * 8u],
                       sizeof(left_n));
                memcpy(&right_n, &opt[i + 6u + block_index * 8u],
                       sizeof(right_n));
                tcp_sack_block block = {
                    .left = ntohl(left_n),
                    .right = ntohl(right_n),
                };
                bool valid = false;
                newly += tcp_sack_mark_block(pcb, ack, &block, &valid);
                if (valid) {
                    sack_seen = true;
                    pcb->sack_blocks_received++;
                }
            }
        }
        i += len;
    }

    if (newly_sacked)
        *newly_sacked = newly;
    if (sack_seen) {
        tcp_sack_mark_losses(pcb);
        if (tcp_sack_next_hole(pcb)) {
            if (pcb->ca.status == TCP_CA_STATUS_OPEN)
                tcp_ca_recv_repeat_ack(pcb, 3u);
            else
                tcp_schedule_fast_retransmit(pcb);
        }
    }
    return sack_seen;
}

/* 返回重传队列中第一个已判定丢失、尚未被 SACK 且尚未重传的数据 skb。 */
skbuff* tcp_sack_next_hole(tcp_pcb* pcb)
{
    QUEUE_FOR_EACH(&pcb->retransmit_queue, node) {
        skbuff* skb = SKB_FROM_NODE(node, queue_node);
        uint8_t state = skb->l4_private.tcp.sack_state;
        if (skb_data_len(skb) && (state & TCP_SACKED_LOST) &&
            !(state & (TCP_SACKED_ACKED | TCP_SACKED_RETRANS)))
            return skb;
    }
    return NULL;
}

/* 返回重传队列中第一个仍占用序号空间且既未被 SACK、也未处于重传中的
 * skb，用于恢复阶段选择最早的未确认报文。 */
skbuff* tcp_sack_first_unsacked(tcp_pcb* pcb)
{
    QUEUE_FOR_EACH(&pcb->retransmit_queue, node) {
        skbuff* skb = SKB_FROM_NODE(node, queue_node);
        uint8_t state = skb->l4_private.tcp.sack_state;

        if (state & (TCP_SACKED_ACKED | TCP_SACKED_RETRANS))
            return skb;
    }
    return NULL;
}

/* 估算仍在网络中的序号空间：排除已被 SACK 的 skb，以及已判丢但尚未
 * 重传的 skb；结果用于限制恢复阶段的发送量。 */
uint64_t tcp_sack_pipe(const tcp_pcb* pcb)
{
    uint64_t pipe = 0;
    QUEUE_FOR_EACH(&pcb->retransmit_queue, node) {
        const skbuff* skb = SKB_FROM_NODE(node, queue_node);
        uint8_t state = skb->l4_private.tcp.sack_state;
        if (state & TCP_SACKED_ACKED)
            continue;
        if ((state & TCP_SACKED_LOST) && !(state & TCP_SACKED_RETRANS))
            continue;
        pipe += skb->l4_private.tcp.seq_end -
                skb->l4_private.tcp.seq;
    }
    return pipe;
}

/* 记录某个丢失 skb 已经执行重传，并保存当时最高的 SACK 右边界，用于
 * 后续判断该次重传之后是否又出现了足够的丢包证据。 */
void tcp_sack_mark_retransmitted(tcp_pcb* pcb, skbuff* skb)
{
    if (skb->l4_private.tcp.sack_state & TCP_SACKED_RETRANS)
        return;

    uint32_t high = skb->l4_private.tcp.seq_end;
    QUEUE_FOR_EACH(&pcb->retransmit_queue, node) {
        skbuff* queued = SKB_FROM_NODE(node, queue_node);
        if (queued->l4_private.tcp.sack_state & TCP_SACKED_ACKED) {
            uint32_t right = queued->l4_private.tcp.seq_end;
            if (SEQ_GT(right, high))
                high = right;
        }
    }
    skb->l4_private.tcp.sack_retransmit_high = high;
    skb->l4_private.tcp.sack_state |=
        TCP_SACKED_LOST | TCP_SACKED_RETRANS;
    pcb->sack_retransmits++;
}

/* 清除单个 skb 的 SACK、丢失和重传标记，使其恢复为未确认状态。 */
void tcp_sack_clear_skb_state(skbuff* skb)
{
    skb->l4_private.tcp.sack_state = 0;
    skb->l4_private.tcp.sack_retransmit_high = 0;
}

/* 清除整个重传队列的 SACK scoreboard，通常在 RTO 后防止依赖可能失效的
 * 选择确认信息。 */
void tcp_sack_clear_scoreboard(tcp_pcb* pcb)
{
    QUEUE_FOR_EACH(&pcb->retransmit_queue, node) {
        skbuff* skb = SKB_FROM_NODE(node, queue_node);
        tcp_sack_clear_skb_state(skb);
    }
}

/* 完全复位连接的 SACK 状态，包括发送 scoreboard、接收 blocks、统计值
 * 以及双方在握手阶段协商得到的 SACK 能力标志。 */
void tcp_sack_reset(tcp_pcb* pcb)
{
    tcp_sack_clear_scoreboard(pcb);
    memset(pcb->recv_sacks, 0, sizeof(pcb->recv_sacks));
    pcb->recv_sack_count = 0;
    pcb->sack_blocks_sent = 0;
    pcb->sack_blocks_received = 0;
    pcb->sack_retransmits = 0;
    pcb->sack_rto_events = 0;
    pcb->tcp_flag.peer_sack_ok = 0;
    pcb->tcp_flag.sack_permitted_sent = 0;
}
