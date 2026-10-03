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

/* 将 src 覆盖的序号范围并入 dst，结果取两者的最左和最右边界。 */
static inline void tcp_sack_block_merge(tcp_sack_block* dst,
                                        const tcp_sack_block* src)
{
    if (SEQ_LT(src->left, dst->left))
        dst->left = src->left;
    if (SEQ_GT(src->right, dst->right))
        dst->right = src->right;
}

void tcp_sack_set_state(tcp_pcb* pcb, skbuff* skb, uint8_t state)
{
    if (skb->l4_private.tcp.sack_state == state ||
        !pcb->tcp_flag.peer_sack_ok)
        return;
    uint32_t bytes = skb->l4_private.tcp.seq_end - skb->l4_private.tcp.seq;
    if(skb->l4_private.tcp.sack_state & TCP_SACKED_ACKED){
        if(!(state & TCP_SACKED_ACKED)){
            pcb->sack.sacked_bytes -= bytes;

        }
    }else {
        if(state & TCP_SACKED_ACKED){
            pcb->sack.sacked_bytes += bytes;

        }
    }
    if(skb->l4_private.tcp.sack_state & TCP_SACKED_RETRANS){
        if(!(state & TCP_SACKED_RETRANS))
            pcb->sack.recovery_bytes -= bytes;
    }else {
        if(state & TCP_SACKED_RETRANS)
            pcb->sack.recovery_bytes += bytes;
    }
    skb->l4_private.tcp.sack_state = state;
    tcp_rack_update_skb(pcb, skb);
}


void tcp_sack_rcv_nxt_advance(tcp_pcb* pcb)
{
    if (!pcb->tcp_flag.peer_sack_ok || pcb->sack.notify_sack_count == 0)
        return;

    tcp_sack_block next[TCP_MAX_SACK_BLOCKS] = {0};
    uint32_t old_count = pcb->sack.notify_sack_count;
    pcb->sack.notify_sack_count = 0;
    uint32_t high = pcb->rcv_nxt;
    for (uint32_t i = 0; i < old_count; i++) {
        if (SEQ_LEQ(pcb->sack.notify_sacks[i].left, pcb->rcv_nxt))
            continue;
        next[pcb->sack.notify_sack_count++] = pcb->sack.notify_sacks[i];
        if (SEQ_GT(pcb->sack.notify_sacks[i].right, high))
            high = pcb->sack.notify_sacks[i].right;
    }
    memcpy(pcb->sack.notify_sacks, next, pcb->sack.notify_sack_count * sizeof(tcp_sack_block));
    skbuff* skb = TCP_TREE_LOWER_BOUND(pcb, reorder, high);
    if(pcb->sack.notify_sack_count < TCP_MAX_SACK_BLOCKS && skb){
        tcp_sack_block new_block={.left = skb->l4_private.tcp.seq, .right = skb->l4_private.tcp.seq_end};
        skb = TCP_TREE_NEXT(skb, reorder);
        while(skb){
            if(!tcp_sack_blocks_touch(&new_block, &(tcp_sack_block){.left = skb->l4_private.tcp.seq, .right = skb->l4_private.tcp.seq_end}))
                break;
            tcp_sack_block_merge(&new_block, &(tcp_sack_block){.left = skb->l4_private.tcp.seq, .right = skb->l4_private.tcp.seq_end});
            skb = TCP_TREE_NEXT(skb, reorder);
        }
        pcb->sack.notify_sacks[pcb->sack.notify_sack_count++] = new_block;
    }

}

// recv out of order skb, update sack
void tcp_sack_recv_ooo_skb(tcp_pcb* pcb, const skbuff* skb)
{
    if (!pcb->tcp_flag.peer_sack_ok)
        return;

    tcp_sack_block merged = {
        .left = skb->l4_private.tcp.seq,
        .right = skb->l4_private.tcp.seq_end,
    };

    for (const skbuff* queued_skb = TCP_TREE_PREV(skb, reorder); queued_skb;
         queued_skb = TCP_TREE_PREV(queued_skb, reorder)) {
        tcp_sack_block queued = {
            .left = queued_skb->l4_private.tcp.seq,
            .right = queued_skb->l4_private.tcp.seq_end,
        };
        if (!tcp_sack_blocks_touch(&merged, &queued))
            break;
        tcp_sack_block_merge(&merged, &queued);
    }
    for (const skbuff* queued_skb = TCP_TREE_NEXT(skb, reorder); queued_skb;
         queued_skb = TCP_TREE_NEXT(queued_skb, reorder)) {
        tcp_sack_block queued = {
            .left = queued_skb->l4_private.tcp.seq,
            .right = queued_skb->l4_private.tcp.seq_end,
        };
        if (!tcp_sack_blocks_touch(&merged, &queued))
            break;
        tcp_sack_block_merge(&merged, &queued);
    }

    tcp_sack_block next[TCP_MAX_SACK_BLOCKS] = {0};
    uint32_t count = 1;
    next[0] = merged;
    for (uint32_t i = 0; i < pcb->sack.notify_sack_count &&
                         count < TCP_MAX_SACK_BLOCKS; i++) {
        if (!tcp_sack_blocks_touch(&merged, &pcb->sack.notify_sacks[i]))
            next[count++] = pcb->sack.notify_sacks[i];
    }
    memcpy(pcb->sack.notify_sacks, next, sizeof(next));
    pcb->sack.notify_sack_count = (uint8_t)count;
}


static uint32_t tcp_sack_option_block_count(const tcp_pcb* pcb,
                                             uint8_t flags)
{
    if ((flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) != TCP_FLAG_ACK ||
        (flags & TCP_FLAG_RST) || !pcb->tcp_flag.peer_sack_ok)
        return 0;

    uint32_t max_blocks = pcb->tcp_flag.peer_ts_ok ? 3u : 4u;
    return min((uint32_t)pcb->sack.notify_sack_count, max_blocks);
}

uint64_t tcp_sack_acked_bytes(const tcp_pcb* pcb)
{
    return pcb->sack.sacked_bytes;
}

uint64_t tcp_sack_retransmited_bytes(const tcp_pcb* pcb)
{
    return pcb->sack.recovery_bytes;
}

uint32_t tcp_sack_option_len(const tcp_pcb* pcb, uint8_t flags)
{
    uint32_t count = tcp_sack_option_block_count(pcb, flags);
    if (!count)
        return 0;

    return (2u + count * 8u + 3u) & ~3u;
}

/* 将接收端保存的 SACK blocks 编码到已预留的 TCP 选项缓冲区，转换为网络
 * 字节序，并使用 NOP 补齐到四字节边界。 */
void tcp_sack_write_option(tcp_pcb* pcb, uint8_t flags, uint8_t* out)
{
    uint32_t count = tcp_sack_option_block_count(pcb, flags);
    if (!count)
        return;

    uint32_t option_len = (2u + count * 8u + 3u) & ~3u;

    uint32_t pos = 0;
    out[pos++] = TCP_OPTION_SACK;
    out[pos++] = (uint8_t)(2u + count * 8u);
    for (uint32_t i = 0; i < count; i++) {
        uint32_t left = htonl(pcb->sack.notify_sacks[i].left);
        uint32_t right = htonl(pcb->sack.notify_sacks[i].right);
        memcpy(out + pos, &left, sizeof(left));
        pos += sizeof(left);
        memcpy(out + pos, &right, sizeof(right));
        pos += sizeof(right);
    }
    while (pos < option_len)
        out[pos++] = 1; /* NOP padding */

    pcb->sack_blocks_sent += count;
}

/* Return the retransmit skb whose sequence interval covers seq, if any. */
static inline skbuff* tcp_sack_find_covering_skb(tcp_pcb* pcb,
                                                 uint32_t seq)
{
    skbuff* skb = TCP_TREE_LOWER_BOUND(pcb, retransmit, seq);
    if (!skb)
        return TCP_TREE_LAST(pcb, retransmit);

    /* lower_bound() already gives us the insertion point; its rb predecessor
     * is the only possible skb that can start before seq and still cover it. */
    skbuff* prev = TCP_TREE_PREV(skb, retransmit);
    if (prev && SEQ_GT(prev->l4_private.tcp.seq_end, seq))
        return prev;

    return skb;
}

/* Mark exactly [left, right) as SACKed, splitting boundary skbs as needed. */
static void tcp_sack_mark_block(tcp_pcb* pcb, const tcp_sack_block* block)
{
    uint32_t left = block->left;
    uint32_t right = block->right;
    skbuff* skb = tcp_sack_find_covering_skb(pcb, left);

    while (skb && SEQ_LT(skb->l4_private.tcp.seq, right)) {
        if (SEQ_LT(skb->l4_private.tcp.seq, left)) {
            skb = tcp_skb_split(pcb, skb,
                                left - skb->l4_private.tcp.seq);
            if (!skb)
                return;
        }

        if (SEQ_GT(skb->l4_private.tcp.seq_end, right) &&
            !tcp_skb_split(pcb, skb,
                           right - skb->l4_private.tcp.seq))
            return;

        skbuff* next = TCP_TREE_NEXT(skb, retransmit);
        tcp_sack_set_state(pcb, skb,
                           skb->l4_private.tcp.sack_state |
                           TCP_SACKED_ACKED);
        skb = next;
    }
}

void tcp_sack_process_options(tcp_pcb* pcb, const tcp_options* options)
{
    if (!pcb->tcp_flag.peer_sack_ok ||
        !(options->flags & TCP_OPTION_SACK_SEEN))
        return;

    tcp_sack_block valid_sacks[TCP_MAX_SACK_BLOCKS];
    uint8_t valid_count = 0;
    uint32_t sack_count = min((uint32_t)options->sack_count,
                              (uint32_t)TCP_MAX_SACK_BLOCKS);

    for (uint32_t i = 0; i < sack_count; i++) {
        tcp_sack_block block = options->sacks[i];
        if (block.left == block.right ||
            SEQ_LEQ(block.left, pcb->snd_una) ||
            SEQ_GEQ(block.left, pcb->snd_nxt) ||
            SEQ_GT(block.right, pcb->snd_nxt))
            continue;
        if (!SEQ_LT(block.left, block.right))
            continue;

        bool duplicate = false;
        for (uint32_t j = 0; j < valid_count; j++) {
            if (valid_sacks[j].left == block.left &&
                valid_sacks[j].right == block.right) {
                duplicate = true;
                break;
            }
        }
        if (duplicate)
            continue;

        valid_sacks[valid_count++] = block;
        bool seen = false;
        for (uint32_t j = 0; j < pcb->sack.peer_sack_count; j++) {
            if (pcb->sack.peer_sacks[j].left == block.left &&
                pcb->sack.peer_sacks[j].right == block.right) {
                seen = true;
                break;
            }
        }
        if (seen)
            continue;
        tcp_sack_mark_block(pcb, &block);
    }
    pcb->sack.peer_sack_count = valid_count;
    memcpy(pcb->sack.peer_sacks, valid_sacks,
           sizeof(tcp_sack_block) * valid_count);

}

void tcp_sack_reset(tcp_pcb* pcb)
{
    memset(pcb->sack.notify_sacks, 0, sizeof(pcb->sack.notify_sacks));
    pcb->sack.notify_sack_count = 0;
    pcb->sack_blocks_sent = 0;
    pcb->tcp_flag.peer_sack_ok = 0;
}
