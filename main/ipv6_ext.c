#include "ipv6_ext.h"

#include "base.h"
#include "hash.h"
#include "log.h"
#include "route_arp_ndp.h"
#include "skbuff.h"
#include "stack.h"
#include "worker.h"

#include <string.h>

/* ── 获取当前 worker 的 IPv6 重组 hash ──────────────────── */
static inline hash* get_ipq6_hash(void)
{
    return get_current_worker()->stack.ipq6_hash;
}

/* ── 创建 / 销毁 / 查找 ipq6 ────────────────────────────── */

static ipq6* create_ipq6(uint32_t id, const uint8_t* src, const uint8_t* dst)
{
    hash* h = get_ipq6_hash();
    ipq6* q = calloc(1, sizeof(*q));
    if (!q)
        return NULL;

    q->key.id = id;
    memcpy(q->key.src_ip, src, 16);
    memcpy(q->key.dst_ip, dst, 16);
    q->last_update_time = (uint32_t)get_current_time_ms();
    if (!hash_add(h, (const uint8_t*)&q->key, sizeof(q->key), (uint64_t)q)) {
        free(q);
        return NULL;
    }
    return q;
}

static void destroy_ipq6(ipq6* q)
{
    hash* h = get_ipq6_hash();
    hash_del(h, (uint8_t*)&q->key, sizeof(q->key));

    list_node *node, *tmp;
    FOR_EACH_LIST_SAFE(&q->frag_head, node, tmp) {
        ipq6_frag* frag = (ipq6_frag*)node->element;
        remove_list_node(node);
        PUT_REF(frag->skb);
        free(frag);
    }
    free(q);
}

static ipq6* search_ipq6(uint32_t id, const uint8_t* src, const uint8_t* dst)
{
    hash* h = get_ipq6_hash();
    ipq6_key key;
    key.id = id;
    memcpy(key.src_ip, src, 16);
    memcpy(key.dst_ip, dst, 16);
    uint64_t elem = hash_get_element(h, (uint8_t*)&key, sizeof(key));
    return elem ? (ipq6*)elem : NULL;
}

/* ── 超时清理 ──────────────────────────────────────────── */

static void ipq6_walk_cb(uint64_t element)
{
    ipq6* q = (ipq6*)element;
    if ((uint32_t)(get_current_time_ms() - q->last_update_time) > IPQ6_TIMEOUT)
        destroy_ipq6(q);
}

void ipq6_timer(task* tk)
{
    hash* h = get_ipq6_hash();
    HASH_ELEMENT_WALK(h, ipq6_walk_cb);
    update_task_timer(tk, get_current_time_ms() + IPQ6_TIMER_INTERVAL);
}

/* ── 排序比较：按 fragment offset 升序 ─────────────────── */

static int frag6_offset_cmp(list_node* a, list_node* b)
{
    ipq6_frag* fa = (ipq6_frag*)((uint8_t*)a - offsetof(ipq6_frag, node));
    ipq6_frag* fb = (ipq6_frag*)((uint8_t*)b - offsetof(ipq6_frag, node));
    if (fa->offset < fb->offset) return -1;
    return fa->offset > fb->offset;
}

/* ── 检测扩展头链中是否有 Fragment EH ──────────────────── */

bool ipv6_has_frag(const skbuff* skb)
{
    if (!skb->ipv6_hdr)
        return false;

    /* Keep this helper safe when called before the fixed-header validator. */
    if (skb_data_len(skb) < IPV6_HDR_LEN)
        return false;

    uint8_t nh = skb->ipv6_hdr->next_hdr;
    uint32_t offset = IPV6_HDR_LEN;
    uint32_t remaining = skb_data_len(skb) - IPV6_HDR_LEN;

    for (int i = 0; i < 8 && remaining > 0; i++) {
        if (nh == IPV6_NEXTHDR_FRAG)
            return true;

        switch (nh) {
        case IPV6_NEXTHDR_HOPOPT:  /* 0 */
        case IPV6_NEXTHDR_DSTOPTS: /* 60 */
        case IPV6_NEXTHDR_ROUTING: /* 43 */
            uint8_t ext[2];
            if (remaining < sizeof(ext) ||
                !skb_copy_bits(skb, offset, ext, sizeof(ext)))
                return false;
            {
                uint8_t ext_len = ext[1];
                uint32_t hdr_len = (uint32_t)(ext_len + 1u) * 8u;
                if (hdr_len < 8 || remaining < hdr_len)
                    return false;
                nh = ext[0];
                offset += hdr_len;
                remaining -= hdr_len;
            }
            break;
        default:
            return false;  /* No Next Header or L4 reached; no Fragment EH. */
        }
    }
    return false;
}

/* ── IPv6 分片重组 ─────────────────────────────────────── */

skbuff* ipv6_defrag(skbuff* skb)
{
    ipv6_hdr* ip6 = skb->ipv6_hdr;

    /* 遍历扩展头，定位 Fragment EH */
    uint8_t nh = ip6->next_hdr;
    uint32_t ext_offset = IPV6_HDR_LEN;
    ipv6_frag_hdr fh_storage;
    ipv6_frag_hdr* fh = NULL;

    for (int i = 0; i < 8; i++) {
        if (nh == IPV6_NEXTHDR_FRAG) {
            if (!skb_copy_bits(skb, ext_offset, &fh_storage,
                               sizeof(fh_storage)))
                return NULL;
            fh = &fh_storage;
            break;
        }

        switch (nh) {
        case IPV6_NEXTHDR_HOPOPT:
        case IPV6_NEXTHDR_DSTOPTS:
        case IPV6_NEXTHDR_ROUTING:
            uint8_t ext[2];
            if (!skb_copy_bits(skb, ext_offset, ext, sizeof(ext)))
                return NULL;
            {
                uint8_t ext_len = ext[1];
                uint32_t hdr_len = (uint32_t)(ext_len + 1u) * 8u;
                if (hdr_len < 8 || ext_offset + hdr_len > skb_data_len(skb))
                    return NULL;
                nh = ext[0];
                ext_offset += hdr_len;
            }
            break;
        default:
            return NULL;  /* no Fragment EH found */
        }
    }

    if (!fh)
        return NULL;

    uint16_t frag_off_host = ntohs(fh->frag_off);
    /* RFC 8200 reserves bits 1..2 in Fragment Offset/Flags and the
     * immediately following byte.  Silently accepting either value makes
     * malformed fragments share a reassembly queue with valid traffic. */
    if ((frag_off_host & 0x0006u) != 0 || fh->reserved != 0)
        return NULL;
    uint16_t offset8 = (frag_off_host & IPV6_FRAG_OFFSET_MASK) >> 3;
    bool mf = (frag_off_host & IPV6_FRAG_MF_MASK) != 0;

    /* 非法：DF 等价物不存在于 v6，但 offset=0 且 mf=0 是完整包 */
    if (offset8 == 0 && !mf)
        return skb;  /* 不是分片，直接返回 */

    /* payload = 所有非固定头 + 扩展头之后的数据 */
    uint32_t frag_hdr_end = ext_offset + sizeof(*fh);
    if (frag_hdr_end > skb_data_len(skb))
        return NULL;
    uint32_t frag_payload_len = skb_data_len(skb) - frag_hdr_end;

    /* Fragment offsets are measured in 8-byte units and the IPv6 payload
     * length is limited to 65535 bytes.  Reject empty/out-of-range ranges
     * before inserting them into the reassembly queue. */
    uint32_t frag_offset_bytes = (uint32_t)offset8 * 8u;
    if (frag_payload_len == 0 ||
        frag_offset_bytes > UINT16_MAX ||
        frag_payload_len > (uint32_t)UINT16_MAX - frag_offset_bytes) {
        DEBUG_LOG("Invalid IPv6 fragment range offset=%u len=%u",
                 frag_offset_bytes, frag_payload_len);
        return NULL;
    }

    /* Every non-final fragment must end on an 8-byte boundary. */
    if (mf && (frag_payload_len & 7u))
        return NULL;

    bool created_q = false;
    ipq6* q = search_ipq6(fh->id, ip6->saddr, ip6->daddr);
    if (!q) {
        q = create_ipq6(fh->id, ip6->saddr, ip6->daddr);
        if (!q) {
            WARN_LOG("Failed to create IPv6 reassembly queue");
            return NULL;
        }
        created_q = true;
        q->unfrag_len = (uint16_t)ext_offset;
        q->next_header = fh->next_hdr;
    } else if (q->unfrag_len != ext_offset ||
               q->next_header != fh->next_hdr) {
        destroy_ipq6(q);
        return NULL;
    }
    q->last_update_time = (uint32_t)get_current_time_ms();

    /* 创建分片节点 */
    ipq6_frag* frag = calloc(1, sizeof(*frag));
    if (!frag) {
        if (created_q)
            destroy_ipq6(q);
        return NULL;
    }
    frag->skb = skb;
    frag->offset = offset8;
    frag->len = frag_payload_len;
    INC_REF(skb);  /* 重组队列持有引用 */

    /* Do not accept overlapping ranges.  Counting overlapping bytes would
     * otherwise make received_len inconsistent and can produce ambiguous
     * reassembled data. */
    uint32_t frag_end = frag_offset_bytes + frag_payload_len;
    bool inconsistent_end = q->flag.last_recved && frag_end > q->total_len;
    ipq6_frag* existing;
    FOR_EACH_LIST_OFFSET(&q->frag_head, existing, ipq6_frag, node) {
        uint32_t existing_start = existing->offset * 8u;
        uint32_t existing_end = existing_start + existing->len;
        if (!mf && existing_end > frag_end)
            inconsistent_end = true;
        if (frag_offset_bytes < existing_end && existing_start < frag_end) {
            PUT_REF(skb);
            free(frag);
            DEBUG_LOG("Overlapping IPv6 fragment offset=%u len=%u",
                     frag_offset_bytes, frag_payload_len);
            if (created_q)
                destroy_ipq6(q);
            return NULL;
        }
    }

    if (inconsistent_end ||
        (!mf && q->flag.last_recved && q->total_len != frag_end)) {
        PUT_REF(skb);
        free(frag);
        destroy_ipq6(q);
        return NULL;
    }

    if (add_list_node_compare(&q->frag_head, &frag->node, frag6_offset_cmp) < 0) {
        PUT_REF(skb);
        free(frag);
        if (created_q)
            destroy_ipq6(q);
        return NULL;
    }

    /* 更新首尾标记 */
    if (!mf) {
        q->flag.last_recved = 1;
        q->total_len = (uint32_t)(offset8 * 8u) + frag_payload_len;
    }
    if (offset8 == 0)
        q->flag.first_recved = 1;

    q->received_len += frag_payload_len;

    /* 还未收齐 */
    if (!(q->flag.first_recved && q->flag.last_recved &&
          q->received_len >= q->total_len))
        return NULL;

    if (q->received_len != q->total_len) {
        DEBUG_LOG("IPv6 received_len %u != total_len %u", q->received_len, q->total_len);
        destroy_ipq6(q);
        return NULL;
    }

    /* ── 收齐，开始重组 ────────────────────────────────── */
    skbuff* reassembled = NULL;
    uint32_t expect_byte = 0;
    /* All fragments carry the same unfragmentable headers.  Save them before
     * pulling headers from the first skb; this also handles headers split over
     * multiple UMEM frames. */
    uint32_t unfrag_len = q->unfrag_len;
    uint32_t strip_all = unfrag_len + sizeof(*fh);
    uint8_t unfrag[IPV6_HDR_LEN + 255u * 8u];
    ipq6_frag *first_frag = q->frag_head.next
        ? (ipq6_frag *)((uint8_t *)q->frag_head.next - offsetof(ipq6_frag, node))
        : NULL;
    if (!first_frag || unfrag_len > sizeof(unfrag) ||
        !skb_copy_bits(first_frag->skb, 0,
                       unfrag, unfrag_len)) {
        destroy_ipq6(q);
        return NULL;
    }

    uint8_t next_header = q->next_header;
    uint32_t previous_nh_offset = offsetof(ipv6_hdr, next_hdr);
    uint32_t walk = IPV6_HDR_LEN;
    while (walk < unfrag_len) {
        if (walk + 2u > unfrag_len) {
            destroy_ipq6(q);
            return NULL;
        }
        previous_nh_offset = walk;
        uint8_t ext_len = unfrag[walk + 1u];
        uint32_t hdr_len = (uint32_t)(ext_len + 1u) * 8u;
        if (hdr_len < 8u || walk + hdr_len > unfrag_len) {
            destroy_ipq6(q);
            return NULL;
        }
        walk += hdr_len;
    }

    ipq6_frag *f;
    list_node *tmp;
    FOR_EACH_LIST_SAFE_OFFSET(&q->frag_head, f, tmp, ipq6_frag, node) {
        remove_list_node(&f->node);

        if (f->offset * 8u != expect_byte) {
            DEBUG_LOG("IPv6 fragment hole: expected byte %u, got %u",
                     expect_byte, f->offset * 8u);
            PUT_REF(f->skb);
            free(f);
            PUT_REF(reassembled);
            destroy_ipq6(q);
            return NULL;
        }

        if (skb_consume(f->skb, strip_all, false) != strip_all) {
            PUT_REF(f->skb);
            free(f);
            PUT_REF(reassembled);
            destroy_ipq6(q);
            return NULL;
        }
        if (!reassembled) {
            reassembled = f->skb;
        } else {
            if (!skb_append_skb(reassembled, f->skb, false)) {
                PUT_REF(f->skb);
                free(f);
                PUT_REF(reassembled);
                destroy_ipq6(q);
                return NULL;
            }
			PUT_REF(f->skb);
        }

        expect_byte += f->len;
        free(f);
    }

    if (!reassembled) {
        destroy_ipq6(q);
        return NULL;
    }

    uint32_t payload_len = unfrag_len - IPV6_HDR_LEN + expect_byte;
    if (payload_len > UINT16_MAX) {
        PUT_REF(reassembled);
        destroy_ipq6(q);
        return NULL;
    }

    uint8_t* header = skb_data_push(reassembled, unfrag_len);
    if (!header) {
        PUT_REF(reassembled);
        destroy_ipq6(q);
        return NULL;
    }
    memcpy(header, unfrag, unfrag_len);

    ipv6_hdr* new_ip6 = (ipv6_hdr*)header;
    reassembled->ipv6_hdr = new_ip6;
    *((uint8_t*)new_ip6 + previous_nh_offset) = next_header;
    new_ip6->payload_len = htons((uint16_t)payload_len);
    reassembled->protocol = next_header;

    reassembled->flag.is_defrag = 1;

    destroy_ipq6(q);
    return reassembled;
}

/* ── IPv6 分片输出（仅源端执行）────────────────────────── */

bool ipv6_frag(skbuff* skb)
{
    if_info* info = skb->route->if_info;

    ipv6_hdr* ip6 = skb->ipv6_hdr;
    uint32_t mtu = info->mtu;
    uint32_t hdr_total = IPV6_HDR_LEN + sizeof(ipv6_frag_hdr);
    uint32_t tot_len = skb_data_len(skb);

    if (mtu < 1280 || tot_len <= IPV6_HDR_LEN)
        return false;
    if (tot_len <= mtu)
        return true;  /* 无需分片 */

    uint32_t mtu_payload = mtu - hdr_total;
    uint32_t frag_payload = mtu_payload & ~7u;  /* 8 字节对齐 */

    uint8_t hdr_copy[IPV6_HDR_LEN];
    memcpy(hdr_copy, ip6, IPV6_HDR_LEN);
    uint8_t orig_next_hdr = ip6->next_hdr;

    /* Remove the fixed header, split only fragmentable payload, then prepend
     * fixed + Fragment headers to each fragment. */
    if (skb_consume(skb, IPV6_HDR_LEN, true) != IPV6_HDR_LEN)
        return false;
    uint32_t first_payload = frag_payload;
    skbuff* cur = skb_split(skb, first_payload);
    if (!cur)
        return false;

    uint8_t* first_headers = skb_data_push(skb, hdr_total);
    if (!first_headers) {
        PUT_REF(cur);
        return false;
    }
    memcpy(first_headers, hdr_copy, IPV6_HDR_LEN);
    ip6 = (ipv6_hdr*)first_headers;
    ipv6_frag_hdr* fh_first = (ipv6_frag_hdr*)(first_headers + IPV6_HDR_LEN);
    fh_first->next_hdr = orig_next_hdr;
    fh_first->reserved = 0;
    ipv6_frag_set(fh_first, 0, true);
    static _Atomic(uint32_t) frag_id = 1;
    fh_first->id = htonl(atomic_fetch_add_explicit(&frag_id, 1,
                                                   memory_order_relaxed));

    /* 更新第一个分片的 IPv6 头 */
    ip6->next_hdr = IPV6_NEXTHDR_FRAG;
    ip6->payload_len = htons((uint16_t)(skb_data_len(skb) - IPV6_HDR_LEN));
    skb->ipv6_hdr = ip6;

    uint32_t offset_bytes = first_payload;
    list_node* list_tail = &skb->frag_list;

    /* 后续分片 */
    while (cur) {
        uint32_t cur_payload = skb_data_len(cur);
        skbuff* next = NULL;
        if (cur_payload > frag_payload) {
            next = skb_split(cur, frag_payload);
            if (!next)
                goto fail;
            cur_payload = frag_payload;
        }

        /* 推入 IPv6 头 + Fragment EH */
        ipv6_frag_hdr* fh = (ipv6_frag_hdr*)
            skb_data_push(cur, IPV6_HDR_LEN + sizeof(*fh));
        if (!fh) {
            PUT_REF(next);
            goto fail;
        }
        ipv6_hdr* frag_ip6 = (ipv6_hdr*)fh;
        memcpy(frag_ip6, hdr_copy, IPV6_HDR_LEN);
        fh = (ipv6_frag_hdr*)(frag_ip6 + 1);

        fh->next_hdr = orig_next_hdr;
        fh->reserved = 0;
        bool is_last = (next == NULL);
        ipv6_frag_set(fh, (uint16_t)(offset_bytes / 8u), !is_last);
        fh->id = fh_first->id;  /* 同一包的所有分片共享 ID */

        frag_ip6->next_hdr = IPV6_NEXTHDR_FRAG;
        frag_ip6->payload_len = htons((uint16_t)(sizeof(*fh) + cur_payload));
        cur->ipv6_hdr = frag_ip6;
        cur->frag_list.element = (uint64_t)cur;
        add_list_node(list_tail, &cur->frag_list);
        list_tail = &cur->frag_list;

        offset_bytes += cur_payload;
        cur = next;
    }

    /* Individual IP fragments are not complete L4 packets and therefore
     * must not request AF_XDP L4 checksum offload. */
    skb->l4_hdr = NULL;
    skb->tx_checksum_offset = 0;
    return true;

fail:
    PUT_REF(cur);
    {
        skbuff* frag;
        list_node* tnode;
        FOR_EACH_LIST_SAFE_OFFSET(&skb->frag_list, frag, tnode, skbuff, frag_list) {
            remove_list_node(&frag->frag_list);
            PUT_REF(frag);
        }
    }
    return false;
}
