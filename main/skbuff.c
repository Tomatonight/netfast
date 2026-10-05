#include "skbuff.h"

#include <stddef.h>
#include <string.h>

#include "ether.h"
#include "log.h"
#include "route_arp_ndp.h"
#include "socket.h"
#include "worker.h"

int skb_send_frags(skbuff *skb)
{
    route_info *route = skb->route;

    /* 发送首片 */
    if (route->if_info->ops->send(route->if_info, skb) < 0)
        return -1;

    /* 发送其余分片 */
    skbuff *frag;
    list_node *tmp;
    FOR_EACH_LIST_SAFE_OFFSET(&skb->frag_list, frag, tmp, skbuff, frag_list) {
        remove_list_node(&frag->frag_list);
        if (frag->route->if_info->ops->send(frag->route->if_info, frag) < 0) {
            WARN_LOG("Failed to send fragment; stopping fragment transmission");
            PUT_REF(frag);
            /* Release every fragment that has not been sent yet. */
            FOR_EACH_LIST_SAFE_OFFSET(&skb->frag_list, frag, tmp,
                                     skbuff, frag_list) {
                remove_list_node(&frag->frag_list);
                PUT_REF(frag);
            }
            return -1;
        }
        PUT_REF(frag);
    }
    return 0;
}

uint8_t *skb_consume(skbuff *skb, uint32_t size, bool linear)
{
    uint8_t *start = skb_start(skb);
    if (size > skb->data_total_len)
        return NULL;
    if (!size)
        return start;
    if (linear) {
        if (size > skb_data0_len(skb))
            return NULL;
        skb->data0.start += size;
        skb->data_total_len -= size;
        return start;
    }

    uint32_t remaining = size;
    while (remaining) {
        uint32_t len = skb_data0_len(skb);
        if (remaining < len) {
            skb->data0.start += remaining;
            break;
        }
        remaining -= len;
        frame_slot *old_slot = skb->data0.slot;
        data_info *next = skb->data0.next;
        skb->data0 = *next;
        free(next);
        PUT_REF(old_slot);
        skb->data_num--;
    }
    skb->data_total_len -= size;
    return start;
}
//linger
bool skb_data_expand(skbuff *skb, uint32_t size, bool begin)
{

    if (begin) {
        data_info *di = &skb->data0;
        uint32_t pre_space = skb_pre_space(skb);
        if (pre_space >= size) {
            di->start -= size;
            skb->data_total_len += size;
            return true;
        }
    } else {
        data_info *di = skb_end_data_info(skb);
        uint32_t end_space = skb_end_space(skb);
        if (end_space >= size) {
            di->end += size;
            skb->data_total_len += size;
            return true;
        }
    }
    return false;
}

uint8_t *skb_data_push(skbuff *skb, uint32_t size, uint32_t alloc_size)
{
    if (skb_data_expand(skb, size, true))
        return skb_start(skb);
    if (!alloc_size || alloc_size < size)
        return NULL;

    data_info *old_first = malloc(sizeof(*old_first));
    if (!old_first)
        return NULL;
    frame_slot *slot = frame_slot_alloc(alloc_size);
    if (!slot) {
        free(old_first);
        return NULL;
    }
    *old_first = skb->data0;
    skb->data0.slot = slot;
    skb->data0.buf_start = slot->data;
    skb->data0.buf_end = slot->data + slot->slot_size;
    skb->data0.start = slot->data + alloc_size - size;
    skb->data0.end = slot->data + alloc_size;
    skb->data0.next = old_first;
    skb->data_num++;
    skb->data_total_len += size;
    return skb_start(skb);
}

uint8_t *skb_data_put(skbuff *skb, uint32_t size, uint32_t alloc_size)
{
    data_info *target = &skb->data0;
    data_info *tail = &skb->data0;
    for (data_info *di = &skb->data0; di; di = di->next) {
        if (di->end != di->start)
            target = di;
        tail = di;
    }

    for (data_info *di = target; di; di = di->next) {
        uint32_t available = (uint32_t)
            (di->buf_end - di->end);
        if (available < size)
            continue;
        uint8_t *data = di->end;
        di->end += size;
        skb->data_total_len += size;
        return data;
    }
    if (!alloc_size || alloc_size < size)
        return NULL;

    data_info *added = alloc_data_info(alloc_size);
    if (!added)
        return NULL;
    added->end = added->start + size;
    tail->next = added;
    skb->data_num++;
    skb->data_total_len += size;
    return added->start;
}

void skb_truncate(skbuff *skb, uint32_t new_len)
{
    uint32_t cur = skb->data_total_len;
    if (new_len >= cur)
        return;
    if (!new_len) {
        data_info *next = skb->data0.next;
        while (next) {
            data_info *tmp = next;
            next = next->next;
            free_data_info(tmp);
        }
        PUT_REF(skb->data0.slot);
        memset(&skb->data0, 0, sizeof(skb->data0));
        skb->data_num = 0;
        skb->data_total_len = 0;
        return;
    }
    uint32_t cum = 0;
    data_info *di = &skb->data0;
    while (di) {
        uint32_t len = di->end - di->start;
        if (cum + len >= new_len) {
            di->end = di->start + (new_len - cum);
            break;
        }
        cum += len;
        di = di->next;
    }

    data_info *next = di->next;
    di->next = NULL;
    while (next) {
        data_info *tmp = next;
        next = next->next;
        free_data_info(tmp);
        skb->data_num --;
    }
    skb->data_total_len = new_len;
}

bool skb_data_append(skbuff *skb, const void *buf, uint32_t size,
                     uint32_t alloc_size)
{
    if (!size)
        return true;

    const uint8_t *src = (const uint8_t*)buf;
    uint32_t remaining = size;

    /* 从最后一个已有数据的节点开始，后面的空节点均为 skb_alloc()
     * 预先分配的容量。 */
    data_info *append = &skb->data0;
    data_info *chain_tail = &skb->data0;
    for (data_info *di = &skb->data0; di; di = di->next) {
        if (di->end != di->start)
            append = di;
        chain_tail = di;
    }

    uint64_t available = 0;
    for (data_info *di = append; di; di = di->next)
        available += (uint32_t)(di->buf_end - di->end);

    /* 先分配所有缺少的 slot，失败时 skb 保持不变。单个 slot 的大小
     * 仍受 frame cache 限制，但 skb 的 slot 数量不再设固定上限。 */
    data_info *added = NULL;
    data_info *added_tail = NULL;
    uint32_t added_count = 0;
    if (available < remaining) {
        if (!alloc_size)
            return false;
        uint32_t capacity = alloc_size;
        uint64_t needed = remaining - available;

        while (needed) {
            data_info *di = alloc_data_info(alloc_size);
            if (!di) {
                while (added) {
                    data_info *next = added->next;
                    free_data_info(added);
                    added = next;
                }
                return false;
            }
            if (added_tail)
                added_tail->next = di;
            else
                added = di;
            added_tail = di;
            added_count++;
            needed -= min(needed, (uint64_t)capacity);
        }

        chain_tail->next = added;
        skb->data_num += added_count;
    }

    for (data_info *di = append; di && remaining; di = di->next) {
        uint32_t available_in_slot = (uint32_t)
            (di->buf_end - di->end);
        uint32_t chunk = min(remaining, available_in_slot);
        if (!chunk)
            continue;
        memcpy(di->end, src, chunk);
        di->end += chunk;
        skb->data_total_len += chunk;
        src += chunk;
        remaining -= chunk;
    }
    return remaining == 0;
}

/* ── original skbuff.c ── */

bool skb_copy_bits(const skbuff *skb, uint32_t offset, void *dst, uint32_t len)
{
    if (len > skb->data_total_len - offset)
        return false;
    uint8_t *out = dst;
    const data_info *di = &skb->data0;
    uint32_t pos = 0;

    /* Skip data_infos before the offset. */
    while (di) {
        uint32_t n = di->end - di->start;
        if (pos + n > offset)
            break;
        pos += n;
        di = di->next;
    }

    /* Copy across remaining data_infos. */
    while (di && len) {
        uint32_t n = di->end - di->start;
        uint32_t in = offset > pos ? offset - pos : 0;
        uint32_t take = n - in < len ? n - in : len;
        memcpy(out, di->start + in, take);
        out += take;
        len -= take;
        offset += take;
        pos += n;
        di = di->next;
    }
    return len == 0;
}

uint16_t skb_checksum(const skbuff *skb, uint32_t len, uint32_t start_sum)
{

    uint32_t sum = start_sum;
    uint8_t pending = 0;
    bool has_pending = false;
    const data_info *di = &skb->data0;

    while (di && len) {
        uint32_t n = di->end - di->start;
        if (n > len) n = len;
        const uint8_t *data = di->start;

        if (has_pending && n) {
            uint8_t pair[2] = {pending, *data};
            sum = checksum_partial(pair, sizeof(pair), sum);
            data++;
            n--;
            len--;
            has_pending = false;
        }

        uint32_t even = n & ~1u;
        if (even) {
            sum = checksum_partial(data, even, sum);
            data += even;
            n -= even;
            len -= even;
        }
        if (n) {
            pending = *data;
            has_pending = true;
            len--;
        }
        di = di->next;
    }
    if (has_pending)
        sum = checksum_partial(&pending, 1, sum);
    while (sum >> 16)
        sum = (sum & 0xffffu) + (sum >> 16);
    return (uint16_t)~sum;
}

uint16_t skb_checksum_protocol(const skbuff *skb, uint32_t len,
                               uint32_t saddr, uint32_t daddr, uint8_t protocol)
{
    uint32_t sum = checksum_partial(&saddr, sizeof(saddr), 0);
    sum = checksum_partial(&daddr, sizeof(daddr), sum);
    uint16_t net_proto = htons((uint16_t)protocol);
    uint16_t net_len   = htons((uint16_t)len);
    sum = checksum_partial(&net_proto, sizeof(net_proto), sum);
    sum = checksum_partial(&net_len,   sizeof(net_len),   sum);
    if (!skb)
        return (uint16_t)~checksum(NULL, 0, sum);
    return skb_checksum(skb, len, sum);
}

uint16_t skb_checksum_protocol6(const skbuff *skb, uint32_t len,
                                const uint8_t saddr[16],
                                const uint8_t daddr[16], uint8_t protocol)
{
    uint32_t sum = checksum_partial(saddr, 16, 0);
    sum = checksum_partial(daddr, 16, sum);
    uint32_t net_len = htonl(len);
    uint8_t tail[4] = {0, 0, 0, protocol};
    sum = checksum_partial(&net_len, sizeof(net_len), sum);
    sum = checksum_partial(tail, sizeof(tail), sum);
    if (!skb)
        return (uint16_t)~checksum(NULL, 0, sum);
    return skb_checksum(skb, len, sum);
}

static void *skb_rebase_data_ptr(const skbuff *old_skb, const skbuff *new_skb, const void *ptr)
{
    if (!ptr)
        return NULL;

    const uint8_t *p = (const uint8_t*)ptr;
    const data_info *old_di = &old_skb->data0;
    const data_info *new_di = &new_skb->data0;

    while (old_di && new_di) {
        if (p >= old_di->start && p < old_di->end)
            return new_di->start + (uint32_t)(p - old_di->start);
        old_di = old_di->next;
        new_di = new_di->next;
    }
    return NULL;
}

skbuff *skb_alloc(uint32_t size)
{
    CREATE_REF(skbuff, skb, skb_destroy);
    if (!skb)
        return NULL;

    uint32_t chunk = min(size, (uint32_t)FRAME_SLOT_MAX_SIZE);
    frame_slot *slot = frame_slot_alloc(chunk);
    if (!slot) {
        PUT_REF(skb);
        return NULL;
    }
    skb->data0.slot  = slot;
    skb->data0.buf_start = slot->data;
    skb->data0.buf_end = slot->data + slot->slot_size;
    skb->data0.start = skb->data0.buf_start;
    skb->data0.end   = skb->data0.start; /* empty, ready for reserve/push/put */
    skb->data0.next  = NULL;
    skb->data_num    = 1;
    skb->data_total_len = 0;

    uint32_t remaining = size - chunk;
    data_info *tail = &skb->data0;
    while (remaining) {
        chunk = min(remaining, (uint32_t)FRAME_SLOT_MAX_SIZE);
        data_info *di = alloc_data_info(chunk);
        if (!di) {
            PUT_REF(skb);
            return NULL;
        }
        tail->next = di;
        tail = di;
        skb->data_num++;
        remaining -= chunk;
    }
    return skb;
}

skbuff *skb_alloc_with_data_info(data_info *infos)
{
    CREATE_REF(skbuff, skb, skb_destroy);
    if (!skb)
        return NULL;

    skb->data0 = *infos;
    free(infos);
    for (data_info *di = &skb->data0; di; di = di->next) {
        skb->data_total_len += (uint32_t)(di->end - di->start);
        skb->data_num++;
    }
    return skb;
}

skbuff *skb_clone(skbuff *skb) {
    CREATE_REF(skbuff, new_skb, skb_destroy);
    if (!new_skb)
        return NULL;

    new_skb->family   = skb->family;
    new_skb->protocol = skb->protocol;
    new_skb->tx_checksum_offset = skb->tx_checksum_offset;
    new_skb->sock     = skb->sock;
    new_skb->l4_private = skb->l4_private;

    data_info *orig = &skb->data0;
    data_info *prev = NULL;
    while (orig) {
        data_info *dst;
        if (!prev) {
            dst = &new_skb->data0;
        } else {
            dst = (data_info*)malloc(sizeof(*dst));
            if (!dst) {
                PUT_REF(new_skb);
                return NULL;
            }
            prev->next = dst;
        }
        dst->slot  = orig->slot;
        INC_REF(orig->slot);
        dst->buf_start = orig->buf_start;
        dst->buf_end = orig->buf_end;
        dst->start = orig->start;
        dst->end   = orig->end;
        dst->next  = NULL;
        prev = dst;
        new_skb->data_num++;
        orig = orig->next;
    }
    new_skb->data_total_len = skb->data_total_len;

    new_skb->l2_hdr = skb->l2_hdr;
    new_skb->l3_hdr = skb->l3_hdr;
    new_skb->l4_hdr = skb->l4_hdr;

    new_skb->flag = skb->flag;
    new_skb->flag.is_clone = 1;

    GET_REF(new_skb->recv_if,    skb->recv_if);
    GET_REF(new_skb->route, skb->route);
    new_skb->route_generation = skb->route_generation;
    memcpy(new_skb->route_dest, skb->route_dest, sizeof(new_skb->route_dest));
    new_skb->route_scope_id = skb->route_scope_id;

    return new_skb;
}

skbuff *skb_copy(skbuff *skb)
{
    CREATE_REF(skbuff, new_skb, skb_destroy);
    if (!new_skb)
        return NULL;

    new_skb->family   = skb->family;
    new_skb->protocol = skb->protocol;
    new_skb->tx_checksum_offset = skb->tx_checksum_offset;
    new_skb->sock     = skb->sock;
    new_skb->l4_private = skb->l4_private;

    data_info *orig = &skb->data0;
    data_info *prev = NULL;
    while (orig) {
        uint32_t n = orig->end - orig->start;
        uint32_t buf_start = (uint32_t)(orig->buf_start - orig->slot->data);
        uint32_t buf_end = (uint32_t)(orig->buf_end - orig->slot->data);
        uint32_t headroom = (uint32_t)(orig->start - orig->buf_start);
        data_info *dst;

        if (!prev) {
            dst = &new_skb->data0;
            frame_slot *slot = frame_slot_alloc(buf_end);
            if (!slot) {
                PUT_REF(new_skb);
                return NULL;
            }
            dst->slot  = slot;
            dst->buf_start = slot->data + buf_start;
            dst->buf_end = dst->buf_start + (buf_end - buf_start);
            dst->start = dst->buf_start + headroom;
            dst->end   = dst->start + n;
        } else {
            dst = alloc_data_info(buf_end);
            if (dst) {
                dst->buf_start = dst->slot->data + buf_start;
                dst->buf_end = dst->buf_start + (buf_end - buf_start);
                dst->start = dst->buf_start + headroom;
                dst->end = dst->start + n;
                prev->next = dst;
            }
        }
        if (!dst) {
            PUT_REF(new_skb);
            return NULL;
        }
        memcpy(dst->start, orig->start, n);
        dst->next = NULL;
        prev = dst;
        new_skb->data_num++;
        orig = orig->next;
    }
    new_skb->data_total_len = skb->data_total_len;

    new_skb->l2_hdr = skb_rebase_data_ptr(skb, new_skb, skb->l2_hdr);
    new_skb->l3_hdr = skb_rebase_data_ptr(skb, new_skb, skb->l3_hdr);
    new_skb->l4_hdr = skb_rebase_data_ptr(skb, new_skb, skb->l4_hdr);

    new_skb->flag = skb->flag;
    new_skb->flag.is_copy = 1;

    GET_REF(new_skb->recv_if,    skb->recv_if);
    GET_REF(new_skb->route, skb->route);
    new_skb->route_generation = skb->route_generation;
    memcpy(new_skb->route_dest, skb->route_dest, sizeof(new_skb->route_dest));
    new_skb->route_scope_id = skb->route_scope_id;

    return new_skb;
}

void skb_free_frag_list(skbuff *skb)
{
    skbuff *frag;
    list_node *next;
    FOR_EACH_LIST_SAFE_OFFSET(&skb->frag_list, frag, next,
                             skbuff, frag_list) {
        remove_list_node(&frag->frag_list);
        PUT_REF(frag);
    }
}

void skb_destroy(skbuff *skb) {
    /* A fragment list is owned by its root skb. */
    skb_free_frag_list(skb);

    PUT_REF(skb->recv_if);
    PUT_REF(skb->route);

    /* Free linked data_infos (data0 is embedded, rest are malloc'd). */
    data_info *di = skb->data0.next;
    while (di) {
        data_info *tmp = di;
        di = di->next;
        free_data_info(tmp);
    }
    PUT_REF(skb->data0.slot);
    free(skb);
}

bool skb_frag(skbuff * skb, uint32_t frag_len)
{
       /* skb is an owned packet; only a zero fragment length is invalid. */
       if (!frag_len)
        return false;

    list_node *list_tail = &skb->frag_list;
    while (skb_data_len(skb) > frag_len) {
        skbuff *frag_tail = skb_split(skb, frag_len);
        if (!frag_tail)
            return false;
        add_list_node(list_tail, &frag_tail->frag_list);
        list_tail = &frag_tail->frag_list;
        skb = frag_tail;
    }
    return true;
}

skbuff *skb_split(skbuff *skb, uint32_t len)
{
    if (len >= skb->data_total_len)
        return NULL;

    data_info *prev = NULL;
    data_info *split_di = &skb->data0;
    uint32_t cut = 0;
    uint32_t cum = 0;

    while (split_di) {
        uint32_t n = split_di->end - split_di->start;
        if (cum + n > len) {
            cut = len - cum;
            break;        /* split inside this data_info → stays in source, truncated */
        }
        cum += n;
        prev = split_di;
        split_di = split_di->next;
        if (cum == len)
            break;        /* exact boundary → split_di is first tail node */
    }

    CREATE_REF(skbuff, tail, skb_destroy);
    if (!tail)
        return NULL;

    uint32_t tail_count = 0;
    if (cut && split_di) {
        uint8_t *split = split_di->start + cut;
        data_info *di = malloc(sizeof(*di));
        if (!di) {
            PUT_REF(tail);
            return NULL;
        }
        di->slot = split_di->slot;
        INC_REF(di->slot);
        /* Split both the data range and the writable range.  The two
         * data_info nodes then share storage without sharing writable bytes. */
        di->buf_start = split;
        di->buf_end = split_di->buf_end;
        di->start = split;
        di->end = split_di->end;
        di->next = NULL;
        tail->data0 = *di;
        free(di);
        tail_count = 1;
        data_info *rest = split_di->next;
        tail->data0.next = rest;
        split_di->buf_end = split;
        split_di->end = split;
        split_di->next = NULL;
        for (data_info *di_it = rest; di_it; di_it = di_it->next)
            tail_count++;
    } else {
        if (!prev || !split_di) {
            PUT_REF(tail);
            return NULL;
        }
        prev->next = NULL;
        tail->data0 = *split_di;
        free(split_di);
        for (data_info *di_it = &tail->data0; di_it; di_it = di_it->next)
            tail_count++;
    }

    tail->data_num = tail_count;
    tail->data_total_len = skb->data_total_len - len;
    skb->data_num -= tail_count - (cut ? 1U : 0U);
    skb->data_total_len = len;

    tail->family   = skb->family;
    tail->protocol = skb->protocol;
    tail->sock     = skb->sock;
    tail->l4_private = skb->l4_private;
    GET_REF(tail->recv_if, skb->recv_if);
    GET_REF(tail->route,  skb->route);
    tail->route_generation = skb->route_generation;
    memcpy(tail->route_dest, skb->route_dest, sizeof(tail->route_dest));
    tail->route_scope_id = skb->route_scope_id;

    return tail;
}

bool skb_append_skb(skbuff *a, skbuff *b)
{
    if (!b->data_total_len) {
        PUT_REF(b);
        return true;
    }

    data_info *tail = skb_end_data_info(a);
    uint32_t tail_space = tail->buf_end && tail->end
        ? (uint32_t)(tail->buf_end - tail->end) : 0;
    uint32_t copy_len = min(tail_space, b->data_total_len);
    data_info *move_head = NULL;
    data_info *move_prev = NULL;
    data_info *partial = NULL;
    uint32_t move_skip = 0;

    /* Locate the first byte that will remain zero-copy.  Allocate the only
     * metadata node that may be needed before changing either skb, so an
     * allocation failure leaves both packets untouched. */
    uint32_t skip = copy_len;
    data_info *di = &b->data0;
    data_info *prev = NULL;
    while (di && skip) {
        uint32_t len = (uint32_t)(di->end - di->start);
        if (skip < len)
            break;
        skip -= len;
        prev = di;
        di = di->next;
    }
    while (di && di->start == di->end && di->next) {
        prev = di;
        di = di->next;
    }
    if (di && di == &b->data0) {
        partial = malloc(sizeof(*partial));
        if (!partial)
            return false;
        copy_data_info(partial, di);
        partial->start += skip;
        partial->next = di->next;
        move_head = partial;
        move_prev = prev;
    } else if (di) {
        move_head = di;
        move_prev = prev;
        move_skip = skip;
    }

    if (copy_len && !skb_copy_bits(b, 0, tail->end, copy_len)) {
        if (partial)
            free_data_info(partial);
        return false;
    }

    if (copy_len) {
        tail->end += copy_len;
        a->data_total_len += copy_len;
    }
    if (move_head && move_head != partial && move_skip)
        move_head->start += move_skip;

    if (!move_head) {
        PUT_REF(b);
        return true;
    }

    if (move_head == partial) {
        /* b->data0 is embedded, so the first remaining data_info must use a
         * heap node while retaining b's frame slot through a ref. */
        b->data0.next = NULL;
    } else {
        move_prev->next = NULL;
    }

    data_info *moved_tail = move_head;
    uint32_t moved_count = 1;
    while (moved_tail->next) {
        moved_tail = moved_tail->next;
        moved_count++;
    }
    tail->next = move_head;
    a->data_num += moved_count;
    a->data_total_len += b->data_total_len - copy_len;

    PUT_REF(b);
    return true;
}
