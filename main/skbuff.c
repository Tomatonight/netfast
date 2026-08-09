#include"skbuff.h"
#include"socket.h"
#include"route_arp_ndp.h"
#include"worker.h"
#include"ether.h"
#include"log.h"
#include <stddef.h>
#include <string.h>


int skb_send_frags(skbuff* skb)
{
	route_info* route = skb->route;

	/* 发送首片 */
	if (route->if_info->ops->send(route->if_info, skb) < 0)
		goto cleanup;

	/* 发送其余分片 */
	skbuff* frag;
	list_node* tmp;
	FOR_EACH_LIST_SAFE_OFFSET(&skb->frag_list, frag, tmp, skbuff, frag_list) {
		remove_list_node(&frag->frag_list);
		if (frag->route->if_info->ops->send(frag->route->if_info, frag) < 0)
			WARN_LOG("Failed to send fragment");
		PUT_REF(frag);
	}
	return 0;

cleanup:
	{
		skbuff* f;
		list_node* t;
		FOR_EACH_LIST_SAFE_OFFSET(&skb->frag_list, f, t, skbuff, frag_list) {
			remove_list_node(&f->frag_list);
			PUT_REF(f);
		}
	}
	return -1;
}

uint32_t skb_consume(skbuff* skb, uint32_t size, bool linear)
{
	uint32_t consumed = min(size, skb->data_total_len);
	if (!consumed)
		return 0;
	if (linear) {
		consumed = min(consumed, skb_data0_len(skb));
		skb->data0.start += consumed;
		if (!skb_data0_len(skb)) {
			frame_slot* old_slot = skb->data0.slot;
			if (skb->data_num > 1) {
				data_info* next = skb->data0.next;
				skb->data0 = *next;
				free(next);
				skb->data_num--;
			} else {
				memset(&skb->data0, 0, sizeof(skb->data0));
				skb->data_num = 0;
			}
			PUT_REF(old_slot);
		}
		skb->data_total_len -= consumed;
		return consumed;
	}

	uint32_t remaining = consumed;
	while (remaining) {
		uint32_t len = skb_data0_len(skb);
		if (remaining < len) {
			skb->data0.start += remaining;
			break;
		}
		remaining -= len;
		frame_slot* old_slot = skb->data0.slot;
		if (skb->data_num == 1) {
			memset(&skb->data0, 0, sizeof(skb->data0));
			skb->data_num = 0;
			PUT_REF(old_slot);
			break;
		}
		data_info* next = skb->data0.next;
		skb->data0 = *next;
		free(next);
		PUT_REF(old_slot);
		skb->data_num--;
	}
	skb->data_total_len -= consumed;
	return consumed;
}
//linger
bool skb_data_expand(skbuff* skb, uint32_t size, bool begin)
{

	if(begin){
		data_info* di = &skb->data0;
		uint32_t pre_space = skb_pre_space(skb);
		if(pre_space >= size){
			di->start -= size;
			skb->data_total_len += size;
			return true;
		}
	}else{
		data_info* di = skb_end_data_info(skb);
		uint32_t end_space = skb_end_space(skb);
		if(end_space >= size){
			di->end += size;
			skb->data_total_len += size;
			return true;
		}
	}
	return false;
}

uint8_t* skb_data_push(skbuff* skb, uint32_t size)
{
	if (skb_data_expand(skb, size, true))
		return skb_start(skb);
	if (skb->data_num >= SKB_DATA_MAX_NUM)
		return NULL;

	data_info* old_first = malloc(sizeof(*old_first));
	if (!old_first)
		return NULL;
	frame_slot* slot = frame_slot_alloc(size);
	if (!slot) {
		free(old_first);
		return NULL;
	}
	*old_first = skb->data0;
	skb->data0.slot = slot;
	skb->data0.start = slot->data;
	skb->data0.end = slot->data + size;
	skb->data0.next = old_first;
	skb->data0.size = slot->slot_size;
	skb->data_num++;
	skb->data_total_len += size;
	return skb_start(skb);
}

uint8_t* skb_data_put(skbuff* skb, uint32_t size)
{
	uint8_t* end = skb_end(skb);
	if(!skb_data_expand(skb, size, false))
		return NULL;
	return end;
}

void skb_truncate(skbuff* skb, uint32_t new_len)
{
	uint32_t cur = skb->data_total_len;
	if (new_len >= cur)
		return;
	if (!new_len) {
		data_info* next = skb->data0.next;
		while (next) {
			data_info* tmp = next;
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
	data_info* di = &skb->data0;
	while(di){
		uint32_t len = di->end - di->start;
		if(cum + len >= new_len){
			di->end = di->start + (new_len - cum);
			break;
		}
		cum += len;
		di = di->next;
	}
	if (!di) {
		ERR_LOG("skb_truncate: data chain shorter than data_total_len");
		return;
	}
	data_info* next = di->next;
	di->next = NULL;
	while(next){
		data_info* tmp = next;
		next = next->next;
		free_data_info(tmp);
		skb->data_num --;
	}
	skb->data_total_len = new_len;
}

bool skb_data_append(skbuff* skb, const void* buf, uint32_t size,
                     uint32_t pre_size, uint32_t seg_len)
{
	const uint8_t* src = (const uint8_t*)buf;
	uint32_t remaining = size;

	uint32_t capacity = seg_len - pre_size;

	data_info* last_data_info = skb_end_data_info(skb);
	data_info* last = last_data_info;
	uint8_t* original_end = last_data_info->end;
	uint32_t original_total = skb->data_total_len;
	uint8_t original_count = skb->data_num;
	uint32_t end_space = skb_end_space(skb);
	if ((uint64_t)end_space + (uint64_t)capacity *
	    (SKB_DATA_MAX_NUM - skb->data_num) < remaining)
		return false;

	/* An empty initial data_info can hold the first chunk.  Never extend a
	 * non-empty one: seg_len defines the caller's segment boundary. */
	if (end_space) {
		uint32_t use = min(remaining, end_space);
		uint8_t* dst = skb_data_put(skb, use);
		memcpy(dst, src, use);
		src += use;
		remaining -= use;
	}

	/* Allocate new data_infos for remaining data. */
	while (remaining > 0) {
		uint32_t chunk = remaining < capacity ? remaining : capacity;
		data_info* di = alloc_data_info(seg_len);
		if (!di)
			goto rollback;

		di->start = di->slot->data + pre_size;
		di->end   = di->start + chunk;
		skb->data_total_len += chunk;
		memcpy(di->start, src, chunk);
		src += chunk;
		remaining -= chunk;
		last->next = di;
		last = di;
		skb->data_num++;
	}
	return true;

rollback:
	last = last_data_info->next;
	last_data_info->next = NULL;
	while (last) {
		data_info* tmp = last;
		last = last->next;
		free_data_info(tmp);
	}
	last_data_info->end = original_end;

	skb->data_total_len = original_total;
	skb->data_num = original_count;
	return false;
}

/* ── original skbuff.c ── */

bool skb_copy_bits(const skbuff* skb, uint32_t offset, void* dst, uint32_t len)
{
	if (len > skb->data_total_len - offset)
		return false;
	uint8_t* out = dst;
	const data_info* di = &skb->data0;
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

uint16_t skb_checksum(const skbuff* skb, uint32_t len, uint32_t start_sum)
{

	uint32_t sum = start_sum;
	uint8_t pending = 0;
	bool has_pending = false;
	const data_info* di = &skb->data0;

	while (di && len) {
		uint32_t n = di->end - di->start;
		if (n > len) n = len;
		const uint8_t* data = di->start;

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

uint16_t skb_checksum_protocol(const skbuff* skb, uint32_t len,
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

uint16_t skb_checksum_protocol6(const skbuff* skb, uint32_t len,
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

static void* skb_rebase_data_ptr(const skbuff* old_skb, const skbuff* new_skb, const void* ptr)
{
	if (!ptr)
		return NULL;

	const uint8_t* p = (const uint8_t*)ptr;
	const data_info* old_di = &old_skb->data0;
	const data_info* new_di = &new_skb->data0;

	while (old_di && new_di) {
		if (p >= old_di->start && p < old_di->end)
			return new_di->start + (uint32_t)(p - old_di->start);
		old_di = old_di->next;
		new_di = new_di->next;
	}
	return NULL;
}
skbuff* skb_alloc(uint32_t size)
{
	CREATE_REF(skbuff, skb, skb_destroy);
	if (!skb)
		return NULL;
	frame_slot* slot = frame_slot_alloc(size);
	if (!slot) {
		PUT_REF(skb);
		return NULL;
	}
	skb->data0.slot  = slot;
	skb->data0.start = slot->data;
	skb->data0.end   = slot->data;      /* empty, ready for reserve/push/put */
	skb->data0.size  = size ? size : slot->slot_size;
	skb->data0.next  = NULL;
	skb->data_num    = 1;
	skb->data_total_len = 0;
	return skb;
}

skbuff* skb_alloc_with_data_info(data_info** infos)
{

	CREATE_REF(skbuff, skb, skb_destroy);
	if (!skb)
		return NULL;

	data_info* prev = NULL;
	for (int i = 0; i < SKB_DATA_MAX_NUM; i++) {
		if (!infos[i])
			break;
		uint32_t len = (uint32_t)(infos[i]->end - infos[i]->start);
		if (i == 0) {
			skb->data0 = *infos[i];
			skb->data0.next = NULL;
			free(infos[i]);
			prev = &skb->data0;
		} else {
			prev->next = infos[i];
			prev = infos[i];
			prev->next = NULL;
		}
		skb->data_total_len += len;
		skb->data_num++;
	}
	return skb;
}

skbuff* skb_clone(skbuff* skb){

	CREATE_REF(skbuff, new_skb, skb_destroy);
	if (!new_skb)
		return NULL;

	new_skb->family   = skb->family;
	new_skb->protocol = skb->protocol;
	new_skb->tx_checksum_offset = skb->tx_checksum_offset;
	new_skb->sock     = skb->sock;
	new_skb->l4_private = skb->l4_private;

	data_info* orig = &skb->data0;
	data_info* prev = NULL;
	while (orig) {
		data_info* dst;
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
		dst->start = orig->start;
		dst->end   = orig->end;
		dst->size  = orig->size;
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

	return new_skb;
}

skbuff* skb_copy(skbuff* skb)
{
	CREATE_REF(skbuff, new_skb, skb_destroy);
	if (!new_skb)
		return NULL;

	new_skb->family   = skb->family;
	new_skb->protocol = skb->protocol;
	new_skb->tx_checksum_offset = skb->tx_checksum_offset;
	new_skb->sock     = skb->sock;
	new_skb->l4_private = skb->l4_private;

	data_info* orig = &skb->data0;
	data_info* prev = NULL;
	while (orig) {
		uint32_t n = orig->end - orig->start;
		uint32_t headroom = (uint32_t)(orig->start - orig->slot->data);
		data_info* dst;

		if (!prev) {
			dst = &new_skb->data0;
			frame_slot* slot = frame_slot_alloc(orig->size);
			if (!slot) {
				PUT_REF(new_skb);
				return NULL;
			}
			dst->slot  = slot;
			dst->start = slot->data + headroom;
			dst->end   = dst->start + n;
			dst->size  = orig->size;
		} else {
			dst = alloc_data_info(orig->size);
			if (dst) {
				dst->start = dst->slot->data + headroom;
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

	return new_skb;
}

void skb_destroy(skbuff* skb){

	PUT_REF(skb->recv_if);
	PUT_REF(skb->route);

	/* Free linked data_infos (data0 is embedded, rest are malloc'd). */
	data_info* di = skb->data0.next;
	while (di) {
		data_info* tmp = di;
		di = di->next;
		free_data_info(tmp);
	}
	PUT_REF(skb->data0.slot);
	free(skb);
}

skbuff* skb_split(skbuff* skb, uint32_t len)
{
	if (len >= skb->data_total_len)
		return NULL;

	data_info* prev = NULL;
	data_info* split_di = &skb->data0;
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

	uint8_t tail_count = 0;
	if (cut && split_di) {
		uint32_t tail_len = (uint32_t)(split_di->end - (split_di->start + cut));
		uint32_t headroom = (uint32_t)(split_di->start - split_di->slot->data);
		data_info* di = alloc_data_info(split_di->size);
		if (!di) {
			PUT_REF(tail);
			return NULL;
		}
		di->start = di->slot->data + headroom;
		di->end   = di->start + tail_len;
		memcpy(di->start, split_di->start + cut, tail_len);
		tail->data0 = *di;
		free(di);
		tail_count = 1;
		data_info* rest = split_di->next;
		tail->data0.next = rest;
		split_di->end = split_di->start + cut;
		split_di->next = NULL;
		for (data_info* di_it = rest; di_it; di_it = di_it->next)
			tail_count++;
	} else {
		if (!prev || !split_di) {
			PUT_REF(tail);
			return NULL;
		}
		prev->next = NULL;
		tail->data0 = *split_di;
		free(split_di);
		for (data_info* di_it = &tail->data0; di_it; di_it = di_it->next)
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

	return tail;
}

bool skb_append_skb(skbuff* a, skbuff* b, bool data_copy)
{
	if (!data_copy && a->data_num + b->data_num > SKB_DATA_MAX_NUM)
		return false;

    if (data_copy) {
        /* Copy b's data into a's tail space. */
        uint32_t b_len = b->data_total_len;
        uint8_t* dst = skb_data_put(a, b_len);
        if (!dst)
            return false;

        /* Copy all data from b into the expanded region. */
        const data_info* b_di = &b->data0;
        while (b_di && b_len) {
            uint32_t n = b_di->end - b_di->start;
            memcpy(dst, b_di->start, n);
            dst += n;
            b_len -= n;
            b_di = b_di->next;
        }
		PUT_REF(b);
        return true;
    }

	data_info* first = malloc(sizeof(*first));
	if (!first)
		return false;
	*first = b->data0;
	skb_end_data_info(a)->next = first;

	a->data_num += b->data_num;
	a->data_total_len += b->data_total_len;
	memset(&b->data0, 0, sizeof(b->data0));
	b->data_num = 0;
	b->data_total_len = 0;
	PUT_REF(b);
	return true;
}
