#ifndef SKBUFF_H
#define SKBUFF_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>
#include "list.h"
#include "queue.h"
#include "rb_tree.h"
#include "frame_cache.h"
#include "xdp.h"

/* Forward declarations to reduce header coupling. */
struct Socket;
struct worker;
struct route_info;
struct arp_info;
typedef struct if_info if_info;

struct ipv4_hdr;
struct ether_hdr;
struct udp_hdr;
struct tcp_hdr;
struct ipv6_hdr;
struct icmp_hdr;

typedef struct skbuff {
	mpscq_node node;
	int (*process)(struct skbuff* skb);

	int family;
	int protocol;
	/* Offset from l4_hdr to its checksum field.  Zero disables TX checksum
	 * offload. */
	uint16_t tx_checksum_offset;
	struct Socket* sock;
	union {
		struct {
			uint32_t seq;     /* TCP 序号空间的半开左边界。 */
			uint32_t seq_end; /* 半开右边界，包含 payload 及 SYN/FIN。 */
			uint8_t flag;
			uint8_t sack_state;
			/* Low two bits of the IPv4 TOS/IPv6 traffic class. */
			uint8_t ip_ecn;
			uint64_t pkt_send_ms; /* 最后成功提交发送的时间，0 表示尚未发送 */
		} tcp;
	} l4_private;
	union {
		struct ether_hdr* ether_hdr;
		void* l2_hdr;
	};
	union {
		struct ipv4_hdr* ipv4_hdr;
		struct ipv6_hdr* ipv6_hdr;
		void* l3_hdr;
	};
	union {
	struct udp_hdr* udp_hdr;
	struct tcp_hdr* tcp_hdr;
	struct icmp_hdr* icmp_hdr;
	void* l4_hdr;
	};

	struct {
		uint32_t is_clone : 1;
		uint32_t is_copy : 1;
		uint32_t is_frag : 1;
		uint32_t is_defrag : 1;
		uint32_t is_forward : 1;
		uint32_t is_hw_rcv_checksum : 1;
	} flag;
	union {
		list_node frag_list;
		struct rb_node reorder_node; /* TCP 乱序树，按 seq 排序 */
	};
	list_node queue_node;  /* socket queues: send/recv */
	list_node tx_node;     /* XDP pending_tx_queue */
	list_node rack_node;  /* 原始发送 skb 的 RACK 节点；克隆/复制不继承链接 */
	struct rb_node retransmit_node; /* TCP retransmit tree, ordered by seq */

	if_info* recv_if;
	uint32_t data_num; /* data_info 节点数，不设固定上限 */
	uint32_t data_total_len;
	data_info data0;
	struct route_info* route;
	uint64_t route_generation;
	uint8_t route_dest[16];
	uint32_t route_scope_id;
	ref_info ref;
} skbuff;

static inline skbuff *skb_from_node(const void *node, size_t offset)
{
    if (!node)
        return NULL;
    return (skbuff *)((const uint8_t *)node - offset);
}

#define SKB_FROM_NODE(n, member) \
    skb_from_node((n), offsetof(skbuff, member))
static inline data_info* skb_end_data_info(skbuff* skb){
	data_info* end = &skb->data0;
	while (end->next)
		end = end->next;
	return end;
}

static inline uint8_t* skb_start(skbuff* skb)
{
	return skb->data0.start;
}
static inline uint8_t* skb_end(skbuff* skb)
{
	return skb_end_data_info(skb)->end;
}
static inline uint32_t skb_data0_len(const skbuff* skb)
{
	return (uint32_t)(skb->data0.end - skb->data0.start);
}

static inline uint32_t skb_pre_space(skbuff* skb)
{
	return (uint32_t)(skb->data0.start - skb->data0.buf_start);
}

static inline uint32_t skb_end_space(skbuff* skb)
{
	data_info* di = skb_end_data_info(skb);
	return (uint32_t)(di->buf_end - di->end);
}
/* Consuming all data keeps the final data_info/frame_slot as an empty buffer.
 * Returns the data start before consuming, or NULL without modifying the skb
 * when the requested data is absent or a linear consume does not fit in the
 * first data segment. */
uint8_t* skb_consume(skbuff* skb, uint32_t size, bool linear);
int  skb_send_frags(skbuff* skb);
/* Detach and release every skb currently owned by frag_list. */
void skb_free_frag_list(skbuff* skb);
bool skb_data_expand(skbuff* skb, uint32_t size, bool begin);
/* Return a contiguous region of size bytes at the head/tail.  The returned
 * region never spans data_info nodes.  If alloc_size is zero, use existing
 * capacity only; otherwise alloc_size must be at least size and a segment
 * with at least alloc_size bytes is allocated when existing capacity is
 * insufficient.  Oversized allocations fail through the frame allocator. */
uint8_t* skb_data_push(skbuff* skb, uint32_t size, uint32_t alloc_size);
uint8_t* skb_data_put(skbuff* skb, uint32_t size, uint32_t alloc_size);

static inline uint32_t skb_data_len(const skbuff* skb)
{
	return skb->data_total_len;
}
static inline void skb_reserve(skbuff* skb, uint32_t size){
	skb->data0.start += size;
	skb->data0.end += size;
}

void skb_truncate(skbuff* skb, uint32_t new_len);
bool skb_data_append(skbuff* skb, const void* buf, uint32_t size,
                     uint32_t alloc_size);
/* Append b to a.  The available tail room in a is filled by copying first;
 * the remainder of b's data_info chain is then transferred without copying.
 * Ownership of b is consumed on success. */
bool skb_append_skb(skbuff* a, skbuff* b);
skbuff* skb_alloc(uint32_t size);
/* 成功时接管整条 infos 链，失败时所有权仍属于调用者。 */
skbuff* skb_alloc_with_data_info(data_info* infos);
skbuff* skb_clone(skbuff* skb);
skbuff* skb_copy(skbuff* skb);
skbuff* skb_split(skbuff* skb, uint32_t len);
uint16_t skb_checksum(const skbuff* skb, uint32_t len, uint32_t start_sum);
uint16_t skb_checksum_protocol(const skbuff* skb, uint32_t len,
                              uint32_t saddr, uint32_t daddr, uint8_t protocol);
uint16_t skb_checksum_protocol6(const skbuff* skb, uint32_t len,
                                const uint8_t saddr[16],
                                const uint8_t daddr[16], uint8_t protocol);
bool skb_copy_bits(const skbuff* skb, uint32_t offset, void* dst, uint32_t len);
void skb_destroy(skbuff* skb);

/* Split data in order into chunks of at most frag_len bytes.
 * Returns false for invalid arguments or allocation failure. On allocation
 * failure, completed fragments remain linked and the last fragment retains
 * all remaining data so the caller can release the partial chain. */
bool skb_frag(skbuff* skb, uint32_t frag_len);

#endif
