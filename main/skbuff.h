#ifndef SKBUFF_H
#define SKBUFF_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>
#include "list.h"
#include "queue.h"
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

#define SKB_DATA_MAX_NUM 32

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
			uint32_t seq;
			uint8_t flag;
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
		list_node tcp_list;
	};
	list_node queue_node;  /* socket queues: send/recv/retransmit */
	list_node tx_node;     /* XDP pending_tx_queue */

	if_info* recv_if;
	uint8_t data_num;
	uint32_t data_total_len;
	data_info data0;
	struct route_info* route;
	ref_info ref;
} skbuff;

static inline skbuff *skb_from_queue_node(list_node *node)
{
	if (!node)
		return NULL;
	return (skbuff *)((uint8_t *)node - offsetof(skbuff, queue_node));
}

static inline skbuff *skb_from_tx_node(list_node *node)
{
	if (!node)
		return NULL;
	return (skbuff *)((uint8_t *)node - offsetof(skbuff, tx_node));
}

#define SKB_FROM_QUEUE_NODE(n) skb_from_queue_node((n))
#define SKB_FROM_TX_NODE(n)    skb_from_tx_node((n))
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
	return (uint32_t)(skb->data0.start - skb->data0.slot->data);
}

static inline uint32_t skb_end_space(skbuff* skb)
{
	data_info* di = skb_end_data_info(skb);
	return (uint32_t)((di->slot->data + di->size) - di->end);
}
uint32_t skb_consume(skbuff* skb, uint32_t size, bool linear);
int  skb_send_frags(skbuff* skb);
bool skb_data_expand(skbuff* skb, uint32_t size, bool begin);
uint8_t* skb_data_push(skbuff* skb, uint32_t size);
uint8_t* skb_data_put(skbuff* skb, uint32_t size);

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
                     uint32_t pre_size, uint32_t seg_len);
bool skb_append_skb(skbuff* a, skbuff* b, bool data_copy);
skbuff* skb_alloc(uint32_t size);
skbuff* skb_alloc_with_data_info(data_info** infos);
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


#endif
