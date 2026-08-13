#include "ip_frag.h"

#include <string.h>

#include "base.h"
#include "hash.h"
#include "log.h"
#include "route_arp_ndp.h"
#include "skbuff.h"
#include "worker.h"

static inline hash* get_ipq_hash(void)
{
    return get_current_worker()->stack.ipq_hash;
}
static inline void update_ipq_timer(ipq* queue)
{
    queue->last_update_time = (uint32_t)get_current_time_ms();
}
static inline uint16_t ipv4_frag_field_get_host(const ipv4_hdr* ip){
    uint16_t field;
    memcpy(&field, ((const uint8_t*)ip) + 6, sizeof(field));
    return ntohs(field);
}

static inline bool ipv4_get_flag_df(const ipv4_hdr* ip)
{
    return (ipv4_frag_field_get_host(ip) & IPV4_FRAG_DF) != 0;
}

static inline bool ipv4_get_flag_mf(const ipv4_hdr* ip)
{
    return (ipv4_frag_field_get_host(ip) & IPV4_FRAG_MF) != 0;
}

static inline uint16_t ipv4_get_frag_offset(const ipv4_hdr* ip)
{
    return ipv4_frag_field_get_host(ip) & IPV4_FRAG_OFF_MASK;
}

static ipq* create_ipq(uint16_t id,uint32_t src_ip,uint32_t dst_ip,uint8_t protocol){
    hash* h = get_ipq_hash();

    ipq* new_ipq=calloc(1,sizeof(ipq));
    if(!new_ipq){
        return NULL;
    }

    memset(&new_ipq->key, 0, sizeof(new_ipq->key));
    new_ipq->key.id=id;
    new_ipq->key.src_ip=src_ip;
    new_ipq->key.dst_ip=dst_ip;
    new_ipq->key.protocol=protocol;

    update_ipq_timer(new_ipq);
    if (!hash_add_node(h, &new_ipq->hash_node)) {
        free(new_ipq);
        return NULL;
    }
    return new_ipq;
}
static void destroy_ipq(ipq* ipq){
    hash* h = get_ipq_hash();

    //DEBUG_LOG("Destroying IPQ: id=%u src=" IP_STR " dst=" IP_STR " proto=%u", ipq->key.id, IP_ARG(ipq->key.src_ip), IP_ARG(ipq->key.dst_ip), ipq->key.protocol);
    hash_del_node(h, &ipq->hash_node);
    list_node* node;
    list_node* tmp;
    FOR_EACH_LIST_SAFE(&ipq->frag_head, node, tmp){
        skbuff* frag_skb = (skbuff*)node->element;
        remove_list_node(node);
        PUT_REF(frag_skb);
    }
    free(ipq);
}
static ipq* search_ipq(uint16_t id,uint32_t src_ip,uint32_t dst_ip,uint8_t protocol){
    hash* h = get_ipq_hash();

    ipq_key key;
    /* ipq_key has padding; ensure deterministic bytes */
    memset(&key, 0, sizeof(key));
    key.id=id;
    key.src_ip=src_ip;
    key.dst_ip=dst_ip;
    key.protocol=protocol;
    hash_node* node = hash_find_node(h, &key);
    return node ? HASH_CONTAINER_OF(node, ipq, hash_node) : NULL;
}



void ipq_timer(task* tk){
    hash* h = get_ipq_hash();

    for (uint32_t i = 0; i < h->size; i++) {
        hash_node* node = h->buckets[i];
        while (node) {
            hash_node* next = node->next;
            ipq* queue = HASH_CONTAINER_OF(node, ipq, hash_node);
            if ((uint32_t)(get_current_time_ms() - queue->last_update_time) >
                IPQ_TIMEOUT)
                destroy_ipq(queue);
            node = next;
        }
    }

    update_task_timer(tk, get_current_time_ms() + IPQ_TIMER_INTERVAL);
}
bool ipv4_is_frag(const ipv4_hdr* ip){
    uint16_t f = ipv4_frag_field_get_host(ip);
    return ((f & 0x1FFFu) != 0) || ((f & 0x2000u) != 0);
}
static int skb_offset_cmp(list_node* a, list_node* b){
    skbuff* skb_a = (skbuff*)((uint8_t*)a - offsetof(skbuff, frag_list));
    skbuff* skb_b = (skbuff*)((uint8_t*)b - offsetof(skbuff, frag_list));
    uint32_t a_offset = ipv4_get_frag_offset(skb_a->ipv4_hdr);
    uint32_t b_offset = ipv4_get_frag_offset(skb_b->ipv4_hdr);
    if (a_offset < b_offset)
        return -1;
    return a_offset > b_offset;
}
skbuff* ipv4_defrag(skbuff* skb){
    ipv4_hdr* ip = skb->ipv4_hdr;
    uint16_t id = ntohs(ip->id);
    uint32_t src = ip->saddr;
    uint32_t dst = ip->daddr;
    uint8_t proto = ip->protocol;

    uint32_t ipv4_hdr_len = (uint32_t)IPV4_VHL_IHL(ip->vhl) * 4u;
    uint32_t payload_len = ntohs(ip->tot_len) - ipv4_hdr_len;
    uint32_t offset_bytes = (ipv4_get_frag_offset(ip)) * 8;

    if((ipv4_get_flag_mf(ip) && (payload_len & 7u)) || ipv4_get_flag_df(ip)){
        DEBUG_LOG("Invalid fragment: DF set or payload not 8-byte aligned");
        return NULL;
    }

    ipq* q = search_ipq(id, src, dst, proto);
    if(!q){
        q = create_ipq(id, src, dst, proto);
        if(!q){
            WARN_LOG("Failed to create IPQ for fragment");
            return NULL;
        }
    }

    INC_REF(skb);
    if(add_list_node_compare(&q->frag_head, &skb->frag_list, skb_offset_cmp) < 0){
        PUT_REF(skb);
        return NULL;
    }

    if (!ipv4_get_flag_mf(ip)) {
        q->flag.last_recved = 1;
        q->total_len = offset_bytes + payload_len;
    }
    if (ipv4_get_frag_offset(ip) == 0) {
        q->flag.first_recved = 1;
    }
    q->received_len += payload_len;

    /* Not all fragments received yet */
    if(!(q->flag.first_recved && q->flag.last_recved && q->received_len >= q->total_len)){
        return NULL;
    }
    if(q->received_len != q->total_len){
        destroy_ipq(q);
        return NULL;
    }

    skbuff* reassembled = NULL;
    uint32_t expect_offset = 0;
    skbuff* frag;
    list_node* tmp_node;
    FOR_EACH_LIST_SAFE_OFFSET(&q->frag_head, frag, tmp_node, skbuff, frag_list) {
        remove_list_node(&frag->frag_list);
        if (!reassembled) {
            reassembled = frag;
            expect_offset = (ntohs(reassembled->ipv4_hdr->tot_len) -
                ((uint32_t)IPV4_VHL_IHL(reassembled->ipv4_hdr->vhl) * 4u)) / 8;
        } else {
            if (ipv4_get_frag_offset(frag->ipv4_hdr) != expect_offset) {
                DEBUG_LOG("Fragment offset mismatch: expected=%u, got=%u",
                    expect_offset, ipv4_get_frag_offset(frag->ipv4_hdr));
                PUT_REF(frag);
                PUT_REF(reassembled);
                destroy_ipq(q);
                return NULL;
            }
            ipv4_hdr* frag_ip = frag->ipv4_hdr;
            uint32_t iphdr_len = (uint32_t)IPV4_VHL_IHL(frag_ip->vhl) * 4u;
            uint32_t frag_payload_len = ntohs(frag_ip->tot_len) - iphdr_len;
            skb_consume(frag, iphdr_len, true);
            if (reassembled->data_num + frag->data_num > SKB_DATA_MAX_NUM) {
                DEBUG_LOG("Too many fragments to reassemble");
                PUT_REF(frag);
                PUT_REF(reassembled);
                destroy_ipq(q);
                return NULL;
            }
            data_info* tail = skb_end_data_info(reassembled);
            const data_info* source = &frag->data0;
            while (source) {
                data_info* copied = malloc(sizeof(*copied));
                if (!copied) {
                    PUT_REF(frag);
                    PUT_REF(reassembled);
                    destroy_ipq(q);
                    return NULL;
                }
                copy_data_info(copied, source);
                tail->next = copied;
                tail = copied;
                reassembled->data_num++;
                source = source->next;
            }
            reassembled->data_total_len += frag_payload_len;
            expect_offset += frag_payload_len / 8;
            PUT_REF(frag);
        }
    }

    /* Reconstruct IP header */
    if (!reassembled) {
        destroy_ipq(q);
        return NULL;
    }

    ipv4_hdr* new_ip = reassembled->ipv4_hdr;
    new_ip->frag_off = 0;
    new_ip->tot_len = htons((uint16_t)(reassembled->data_total_len));
    new_ip->check = 0;
    new_ip->check = checksum(new_ip,
        (uint32_t)IPV4_VHL_IHL(new_ip->vhl) * 4u, 0);

    reassembled->protocol = new_ip->protocol;
    reassembled->flag.is_defrag = 1;

    destroy_ipq(q);
    return reassembled;
}

bool ipv4_frag(skbuff* skb){

    if_info* info = skb->route->if_info;
    ipv4_hdr* ip = skb->ipv4_hdr;

    uint32_t mtu = info->mtu;
    uint32_t ipv4_hdr_len = (uint32_t)IPV4_VHL_IHL(ip->vhl) * 4u;
    uint32_t tot_len = ntohs(ip->tot_len);
    uint16_t original_field = ipv4_frag_field_get_host(ip);

    if (tot_len <= mtu)
        return true;
    if(ipv4_get_flag_df(ip)){
        DEBUG_LOG("DF flag set, cannot fragment");
        return false;
    }

    uint32_t mtu_payload = mtu - ipv4_hdr_len;
    uint32_t frag_payload = mtu_payload & ~7u;

    uint8_t header[60];
    memcpy(header, ip, ipv4_hdr_len);
    const uint32_t base_offset =
        (uint32_t)(original_field & IPV4_FRAG_OFF_MASK) * 8u;
    const bool original_more = (original_field & IPV4_FRAG_MF) != 0;

    /* Keep the original skb as the first fragment.  skb_split returns the
       remaining payload, from which subsequent fragments are produced. */
    skbuff* cur = skb_split(skb, ipv4_hdr_len + frag_payload);
    if (!cur)
        return false;

    uint32_t offset = frag_payload;
    list_node* list_tail = &skb->frag_list;
    ip->frag_off = htons((uint16_t)((base_offset / 8u) | IPV4_FRAG_MF));
    ip->tot_len = htons((uint16_t)skb_data_len(skb));
    ip->check = 0;
    ip->check = checksum(ip, ipv4_hdr_len, 0);

    while (cur) {
        uint32_t payload_len = skb_data_len(cur);
        skbuff* next = NULL;
        if (payload_len > frag_payload) {
            next = skb_split(cur, frag_payload);
            if (!next)
                goto fail;
            payload_len = frag_payload;
        }

        ipv4_hdr* frag_ip = (ipv4_hdr*)skb_data_push(cur, ipv4_hdr_len);
        if (!frag_ip) {
            PUT_REF(next);
            goto fail;
        }
        memcpy(frag_ip, header, ipv4_hdr_len);
        uint16_t field = (uint16_t)((base_offset + offset) / 8u);
        if (next || original_more)
            field |= IPV4_FRAG_MF;
        frag_ip->frag_off = htons(field);
        frag_ip->tot_len = htons((uint16_t)(ipv4_hdr_len + payload_len));
        frag_ip->check = 0;
        frag_ip->check = checksum(frag_ip, ipv4_hdr_len, 0);
        cur->ipv4_hdr = frag_ip;
        add_list_node(list_tail, &cur->frag_list);
        list_tail = &cur->frag_list;

        offset += payload_len;
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
		list_node* tmp;
		FOR_EACH_LIST_SAFE_OFFSET(&skb->frag_list, frag, tmp, skbuff, frag_list) {
			remove_list_node(&frag->frag_list);
			PUT_REF(frag);
		}
	}
	return false;
}
