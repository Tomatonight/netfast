#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "base.h"
#include "init.h"
#include "ip.h"
#include "loopback.h"
#include "netfast.h"
#include "ipv6_ext.h"
#include "route_arp_ndp.h"
#include "skbuff.h"
#include "socket.h"
#include "tcp.h"
#include "udp.h"
#include "worker.h"
#include "xdp.h"

#include "test_common.h"

static worker test_worker;
static pthread_t worker_thread;
static atomic_bool worker_running;

#ifndef NDEBUG
#define TEST_TCP_DROP_RULE_MAX 4u

typedef struct test_tcp_drop_rule {
    atomic_bool enabled;
    atomic_uint_least32_t seq;
    atomic_uint attempts;
    atomic_uint drops_left;
} test_tcp_drop_rule;

static atomic_bool test_drop_tcp_data;
static atomic_bool test_delay_duplicate_tcp_data;
static skbuff *test_delayed_tcp_data;
static if_info *test_loopback_if;
static test_tcp_drop_rule test_tcp_drop_rules[TEST_TCP_DROP_RULE_MAX];

typedef struct test_tcp_sack_capture {
    atomic_uint packets;
    atomic_uint blocks;
    atomic_uint option_len;
    atomic_uint tcp_header_len;
    atomic_uint_least32_t ack;
    atomic_uint_least32_t left;
    atomic_uint_least32_t right;
} test_tcp_sack_capture;

static atomic_uint test_tcp_sack_watch_port;
static atomic_uint test_tcp_sack_syn_permitted;
static atomic_uint test_tcp_sack_synack_permitted;
static test_tcp_sack_capture test_tcp_sack_wire;

static const uint8_t *test_tcp_find_option(const tcp_hdr *hdr, uint8_t wanted,
                                           uint8_t *found_len)
{
    uint32_t hdr_len = (uint32_t)(hdr->doff_res_flags >> 4) * 4u;
    if (hdr_len < sizeof(*hdr) || hdr_len > MAX_TCP_HDR_LEN)
        return NULL;

    const uint8_t *options = (const uint8_t *)hdr + sizeof(*hdr);
    uint32_t options_len = hdr_len - sizeof(*hdr);
    for (uint32_t offset = 0; offset < options_len;) {
        uint8_t kind = options[offset];
        if (kind == 0)
            break;
        if (kind == 1) {
            offset++;
            continue;
        }
        if (offset + 1u >= options_len)
            break;
        uint8_t len = options[offset + 1u];
        if (len < 2u || offset + len > options_len)
            break;
        if (kind == wanted) {
            *found_len = len;
            return options + offset;
        }
        offset += len;
    }
    return NULL;
}

static void test_tcp_sack_capture_reset(uint16_t server_port)
{
    atomic_store_explicit(&test_tcp_sack_watch_port, htons(server_port),
                          memory_order_release);
    atomic_store_explicit(&test_tcp_sack_syn_permitted, 0,
                          memory_order_relaxed);
    atomic_store_explicit(&test_tcp_sack_synack_permitted, 0,
                          memory_order_relaxed);
    atomic_store_explicit(&test_tcp_sack_wire.packets, 0,
                          memory_order_relaxed);
    atomic_store_explicit(&test_tcp_sack_wire.blocks, 0,
                          memory_order_relaxed);
    atomic_store_explicit(&test_tcp_sack_wire.option_len, 0,
                          memory_order_relaxed);
    atomic_store_explicit(&test_tcp_sack_wire.tcp_header_len, 0,
                          memory_order_relaxed);
    atomic_store_explicit(&test_tcp_sack_wire.ack, 0,
                          memory_order_relaxed);
    atomic_store_explicit(&test_tcp_sack_wire.left, 0,
                          memory_order_relaxed);
    atomic_store_explicit(&test_tcp_sack_wire.right, 0,
                          memory_order_relaxed);
}

static void test_tcp_capture_sack_options(const skbuff *skb)
{
    if (!skb || skb->protocol != IPPROTO_TCP || !skb->tcp_hdr)
        return;

    uint16_t server_port = (uint16_t)atomic_load_explicit(
        &test_tcp_sack_watch_port, memory_order_acquire);
    if (!server_port)
        return;

    const tcp_hdr *hdr = skb->tcp_hdr;
    uint8_t option_len = 0;
    if (hdr->flags & TCP_FLAG_SYN) {
        const uint8_t *option = test_tcp_find_option(
            hdr, TCP_OPTION_SACK_PERMITTED, &option_len);
        if (!option || option_len != 2u)
            return;
        if (hdr->dport == server_port && !(hdr->flags & TCP_FLAG_ACK)) {
            atomic_fetch_add_explicit(&test_tcp_sack_syn_permitted, 1,
                                      memory_order_release);
        } else if (hdr->sport == server_port &&
                   (hdr->flags & TCP_FLAG_ACK)) {
            atomic_fetch_add_explicit(&test_tcp_sack_synack_permitted, 1,
                                      memory_order_release);
        }
        return;
    }

    if (hdr->sport != server_port || !(hdr->flags & TCP_FLAG_ACK))
        return;
    const uint8_t *option = test_tcp_find_option(
        hdr, TCP_OPTION_SACK, &option_len);
    if (!option || option_len < 10u || ((option_len - 2u) % 8u) != 0)
        return;

    uint32_t left_n;
    uint32_t right_n;
    memcpy(&left_n, option + 2u, sizeof(left_n));
    memcpy(&right_n, option + 6u, sizeof(right_n));
    atomic_store_explicit(&test_tcp_sack_wire.blocks,
                          (option_len - 2u) / 8u,
                          memory_order_relaxed);
    atomic_store_explicit(&test_tcp_sack_wire.option_len, option_len,
                          memory_order_relaxed);
    atomic_store_explicit(&test_tcp_sack_wire.tcp_header_len,
                          (uint32_t)(hdr->doff_res_flags >> 4) * 4u,
                          memory_order_relaxed);
    atomic_store_explicit(&test_tcp_sack_wire.ack, ntohl(hdr->ack_seq),
                          memory_order_relaxed);
    atomic_store_explicit(&test_tcp_sack_wire.left, ntohl(left_n),
                          memory_order_relaxed);
    atomic_store_explicit(&test_tcp_sack_wire.right, ntohl(right_n),
                          memory_order_relaxed);
    atomic_fetch_add_explicit(&test_tcp_sack_wire.packets, 1,
                              memory_order_release);
}

static bool test_loopback_is_tcp_data(const skbuff *skb)
{
    if (!skb || skb->protocol != IPPROTO_TCP || !skb->tcp_hdr)
        return false;

    uint32_t total_len = skb_data_len(skb);
    uint32_t ip_len = skb->family == AF_INET6
        ? IPV6_HDR_LEN
        : (uint32_t)IPV4_VHL_IHL(skb->ipv4_hdr->vhl) * 4u;
    uint32_t tcp_len = (uint32_t)(skb->tcp_hdr->doff_res_flags >> 4) * 4u;
    return tcp_len >= sizeof(tcp_hdr) &&
           total_len > ip_len + tcp_len;
}

static void test_replay_delayed_tcp_data(void)
{
    skbuff *skb = test_delayed_tcp_data;
    test_delayed_tcp_data = NULL;
    if (!skb)
        return;
    (void)loopback_send(test_loopback_if, skb);
    PUT_REF(skb);
}

static void test_tcp_drop_rules_reset(void)
{
    for (uint32_t i = 0; i < TEST_TCP_DROP_RULE_MAX; i++) {
        atomic_store_explicit(&test_tcp_drop_rules[i].enabled, false,
                              memory_order_release);
        atomic_store_explicit(&test_tcp_drop_rules[i].seq, 0,
                              memory_order_relaxed);
        atomic_store_explicit(&test_tcp_drop_rules[i].attempts, 0,
                              memory_order_relaxed);
        atomic_store_explicit(&test_tcp_drop_rules[i].drops_left, 0,
                              memory_order_relaxed);
    }
}

static void test_tcp_drop_rule_arm(uint32_t index, uint32_t seq,
                                   uint32_t drops)
{
    if (index >= TEST_TCP_DROP_RULE_MAX)
        return;
    atomic_store_explicit(&test_tcp_drop_rules[index].seq, seq,
                          memory_order_relaxed);
    atomic_store_explicit(&test_tcp_drop_rules[index].attempts, 0,
                          memory_order_relaxed);
    atomic_store_explicit(&test_tcp_drop_rules[index].drops_left, drops,
                          memory_order_relaxed);
    atomic_store_explicit(&test_tcp_drop_rules[index].enabled, true,
                          memory_order_release);
}

static uint32_t test_tcp_drop_rule_attempts(uint32_t index)
{
    if (index >= TEST_TCP_DROP_RULE_MAX)
        return 0;
    return atomic_load_explicit(&test_tcp_drop_rules[index].attempts,
                                memory_order_acquire);
}

static bool test_tcp_drop_rule_match(uint32_t seq)
{
    bool drop = false;
    for (uint32_t i = 0; i < TEST_TCP_DROP_RULE_MAX; i++) {
        test_tcp_drop_rule *rule = &test_tcp_drop_rules[i];
        if (!atomic_load_explicit(&rule->enabled, memory_order_acquire) ||
            atomic_load_explicit(&rule->seq, memory_order_relaxed) != seq)
            continue;

        atomic_fetch_add_explicit(&rule->attempts, 1,
                                  memory_order_acq_rel);
        uint32_t left = atomic_load_explicit(&rule->drops_left,
                                             memory_order_acquire);
        while (left &&
               !atomic_compare_exchange_weak_explicit(
                   &rule->drops_left, &left, left - 1u,
                   memory_order_acq_rel, memory_order_acquire)) {
        }
        if (left)
            drop = true;
    }
    return drop;
}

static int test_loopback_send(if_info *info, skbuff *skb)
{
    test_tcp_capture_sack_options(skb);
    if (test_loopback_is_tcp_data(skb)) {
        uint32_t seq = ntohl(skb->tcp_hdr->seq);
        test_replay_delayed_tcp_data();
        if (atomic_exchange_explicit(&test_delay_duplicate_tcp_data, false,
                                     memory_order_acq_rel))
            test_delayed_tcp_data = skb_clone(skb);
        if (atomic_exchange_explicit(&test_drop_tcp_data, false,
                                     memory_order_acq_rel))
            return 0;
        if (test_tcp_drop_rule_match(seq))
            return 0;
    }
    return loopback_send(info, skb);
}

static const if_ops test_loopback_ops = {
    .recv = test_loopback_send,
    .send = test_loopback_send,
    .update = loopback_update,
    .create = loopback_create,
};

static void test_drop_tcp_data_once(void)
{
    atomic_store_explicit(&test_drop_tcp_data, true, memory_order_release);
}

static void test_delay_duplicate_tcp_data_once(void)
{
    atomic_store_explicit(&test_delay_duplicate_tcp_data, true,
                          memory_order_release);
}
#endif

static void *run_test_worker(void *opaque)
{
    worker *worker = opaque;
    set_current_worker(worker);
    current_time_ms = read_now_ms();
    while (atomic_load_explicit(&worker_running, memory_order_acquire))
        (void)thread_step(worker->master);
    set_current_worker(NULL);
    return NULL;
}

static int setup_loopback_runtime(void)
{
    current_time_ms = read_now_ms();
    TEST_ASSERT(xdp_frame_pool_init() == 0);
    memset(&test_worker, 0, sizeof(test_worker));
    g_workers = &test_worker;
    g_worker_num = 1;
    main_worker = &test_worker;
    TEST_ASSERT(worker_init(&test_worker) == 0);
    TEST_ASSERT(route_init() == 0);
    TEST_ASSERT(tcp_metrics_init() == 0);
    TEST_ASSERT(loopback_init() == 0);
#ifndef NDEBUG
    test_loopback_if = search_if_by_name("loopback");
    TEST_ASSERT(test_loopback_if);
    test_loopback_if->ops = &test_loopback_ops;
#endif
    atomic_store_explicit(&worker_running, true, memory_order_release);
    TEST_ASSERT(pthread_create(&worker_thread, NULL, run_test_worker,
                               &test_worker) == 0);
    return 0;
}

static int wait_for_read(int fd, void *buffer, size_t len)
{
    const uint64_t deadline = read_now_ms() + 2000;
    while (read_now_ms() < deadline) {
        int ret = net_read(fd, buffer, (uint32_t)len);
        if (ret >= 0)
            return ret;
        if (errno != EAGAIN)
            return -1;
        struct timespec delay = {.tv_nsec = 1000000};
        nanosleep(&delay, NULL);
    }
    errno = ETIMEDOUT;
    return -1;
}

#ifndef NDEBUG
static int wait_for_read_exact_timeout(int fd, uint8_t *buffer, uint32_t len,
                                       uint32_t timeout_ms)
{
    uint32_t offset = 0;
    const uint64_t deadline = read_now_ms() + timeout_ms;
    while (offset < len && read_now_ms() < deadline) {
        int ret = net_read(fd, buffer + offset, len - offset);
        if (ret > 0) {
            offset += (uint32_t)ret;
            continue;
        }
        if (ret == 0 || errno != EAGAIN)
            return -1;
        struct timespec delay = {.tv_nsec = 1000000};
        nanosleep(&delay, NULL);
    }
    return offset == len ? 0 : -1;
}

static int wait_for_read_exact(int fd, uint8_t *buffer, uint32_t len)
{
    return wait_for_read_exact_timeout(fd, buffer, len, 4000u);
}

static int wait_for_tcp_fully_acked(int fd)
{
    const uint64_t deadline = read_now_ms() + 2000;
    while (read_now_ms() < deadline) {
        fd_entry *entry = hold_fd_entry(fd);
        if (!entry)
            return -1;
        tcp_pcb *pcb = ((Socket*)entry->value)->pcb;
        bool done = pcb->snd_una == pcb->snd_end;
        PUT_REF(entry);
        if (done)
            return 0;
        struct timespec delay = {.tv_nsec = 1000000};
        nanosleep(&delay, NULL);
    }
    return -1;
}

static int wait_for_queued_fin(int fd)
{
    const uint64_t deadline = read_now_ms() + 2000;
    while (read_now_ms() < deadline) {
        fd_entry *entry = hold_fd_entry(fd);
        if (!entry)
            return -1;
        tcp_pcb *pcb = ((Socket*)entry->value)->pcb;
        skbuff* queued = SKB_FROM_NODE(
            pcb->unordered_skb_list.next, tcp_list);
        bool done = queued && !pcb->tcp_flag.recv_fin &&
                    (queued->l4_private.tcp.flag & TCP_FLAG_FIN) &&
                    queued->l4_private.tcp.seq_end ==
                        queued->l4_private.tcp.seq +
                        skb_data_len(queued) + 1u &&
                    pcb->recv_sack_count &&
                    pcb->recv_sacks[0].left ==
                        queued->l4_private.tcp.seq &&
                    pcb->recv_sacks[0].right ==
                        queued->l4_private.tcp.seq_end &&
                    SEQ_GT(queued->l4_private.tcp.seq, pcb->rcv_nxt);
        PUT_REF(entry);
        if (done)
            return 0;
        struct timespec delay = {.tv_nsec = 1000000};
        nanosleep(&delay, NULL);
    }
    return -1;
}

static int wait_for_recv_buffer_len(int fd, uint32_t expected)
{
    const uint64_t deadline = read_now_ms() + 2000;
    while (read_now_ms() < deadline) {
        fd_entry *entry = hold_fd_entry(fd);
        if (!entry)
            return -1;
        Socket *sock = entry->value;
        bool done = sock->recv_buffer_len >= expected;
        PUT_REF(entry);
        if (done)
            return 0;
        struct timespec delay = {.tv_nsec = 1000000};
        nanosleep(&delay, NULL);
    }
    return -1;
}

static int replay_delayed_tcp_data(void *opaque)
{
    (void)opaque;
    test_replay_delayed_tcp_data();
    return 0;
}
#endif

static int wait_for_recvfrom(int fd, void *buffer, size_t len,
                             struct sockaddr_in *from, socklen_t *from_len)
{
    const uint64_t deadline = read_now_ms() + 2000;
    while (read_now_ms() < deadline) {
        int ret = net_recvfrom(fd, buffer, (uint32_t)len, MSG_DONTWAIT,
                               (struct sockaddr *)from, from_len);
        if (ret >= 0)
            return ret;
        if (errno != EAGAIN)
            return -1;
        struct timespec delay = {.tv_nsec = 1000000};
        nanosleep(&delay, NULL);
    }
    errno = ETIMEDOUT;
    return -1;
}

static uint32_t skb_chain_count(const skbuff *skb, uint32_t *total_len)
{
    uint32_t count = 0;
    uint32_t total = 0;
    for (const data_info *di = &skb->data0; di; di = di->next) {
        count++;
        total += (uint32_t)(di->end - di->start);
    }
    if (total_len)
        *total_len = total;
    return count;
}

static int test_skb_multisegment_clone_copy(void)
{
    worker allocation_worker = {0};
    allocation_worker.master = create_thread();
    TEST_ASSERT(allocation_worker.master);
    set_current_worker(&allocation_worker);

    uint8_t payload[3000];
    uint8_t copied[3000];
    for (uint32_t i = 0; i < sizeof(payload); ++i)
        payload[i] = (uint8_t)(i * 31u + 7u);

    skbuff *source = skb_alloc(128);
    TEST_ASSERT(source);
    TEST_ASSERT(skb_data_append(source, payload, sizeof(payload), 0, 1024));
    uint32_t total = 0;
    TEST_ASSERT(source->data_num > 1);
    TEST_ASSERT(skb_chain_count(source, &total) == source->data_num);
    TEST_ASSERT(total == sizeof(payload) && total == skb_data_len(source));
    source->l4_hdr = skb_start(source);
    source->tx_checksum_offset = 16;

    skbuff *clone = skb_clone(source);
    TEST_ASSERT(clone);
    TEST_ASSERT(clone->l4_hdr == source->l4_hdr);
    TEST_ASSERT(clone->tx_checksum_offset == 16);
    TEST_ASSERT(skb_chain_count(clone, &total) == clone->data_num);
    TEST_ASSERT(total == sizeof(payload));
    TEST_ASSERT(skb_copy_bits(clone, 0, copied, sizeof(copied)));
    TEST_ASSERT(memcmp(copied, payload, sizeof(payload)) == 0);

    skbuff *copy = skb_copy(source);
    TEST_ASSERT(copy);
    TEST_ASSERT(copy->l4_hdr == skb_start(copy));
    TEST_ASSERT(copy->tx_checksum_offset == 16);
    TEST_ASSERT(skb_chain_count(copy, &total) == copy->data_num);
    TEST_ASSERT(total == sizeof(payload));
    TEST_ASSERT(copy->data0.slot != source->data0.slot);
    TEST_ASSERT(skb_copy_bits(copy, 0, copied, sizeof(copied)));
    TEST_ASSERT(memcmp(copied, payload, sizeof(payload)) == 0);

    void *l4_hdr = source->l4_hdr;
    TEST_ASSERT(skb_data_push(source, 20));
    TEST_ASSERT(source->l4_hdr == l4_hdr);
    TEST_ASSERT(source->tx_checksum_offset == 16);

    skb_truncate(clone, 1500);
    TEST_ASSERT(skb_chain_count(clone, &total) == clone->data_num);
    TEST_ASSERT(total == 1500 && total == skb_data_len(clone));

    frame_slot* retained_slot = skb_end_data_info(clone)->slot;
    TEST_ASSERT(skb_consume(clone, skb_data_len(clone), false) == 1500);
    TEST_ASSERT(skb_data_len(clone) == 0);
    TEST_ASSERT(clone->data_num == 1);
    TEST_ASSERT(clone->data0.slot == retained_slot);
    TEST_ASSERT(clone->data0.start == clone->data0.end);

    skbuff* empty_clone = skb_clone(clone);
    TEST_ASSERT(empty_clone);
    TEST_ASSERT(skb_data_push(empty_clone, 20));
    frame_slot* linear_retained_slot = empty_clone->data0.slot;
    TEST_ASSERT(skb_consume(empty_clone, 20, true) == 20);
    TEST_ASSERT(skb_data_len(empty_clone) == 0);
    TEST_ASSERT(empty_clone->data_num == 1);
    TEST_ASSERT(empty_clone->data0.slot == linear_retained_slot);
    TEST_ASSERT(empty_clone->data0.start == empty_clone->data0.end);
    PUT_REF(empty_clone);

    skbuff *tail = skb_split(copy, 1500);
    TEST_ASSERT(tail);
    TEST_ASSERT(skb_chain_count(copy, &total) == copy->data_num);
    TEST_ASSERT(total == 1500 && total == skb_data_len(copy));
    TEST_ASSERT(skb_chain_count(tail, &total) == tail->data_num);
    TEST_ASSERT(total == sizeof(payload) - 1500 &&
                total == skb_data_len(tail));

    PUT_REF(tail);
    PUT_REF(copy);
    PUT_REF(clone);
    PUT_REF(source);
    set_current_worker(NULL);
    destroy_thread(allocation_worker.master);
    return 0;
}

static skbuff *make_ipv6_packet(uint32_t payload_len, uint8_t next_header,
                                uint32_t segment_len)
{
    uint8_t *packet = calloc(1, IPV6_HDR_LEN + payload_len);
    if (!packet)
        return NULL;

    ipv6_hdr *ip6 = (ipv6_hdr *)packet;
    ip6->vtf = ipv6_make_vtf(0, 0);
    ip6->payload_len = htons((uint16_t)payload_len);
    ip6->next_hdr = next_header;
    ip6->hop_limit = 64;
    ip6->saddr[15] = 1;
    ip6->daddr[15] = 2;
    for (uint32_t i = 0; i < payload_len; ++i)
        packet[IPV6_HDR_LEN + i] = (uint8_t)(i * 17u + 3u);

    skbuff *skb = skb_alloc(128);
    if (!skb || !skb_data_append(skb, packet, IPV6_HDR_LEN + payload_len,
                                 0, segment_len)) {
        PUT_REF(skb);
        skb = NULL;
    }
    free(packet);
    if (skb)
        skb->ipv6_hdr = (ipv6_hdr *)skb_start(skb);
    return skb;
}

static int test_ipv6_extension_fragmentation(void)
{
    worker allocation_worker = {0};
    allocation_worker.master = create_thread();
    TEST_ASSERT(allocation_worker.master);
    set_current_worker(&allocation_worker);
    allocation_worker.stack.ipq6_hash = hash_create(32,
        HASH_KEY_OFFSET(ipq6, hash_node, key), sizeof(ipq6_key));
    TEST_ASSERT(allocation_worker.stack.ipq6_hash);

    skbuff *plain = make_ipv6_packet(32, IPPROTO_UDP, 32);
    TEST_ASSERT(plain && !ipv6_has_frag(plain));
    PUT_REF(plain);

    skbuff *skb = make_ipv6_packet(4000, IPPROTO_UDP, 512);
    TEST_ASSERT(skb);
    if_info iface = {.mtu = 1280};
    route_info *route = calloc(1, sizeof(*route));
    TEST_ASSERT(route);
    INIT_REF(route, NULL);
    route->if_info = &iface;
    skb->route = route;
    TEST_ASSERT(ipv6_frag(skb));
    TEST_ASSERT(ipv6_has_frag(skb));

    skbuff *fragments[8] = {0};
    uint32_t count = 0;
    skbuff *fragment;
    list_node *next;
    FOR_EACH_LIST_SAFE_OFFSET(&skb->frag_list, fragment, next,
                              skbuff, frag_list) {
        TEST_ASSERT(count < 8);
        remove_list_node(&fragment->frag_list);
        fragments[count++] = fragment;
    }
    TEST_ASSERT(count >= 2);

    skbuff *reassembled = NULL;
    for (uint32_t i = count; i > 0; --i) {
        TEST_ASSERT(ipv6_has_frag(fragments[i - 1]));
        skbuff *result = ipv6_defrag(fragments[i - 1]);
        if (result)
            reassembled = result;
        PUT_REF(fragments[i - 1]);
    }
    skbuff *result = ipv6_defrag(skb);
    if (result)
        reassembled = result;
    PUT_REF(skb);

    TEST_ASSERT(reassembled);
    TEST_ASSERT(reassembled->flag.is_defrag);
    TEST_ASSERT(!ipv6_has_frag(reassembled));
    TEST_ASSERT(reassembled->protocol == IPPROTO_UDP);
    TEST_ASSERT(skb_data_len(reassembled) == IPV6_HDR_LEN + 4000);
    uint8_t data[64];
    TEST_ASSERT(skb_copy_bits(reassembled, IPV6_HDR_LEN, data, sizeof(data)));
    for (uint32_t i = 0; i < sizeof(data); ++i)
        TEST_ASSERT(data[i] == (uint8_t)(i * 17u + 3u));
    PUT_REF(reassembled);

    skbuff *pending = make_ipv6_packet(2000, IPPROTO_UDP, 512);
    TEST_ASSERT(pending);
    route_info *pending_route = calloc(1, sizeof(*pending_route));
    TEST_ASSERT(pending_route);
    INIT_REF(pending_route, NULL);
    pending_route->if_info = &iface;
    pending->route = pending_route;
    TEST_ASSERT(ipv6_frag(pending));
    skbuff *queued = (skbuff *)((uint8_t *)pending->frag_list.next -
                                offsetof(skbuff, frag_list));
    remove_list_node(&queued->frag_list);
    TEST_ASSERT(ipv6_defrag(queued) == NULL);
    PUT_REF(queued);
    while (pending->frag_list.next) {
        skbuff *rest = (skbuff *)((uint8_t *)pending->frag_list.next -
                                  offsetof(skbuff, frag_list));
        remove_list_node(&rest->frag_list);
        PUT_REF(rest);
    }
    PUT_REF(pending);
    task timer = {
        .task_type = TASK_TYPE_TIMER,
        .parent_thread = allocation_worker.master,
    };
    current_time_ms += IPQ6_TIMEOUT + 1;
    ipq6_timer(&timer);
    TEST_ASSERT(hash_is_empty(allocation_worker.stack.ipq6_hash));
    unregister_task(&timer);

    hash_destroy(allocation_worker.stack.ipq6_hash);
    set_current_worker(NULL);
    destroy_thread(allocation_worker.master);
    return 0;
}

static int test_tcp_unit_defaults_and_boundaries(void)
{
    Socket *socket = create_socket(AF_INET, SOCK_STREAM, 0);
    TEST_ASSERT(socket && socket->pcb);
    tcp_pcb *pcb = socket->pcb;
    TEST_ASSERT(pcb->state == TCP_STATE_CLOSED);
    TEST_ASSERT(pcb->retransmit_timeout == tcp_metrics_default_rto());
    TEST_ASSERT(pcb->keepalive_timeout == TCP_KEEPALIVE_TIMEOUT_MS_DEFAULT);
    TEST_ASSERT(pcb->persist_backoff == TCP_PERSIST_BACKOFF_MS_DEFAULT);
    TEST_ASSERT(pcb->retransmits_out == 0);
    TEST_ASSERT(pcb->persist_probes_out == 0);
    TEST_ASSERT(pcb->timewait_timeout == TCP_TIMEWAIT_TIMEOUT_MS_DEFAULT);
    TEST_ASSERT(pcb->ack_timeout == TCP_DELACK_TIMEOUT_MS_DEFAULT);
    TEST_ASSERT(pcb->connect_timeout == TCP_CONNECT_TIMEOUT_MS_DEFAULT);
    TEST_ASSERT(SEQ_LT(UINT32_MAX, 0) && SEQ_GT(0, UINT32_MAX));
    TEST_ASSERT(SEQ_LEQ(7, 7) && SEQ_GEQ(7, 7));

    current_time_ms = read_now_ms();
    pcb->fast_retransmit_deadline_ms = current_time_ms;
    pcb->nagle_deadline_ms = current_time_ms;
    pcb->retransmit_deadline_ms = current_time_ms;
    pcb->persist_deadline_ms = current_time_ms;
    pcb->finwait2_deadline_ms = current_time_ms;
    pcb->keepalive_deadline_ms = current_time_ms;
    pcb->timer_task->cb_timer(pcb->timer_task);
    TEST_ASSERT(pcb->fast_retransmit_deadline_ms == TCP_TIMER_STOP);
    TEST_ASSERT(pcb->nagle_deadline_ms == TCP_TIMER_STOP);
    TEST_ASSERT(pcb->retransmit_deadline_ms == TCP_TIMER_STOP);
    TEST_ASSERT(pcb->persist_deadline_ms == TCP_TIMER_STOP);
    TEST_ASSERT(pcb->finwait2_deadline_ms == TCP_TIMER_STOP);
    TEST_ASSERT(pcb->keepalive_deadline_ms == TCP_TIMER_STOP);

    pcb->rcv_wnd = 256u * 1024u;
    pcb->rcv_wnd_scale = TCP_RCV_WND_SCALE_DEFAULT;
    pcb->snd_wnd_scale = TCP_RCV_WND_SCALE_DEFAULT;
    TEST_ASSERT(tcp_should_send_window_scale(pcb, TCP_FLAG_SYN));
    TEST_ASSERT(!tcp_should_send_window_scale(
        pcb, TCP_FLAG_SYN | TCP_FLAG_ACK));
    TEST_ASSERT(!tcp_window_scale_negotiated(pcb));
    TEST_ASSERT(tcp_encode_window(pcb, TCP_FLAG_ACK) == 65535u);
    TEST_ASSERT(tcp_decode_window(pcb, 4096u, TCP_FLAG_ACK) == 4096u);

    pcb->tcp_flag.peer_wnd_scale_ok = 1;
    TEST_ASSERT(tcp_should_send_window_scale(
        pcb, TCP_FLAG_SYN | TCP_FLAG_ACK));
    TEST_ASSERT(tcp_window_scale_negotiated(pcb));
    TEST_ASSERT(tcp_encode_window(pcb, TCP_FLAG_SYN) == 65535u);
    TEST_ASSERT(tcp_encode_window(pcb, TCP_FLAG_ACK) == 4096u);
    TEST_ASSERT(tcp_decode_window(pcb, 4096u, TCP_FLAG_SYN) == 4096u);
    TEST_ASSERT(tcp_decode_window(pcb, 4096u, TCP_FLAG_ACK) == 256u * 1024u);

    pcb->snd_mss = 100;
    TEST_ASSERT(tcp_ca_init(pcb) == 0);
    TEST_ASSERT(pcb->snd_cwnd == 1000 &&
                pcb->ca.status == TCP_CA_STATUS_OPEN);
    uint64_t initial_cwnd = pcb->snd_cwnd;
    pcb->snd_nxt = pcb->snd_una + (uint32_t)pcb->snd_cwnd;
    tcp_ca_ack_bytes(pcb, 40, true);
    TEST_ASSERT(pcb->snd_cwnd == initial_cwnd);
    tcp_ca_ack_bytes(pcb, 60, true);
    TEST_ASSERT(pcb->snd_cwnd >= initial_cwnd);
    pcb->snd_nxt = 5000;
    tcp_ca_recv_repeat_ack(pcb, 3);
    TEST_ASSERT(pcb->ca.status == TCP_CA_STATUS_RECOVERY);
    tcp_ca_rto_timeout(pcb);
    TEST_ASSERT(pcb->ca.status == TCP_CA_STATUS_LOST &&
                pcb->snd_cwnd == 100);
    TEST_ASSERT(tcp_metrics_backoff(TCP_RETRANSMIT_TIMEOUT_MS_MAX) ==
                TCP_RETRANSMIT_TIMEOUT_MS_MAX);
    TEST_ASSERT(tcp_protocol_ops.release(socket, NULL) == 0);
    return 0;
}

static int test_udp_unit_defaults(void)
{
    Socket *socket = create_socket(AF_INET, SOCK_DGRAM, 0);
    TEST_ASSERT(socket && !socket->pcb);
    TEST_ASSERT(socket->send_queue.element_number == 0);
    TEST_ASSERT(udp_protocol_ops.release(socket, NULL) == 0);
    return 0;
}

static int test_bind_ephemeral_ports(void)
{
    netfast_port_range saved_range = g_cfg.source_port_range;
    g_cfg.source_port_range = (netfast_port_range){32000, 32150};
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = 0,
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };
    uint16_t tcp_ports[2] = {0};
    uint16_t udp_ports[2] = {0};
    int tcp_fds[2] = {-1, -1};
    int udp_fds[2] = {-1, -1};

    for (uint32_t i = 0; i < 2; ++i) {
        int fd = net_socket(AF_INET, SOCK_STREAM, 0);
        TEST_ASSERT(fd >= 0);
        tcp_fds[i] = fd;
        TEST_ASSERT(net_bind(fd, (struct sockaddr *)&address,
                             sizeof(address)) == 0);
        struct sockaddr_in bound = {0};
        socklen_t bound_len = sizeof(bound);
        TEST_ASSERT(net_getsockname(fd, (struct sockaddr *)&bound,
                                    &bound_len) == 0);
        TEST_ASSERT(bound_len == sizeof(bound));
        TEST_ASSERT(bound.sin_family == AF_INET);
        TEST_ASSERT(ntohs(bound.sin_port) >= g_cfg.source_port_range.first);
        TEST_ASSERT(ntohs(bound.sin_port) <= g_cfg.source_port_range.last);
        tcp_ports[i] = bound.sin_port;
        TEST_ASSERT(net_listen(fd, 1) == 0);
    }
    TEST_ASSERT(tcp_ports[0] != tcp_ports[1]);
    TEST_ASSERT(net_close(tcp_fds[0]) == 0);
    TEST_ASSERT(net_close(tcp_fds[1]) == 0);

    for (uint32_t i = 0; i < 2; ++i) {
        int fd = net_socket(AF_INET, SOCK_DGRAM, 0);
        TEST_ASSERT(fd >= 0);
        udp_fds[i] = fd;
        TEST_ASSERT(net_bind(fd, (struct sockaddr *)&address,
                             sizeof(address)) == 0);
        struct sockaddr_in bound = {0};
        socklen_t bound_len = sizeof(bound);
        TEST_ASSERT(net_getsockname(fd, (struct sockaddr *)&bound,
                                    &bound_len) == 0);
        TEST_ASSERT(bound_len == sizeof(bound));
        TEST_ASSERT(bound.sin_family == AF_INET);
        TEST_ASSERT(ntohs(bound.sin_port) >= g_cfg.source_port_range.first);
        TEST_ASSERT(ntohs(bound.sin_port) <= g_cfg.source_port_range.last);
        udp_ports[i] = bound.sin_port;
    }
    TEST_ASSERT(udp_ports[0] != udp_ports[1]);
    TEST_ASSERT(net_close(udp_fds[0]) == 0);
    TEST_ASSERT(net_close(udp_fds[1]) == 0);

    struct sockaddr_in6 address6 = {
        .sin6_family = AF_INET6,
        .sin6_port = 0,
        .sin6_addr = IN6ADDR_ANY_INIT,
    };
    int tcp6 = net_socket(AF_INET6, SOCK_STREAM, 0);
    TEST_ASSERT(tcp6 >= 0);
    TEST_ASSERT(net_bind(tcp6, (struct sockaddr *)&address6,
                         sizeof(address6)) == 0);
    struct sockaddr_in6 bound6 = {0};
    socklen_t bound6_len = sizeof(bound6);
    TEST_ASSERT(net_getsockname(tcp6, (struct sockaddr *)&bound6,
                                &bound6_len) == 0);
    TEST_ASSERT(bound6_len == sizeof(bound6));
    TEST_ASSERT(bound6.sin6_family == AF_INET6);
    TEST_ASSERT(ntohs(bound6.sin6_port) >= g_cfg.source_port_range.first);
    TEST_ASSERT(ntohs(bound6.sin6_port) <= g_cfg.source_port_range.last);
    TEST_ASSERT(net_listen(tcp6, 1) == 0);
    TEST_ASSERT(net_close(tcp6) == 0);

    int udp6 = net_socket(AF_INET6, SOCK_DGRAM, 0);
    TEST_ASSERT(udp6 >= 0);
    TEST_ASSERT(net_bind(udp6, (struct sockaddr *)&address6,
                         sizeof(address6)) == 0);
    memset(&bound6, 0, sizeof(bound6));
    bound6_len = sizeof(bound6);
    TEST_ASSERT(net_getsockname(udp6, (struct sockaddr *)&bound6,
                                &bound6_len) == 0);
    TEST_ASSERT(bound6_len == sizeof(bound6));
    TEST_ASSERT(bound6.sin6_family == AF_INET6);
    TEST_ASSERT(ntohs(bound6.sin6_port) >= g_cfg.source_port_range.first);
    TEST_ASSERT(ntohs(bound6.sin6_port) <= g_cfg.source_port_range.last);
    TEST_ASSERT(net_close(udp6) == 0);

    int denied = net_socket(AF_INET, SOCK_DGRAM, 0);
    TEST_ASSERT(denied >= 0);
    address.sin_port = htons(g_cfg.source_port_range.first - 1u);
    errno = 0;
    TEST_ASSERT(net_bind(denied, (struct sockaddr *)&address,
                         sizeof(address)) == -1);
    TEST_ASSERT(errno == EACCES);
    TEST_ASSERT(net_close(denied) == 0);
    g_cfg.source_port_range = saved_range;
    return 0;
}

static int test_tcp_loopback(void)
{
    const char request[] = "netfast tcp loopback";
    const char reply[] = "tcp reply";
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons(32101),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    int listener = net_socket(AF_INET, SOCK_STREAM, 0);
    int client = -1;
    int accepted = -1;
    TEST_ASSERT(listener >= 0);
    int reuse = 1;
    TEST_ASSERT(net_setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse,
                               sizeof(reuse)) == 0);
    int listener_rcvbuf = 16384;
    int listener_sndbuf = 32768;
    struct timeval listener_rcvtimeo = {.tv_sec = 1, .tv_usec = 2000};
    struct timeval listener_sndtimeo = {.tv_sec = 2, .tv_usec = 3000};
    struct linger listener_linger = {.l_onoff = 1, .l_linger = 2};
    TEST_ASSERT(net_setsockopt(listener, SOL_SOCKET, SO_RCVBUF,
                               &listener_rcvbuf,
                               sizeof(listener_rcvbuf)) == 0);
    TEST_ASSERT(net_setsockopt(listener, SOL_SOCKET, SO_SNDBUF,
                               &listener_sndbuf,
                               sizeof(listener_sndbuf)) == 0);
    TEST_ASSERT(net_setsockopt(listener, SOL_SOCKET, SO_RCVTIMEO,
                               &listener_rcvtimeo,
                               sizeof(listener_rcvtimeo)) == 0);
    TEST_ASSERT(net_setsockopt(listener, SOL_SOCKET, SO_SNDTIMEO,
                               &listener_sndtimeo,
                               sizeof(listener_sndtimeo)) == 0);
    TEST_ASSERT(net_setsockopt(listener, SOL_SOCKET, SO_LINGER,
                               &listener_linger,
                               sizeof(listener_linger)) == 0);
    TEST_ASSERT(net_setsockopt(listener, IPPROTO_TCP, TCP_NODELAY, &reuse,
                               sizeof(reuse)) == 0);
    TEST_ASSERT(net_bind(listener, (struct sockaddr *)&address,
                         sizeof(address)) == 0);
    TEST_ASSERT(net_listen(listener, 4) == 0);

    client = net_socket(AF_INET, SOCK_STREAM, 0);
    TEST_ASSERT(client >= 0);
    TEST_ASSERT(net_connect(client, (struct sockaddr *)&address,
                            sizeof(address)) == 0);
    accepted = net_accept(listener, NULL, NULL);
    TEST_ASSERT(accepted >= 0);

    fd_entry *client_entry = hold_fd_entry(client);
    fd_entry *accepted_entry = hold_fd_entry(accepted);
    TEST_ASSERT(client_entry && accepted_entry);
    tcp_pcb *client_pcb = ((Socket *)client_entry->value)->pcb;
    Socket *accepted_sock = (Socket *)accepted_entry->value;
    tcp_pcb *accepted_pcb = accepted_sock->pcb;
    TEST_ASSERT(tcp_window_scale_negotiated(client_pcb));
    TEST_ASSERT(tcp_window_scale_negotiated(accepted_pcb));
    TEST_ASSERT(client_pcb->snd_wnd_scale == TCP_RCV_WND_SCALE_DEFAULT);
    TEST_ASSERT(accepted_pcb->snd_wnd_scale == TCP_RCV_WND_SCALE_DEFAULT);
    TEST_ASSERT(client_pcb->snd_mss == accepted_pcb->rcv_mss);
    TEST_ASSERT(accepted_pcb->snd_mss == client_pcb->rcv_mss);
    TEST_ASSERT(client_pcb->rcv_mss > 536u);
    TEST_ASSERT(accepted_sock->recv_buffer_len_max ==
                (uint32_t)listener_rcvbuf);
    TEST_ASSERT(accepted_sock->send_buffer_len_max ==
                (uint32_t)listener_sndbuf);
    TEST_ASSERT(memcmp(&accepted_sock->recv_timeout, &listener_rcvtimeo,
                       sizeof(listener_rcvtimeo)) == 0);
    TEST_ASSERT(memcmp(&accepted_sock->send_timeout, &listener_sndtimeo,
                       sizeof(listener_sndtimeo)) == 0);
    TEST_ASSERT(accepted_sock->options.linger &&
                accepted_sock->linger_seconds == listener_linger.l_linger);
    TEST_ASSERT(accepted_pcb->tcp_options.nodelay);
    TEST_ASSERT(accepted_pcb->nagle_interval == 0);
    PUT_REF(accepted_entry);
    PUT_REF(client_entry);

    int client_rcvbuf = 4096;
    TEST_ASSERT(net_setsockopt(client, SOL_SOCKET, SO_RCVBUF, &client_rcvbuf,
                               sizeof(client_rcvbuf)) == 0);
    client_entry = hold_fd_entry(client);
    TEST_ASSERT(client_entry);
    client_pcb = ((Socket *)client_entry->value)->pcb;
    TEST_ASSERT(client_pcb->rcv_wnd == (uint32_t)client_rcvbuf);
    PUT_REF(client_entry);

    TEST_ASSERT(net_setsockopt(client, IPPROTO_TCP, TCP_NODELAY, &reuse,
                               sizeof(reuse)) == 0);
    client_entry = hold_fd_entry(client);
    TEST_ASSERT(client_entry);
    client_pcb = ((Socket *)client_entry->value)->pcb;
    TEST_ASSERT(client_pcb->tcp_options.nodelay);
    TEST_ASSERT(client_pcb->nagle_interval == 0);
    PUT_REF(client_entry);
    char buffer[64] = {0};
    TEST_ASSERT(net_fcntl(accepted, F_SETFL, O_NONBLOCK) == 0);

    TEST_ASSERT(net_write(client, request, sizeof(request)) ==
                (int)sizeof(request));
    memset(buffer, 0, sizeof(buffer));
    TEST_ASSERT(wait_for_read(accepted, buffer, sizeof(buffer)) ==
                (int)sizeof(request));
    TEST_ASSERT(memcmp(buffer, request, sizeof(request)) == 0);

    TEST_ASSERT(net_fcntl(client, F_SETFL, O_NONBLOCK) == 0);
    TEST_ASSERT(net_write(accepted, reply, sizeof(reply)) == (int)sizeof(reply));
    memset(buffer, 0, sizeof(buffer));
    TEST_ASSERT(wait_for_read(client, buffer, sizeof(buffer)) == (int)sizeof(reply));
    TEST_ASSERT(memcmp(buffer, reply, sizeof(reply)) == 0);
    TEST_ASSERT(net_close(accepted) == 0);
    TEST_ASSERT(net_close(client) == 0);
    TEST_ASSERT(net_close(listener) == 0);
    return 0;
}

#ifndef NDEBUG
static int make_tcp_pair(uint16_t port, int *listener, int *client,
                         int *accepted)
{
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    int one = 1;
    *listener = net_socket(AF_INET, SOCK_STREAM, 0);
    if (*listener < 0 ||
        net_setsockopt(*listener, SOL_SOCKET, SO_REUSEADDR,
                       &one, sizeof(one)) < 0 ||
        net_bind(*listener, (struct sockaddr*)&address,
                 sizeof(address)) < 0 ||
        net_listen(*listener, 4) < 0)
        return -1;

    *client = net_socket(AF_INET, SOCK_STREAM, 0);
    if (*client < 0 ||
        net_connect(*client, (struct sockaddr*)&address,
                    sizeof(address)) < 0)
        return -1;
    *accepted = net_accept(*listener, NULL, NULL);
    return *accepted < 0 ? -1 : 0;
}

typedef struct test_tcp_timer_snapshot {
    int fd;
    int result;
    uint32_t retransmits_out;
    uint32_t retransmit_timeout;
    uint32_t retransmit_queue_len;
    uint64_t snd_cwnd;
    uint32_t ca_mss;
    enum tcp_ca_status ca_status;
    uint64_t now_ms;
    uint64_t retransmit_deadline_ms;
    uint64_t task_deadline_ms;
} test_tcp_timer_snapshot;

static int test_capture_tcp_timer(void *opaque)
{
    test_tcp_timer_snapshot *snapshot = opaque;
    snapshot->result = -1;
    fd_entry *entry = hold_fd_entry(snapshot->fd);
    if (!entry)
        return -1;

    tcp_pcb *pcb = ((Socket *)entry->value)->pcb;
    snapshot->retransmits_out = pcb->retransmits_out;
    snapshot->retransmit_timeout = pcb->retransmit_timeout;
    snapshot->retransmit_queue_len =
        pcb->retransmit_queue.element_number;
    snapshot->snd_cwnd = pcb->snd_cwnd;
    snapshot->ca_mss = tcp_data_mss(pcb);
    snapshot->ca_status = pcb->ca.status;
    snapshot->now_ms = get_current_time_ms();
    snapshot->retransmit_deadline_ms =
        pcb->retransmit_deadline_ms;
    snapshot->task_deadline_ms = pcb->timer_task->timeout;
    snapshot->result = 0;
    PUT_REF(entry);
    return 0;
}

static int test_wait_for_rto_backoff(
    int fd, uint32_t expected_timeout,
    test_tcp_timer_snapshot *result)
{
    const uint64_t wait_deadline = read_now_ms() + 2000u;
    while (read_now_ms() < wait_deadline) {
        test_tcp_timer_snapshot snapshot = {
            .fd = fd,
            .result = -1,
        };
        submit_req_2_worker(
            &test_worker, &snapshot, test_capture_tcp_timer, true);
        if (snapshot.result < 0)
            return -1;
        if (snapshot.retransmits_out == 1u &&
            snapshot.retransmit_timeout == expected_timeout) {
            *result = snapshot;
            return 0;
        }
        struct timespec delay = {.tv_nsec = 1000000};
        nanosleep(&delay, NULL);
    }
    return -1;
}

static int test_tcp_rto_backoff_deadline(void)
{
    enum { TEST_DEADLINE_SLOP_MS = TCP_RTO_MIN_MS / 2u };
    int listener = -1, client = -1, accepted = -1;
    TEST_ASSERT(make_tcp_pair(32114, &listener, &client, &accepted) == 0);
    TEST_ASSERT(net_fcntl(accepted, F_SETFL, O_NONBLOCK) == 0);
    TEST_ASSERT(wait_for_tcp_fully_acked(client) == 0);

    fd_entry *client_entry = hold_fd_entry(client);
    TEST_ASSERT(client_entry);
    tcp_pcb *client_pcb = ((Socket *)client_entry->value)->pcb;
    uint32_t segment = tcp_data_mss(client_pcb);
    uint32_t first_seq = client_pcb->snd_nxt;
    client_pcb->snd_cwnd = max(client_pcb->snd_cwnd, segment * 2u);
    client_pcb->retransmit_timeout = TCP_RTO_MIN_MS;
    PUT_REF(client_entry);

    uint8_t *tx = malloc(segment);
    uint8_t *rx = malloc(segment);
    TEST_ASSERT(tx && rx);
    for (uint32_t i = 0; i < segment; i++)
        tx[i] = (uint8_t)(i * 61u + 29u);

    /* Drop the original and first timeout retransmission.  Clone only the
     * latter so it can be replayed after the timer state has been inspected. */
    test_tcp_drop_rules_reset();
    test_tcp_drop_rule_arm(0u, first_seq, 2u);
    TEST_ASSERT(net_write(client, tx, segment) == (int)segment);
    TEST_ASSERT(test_tcp_drop_rule_attempts(0u) == 1u);

    test_tcp_timer_snapshot initial = {
        .fd = client,
        .result = -1,
    };
    submit_req_2_worker(
        &test_worker, &initial, test_capture_tcp_timer, true);
    TEST_ASSERT(initial.result == 0);
    TEST_ASSERT(initial.retransmits_out == 0u);
    TEST_ASSERT(initial.retransmit_timeout == TCP_RTO_MIN_MS);
    TEST_ASSERT(initial.retransmit_queue_len == 1u);
    TEST_ASSERT(initial.retransmit_deadline_ms > initial.now_ms);
    TEST_ASSERT(initial.task_deadline_ms ==
                initial.retransmit_deadline_ms);

    test_delay_duplicate_tcp_data_once();
    uint32_t backed_off_timeout =
        tcp_metrics_backoff(TCP_RTO_MIN_MS);
    test_tcp_timer_snapshot backed_off = {0};
    TEST_ASSERT(test_wait_for_rto_backoff(
        client, backed_off_timeout, &backed_off) == 0);
    TEST_ASSERT(test_tcp_drop_rule_attempts(0u) == 2u);
    TEST_ASSERT(backed_off.retransmit_queue_len == 1u);
    TEST_ASSERT(backed_off.ca_status == TCP_CA_STATUS_LOST);
    TEST_ASSERT(backed_off.snd_cwnd == backed_off.ca_mss);

    /* tcp_ca_rto_timeout() changes cwnd while the RTO callback is
     * running.  Its send-timer update must not leave the expired/old RTO as
     * the task deadline; the final deadline uses the backed-off timeout. */
    TEST_ASSERT(backed_off.now_ms >= initial.retransmit_deadline_ms);
    TEST_ASSERT(backed_off.retransmit_deadline_ms >
                initial.retransmit_deadline_ms);
    TEST_ASSERT(backed_off.retransmit_deadline_ms > backed_off.now_ms);
    uint64_t remaining =
        backed_off.retransmit_deadline_ms - backed_off.now_ms;
    TEST_ASSERT(remaining <= backed_off_timeout);
    TEST_ASSERT(remaining + TEST_DEADLINE_SLOP_MS >=
                backed_off_timeout);
    TEST_ASSERT(backed_off.task_deadline_ms ==
                backed_off.retransmit_deadline_ms);

    submit_req_2_worker(
        &test_worker, NULL, replay_delayed_tcp_data, true);
    TEST_ASSERT(wait_for_read_exact(accepted, rx, segment) == 0);
    TEST_ASSERT(memcmp(tx, rx, segment) == 0);
    TEST_ASSERT(wait_for_tcp_fully_acked(client) == 0);
    test_tcp_drop_rules_reset();

    free(rx);
    free(tx);
    TEST_ASSERT(net_close(accepted) == 0);
    TEST_ASSERT(net_close(client) == 0);
    TEST_ASSERT(net_close(listener) == 0);
    return 0;
}

static int test_tcp_sack_ignores_partial_skb(void)
{
    enum {
        FIRST_SEQ = 1000u,
        SEGMENT_LEN = 1000u,
    };
    worker allocation_worker = {0};
    allocation_worker.master = create_thread();
    TEST_ASSERT(allocation_worker.master);
    set_current_worker(&allocation_worker);

    tcp_pcb pcb = {0};
    init_queue(&pcb.retransmit_queue);
    pcb.tcp_flag.sack_permitted_sent = 1;
    pcb.snd_una = FIRST_SEQ;
    pcb.snd_nxt = FIRST_SEQ + 2u * SEGMENT_LEN;
    pcb.snd_mss = SEGMENT_LEN;

    skbuff* partial = skb_alloc(SEGMENT_LEN);
    skbuff* covered = skb_alloc(SEGMENT_LEN);
    TEST_ASSERT(partial && covered);
    TEST_ASSERT(skb_data_put(partial, SEGMENT_LEN));
    TEST_ASSERT(skb_data_put(covered, SEGMENT_LEN));

    partial->l4_private.tcp.seq = FIRST_SEQ;
    partial->l4_private.tcp.seq_end = FIRST_SEQ + SEGMENT_LEN;
    partial->l4_private.tcp.flag = TCP_FLAG_ACK;
    covered->l4_private.tcp.seq = FIRST_SEQ + SEGMENT_LEN;
    covered->l4_private.tcp.seq_end = FIRST_SEQ + 2u * SEGMENT_LEN;
    covered->l4_private.tcp.flag = TCP_FLAG_ACK;
    add_queue(&pcb.retransmit_queue, &partial->queue_node);
    add_queue(&pcb.retransmit_queue, &covered->queue_node);

    struct {
        tcp_hdr hdr;
        uint8_t options[12];
    } packet = {0};
    packet.hdr.doff_res_flags =
        (uint8_t)((sizeof(packet) / 4u) << 4);
    packet.hdr.flags = TCP_FLAG_ACK;
    packet.hdr.ack_seq = htonl(FIRST_SEQ);
    packet.options[0] = TCP_OPTION_SACK;
    packet.options[1] = 10u;
    uint32_t left = htonl(FIRST_SEQ + SEGMENT_LEN / 2u);
    uint32_t right = htonl(FIRST_SEQ + 3u * SEGMENT_LEN / 4u);
    memcpy(&packet.options[2], &left, sizeof(left));
    memcpy(&packet.options[6], &right, sizeof(right));

    uint64_t newly_sacked = 0;
    TEST_ASSERT(tcp_sack_process_options(&pcb, &packet.hdr,
                                         &newly_sacked));
    TEST_ASSERT(newly_sacked == 0);
    TEST_ASSERT(partial->l4_private.tcp.sack_state == 0);
    TEST_ASSERT(covered->l4_private.tcp.sack_state == 0);

    right = htonl(FIRST_SEQ + 2u * SEGMENT_LEN);
    memcpy(&packet.options[6], &right, sizeof(right));
    TEST_ASSERT(tcp_sack_process_options(&pcb, &packet.hdr,
                                         &newly_sacked));
    TEST_ASSERT(newly_sacked == SEGMENT_LEN);
    TEST_ASSERT(partial->l4_private.tcp.sack_state == 0);
    TEST_ASSERT(partial->l4_private.tcp.seq == FIRST_SEQ);
    TEST_ASSERT(partial->l4_private.tcp.seq_end ==
                FIRST_SEQ + SEGMENT_LEN);
    TEST_ASSERT(skb_data_len(partial) == SEGMENT_LEN);
    TEST_ASSERT(covered->l4_private.tcp.sack_state == TCP_SACKED_ACKED);
    TEST_ASSERT(pcb.retransmit_queue.element_number == 2);

    tcp_sack_clear_scoreboard(&pcb);
    left = htonl(FIRST_SEQ);
    right = htonl(FIRST_SEQ + SEGMENT_LEN + SEGMENT_LEN / 2u);
    memcpy(&packet.options[2], &left, sizeof(left));
    memcpy(&packet.options[6], &right, sizeof(right));
    newly_sacked = 0;
    TEST_ASSERT(tcp_sack_process_options(&pcb, &packet.hdr,
                                         &newly_sacked));
    TEST_ASSERT(newly_sacked == SEGMENT_LEN);
    TEST_ASSERT(partial->l4_private.tcp.sack_state == TCP_SACKED_ACKED);
    TEST_ASSERT(covered->l4_private.tcp.sack_state == 0);
    TEST_ASSERT(skb_data_len(covered) == SEGMENT_LEN);
    TEST_ASSERT(pcb.retransmit_queue.element_number == 2);

    skbuff* fin = skb_alloc(1u);
    TEST_ASSERT(fin);
    fin->l4_private.tcp.seq = FIRST_SEQ + 2u * SEGMENT_LEN;
    fin->l4_private.tcp.seq_end = fin->l4_private.tcp.seq + 1u;
    fin->l4_private.tcp.flag = TCP_FLAG_ACK | TCP_FLAG_FIN;
    add_queue(&pcb.retransmit_queue, &fin->queue_node);
    pcb.snd_nxt = fin->l4_private.tcp.seq_end;

    left = htonl(fin->l4_private.tcp.seq);
    right = htonl(fin->l4_private.tcp.seq_end);
    memcpy(&packet.options[2], &left, sizeof(left));
    memcpy(&packet.options[6], &right, sizeof(right));
    newly_sacked = UINT64_MAX;
    TEST_ASSERT(tcp_sack_process_options(&pcb, &packet.hdr,
                                         &newly_sacked));
    TEST_ASSERT(newly_sacked == 0);
    TEST_ASSERT(fin->l4_private.tcp.sack_state == TCP_SACKED_ACKED);
    TEST_ASSERT(pcb.retransmit_queue.element_number == 3);

    list_node* node = pop_queue(&pcb.retransmit_queue);
    PUT_REF(SKB_FROM_NODE(node, queue_node));
    node = pop_queue(&pcb.retransmit_queue);
    PUT_REF(SKB_FROM_NODE(node, queue_node));
    node = pop_queue(&pcb.retransmit_queue);
    PUT_REF(SKB_FROM_NODE(node, queue_node));
    set_current_worker(NULL);
    destroy_thread(allocation_worker.master);
    return 0;
}

static int test_tcp_sack_recovery(void)
{
    enum {
        TEST_SACK_SEGMENTS = 4u,
        TEST_SACK_RECOVERY_TIMEOUT_MS = 2000u,
    };
    const uint16_t port = 32115u;
    int listener = -1, client = -1, accepted = -1;

    test_tcp_drop_rules_reset();
    test_tcp_sack_capture_reset(port);
    TEST_ASSERT(make_tcp_pair(port, &listener, &client, &accepted) == 0);
    TEST_ASSERT(net_fcntl(accepted, F_SETFL, O_NONBLOCK) == 0);
    TEST_ASSERT(wait_for_tcp_fully_acked(client) == 0);

    int one = 1;
    TEST_ASSERT(net_setsockopt(client, IPPROTO_TCP, TCP_NODELAY,
                               &one, sizeof(one)) == 0);

    fd_entry *client_entry = hold_fd_entry(client);
    fd_entry *accepted_entry = hold_fd_entry(accepted);
    TEST_ASSERT(client_entry && accepted_entry);
    tcp_pcb *client_pcb = ((Socket *)client_entry->value)->pcb;
    tcp_pcb *accepted_pcb = ((Socket *)accepted_entry->value)->pcb;
    TEST_ASSERT(client_pcb->tcp_flag.peer_sack_ok);
    TEST_ASSERT(accepted_pcb->tcp_flag.peer_sack_ok);

    uint32_t segment = tcp_data_mss(client_pcb);
    TEST_ASSERT(segment && segment <= UINT32_MAX / TEST_SACK_SEGMENTS);
    uint32_t total = segment * TEST_SACK_SEGMENTS;
    uint32_t first_seq = client_pcb->snd_nxt;
    client_pcb->snd_cwnd = max(client_pcb->snd_cwnd, total * 2u);
    client_pcb->retransmit_timeout = TCP_RETRANSMIT_TIMEOUT_MS_MAX;
    PUT_REF(accepted_entry);
    PUT_REF(client_entry);

    uint8_t *tx = malloc(total);
    uint8_t *rx = malloc(total);
    TEST_ASSERT(tx && rx);
    for (uint32_t i = 0; i < total; i++)
        tx[i] = (uint8_t)(i * 43u + 17u);

    for (uint32_t i = 0; i < TEST_SACK_SEGMENTS; i++) {
        test_tcp_drop_rule_arm(i, first_seq + i * segment,
                               i == 0u ? 1u : 0u);
    }

    TEST_ASSERT(net_write(client, tx, total) == (int)total);
    TEST_ASSERT(wait_for_read_exact_timeout(
        accepted, rx, total, TEST_SACK_RECOVERY_TIMEOUT_MS) == 0);
    TEST_ASSERT(memcmp(tx, rx, total) == 0);
    TEST_ASSERT(wait_for_tcp_fully_acked(client) == 0);

    TEST_ASSERT(atomic_load_explicit(&test_tcp_sack_syn_permitted,
                                     memory_order_acquire) >= 1u);
    TEST_ASSERT(atomic_load_explicit(&test_tcp_sack_synack_permitted,
                                     memory_order_acquire) >= 1u);
    TEST_ASSERT(atomic_load_explicit(&test_tcp_sack_wire.packets,
                                     memory_order_acquire) >= 1u);
    TEST_ASSERT(atomic_load_explicit(&test_tcp_sack_wire.blocks,
                                     memory_order_relaxed) == 1u);
    TEST_ASSERT(atomic_load_explicit(&test_tcp_sack_wire.option_len,
                                     memory_order_relaxed) == 10u);
    uint32_t captured_header_len = atomic_load_explicit(
        &test_tcp_sack_wire.tcp_header_len, memory_order_relaxed);
    TEST_ASSERT(captured_header_len >= sizeof(tcp_hdr) &&
                captured_header_len <= MAX_TCP_HDR_LEN);
    TEST_ASSERT(atomic_load_explicit(&test_tcp_sack_wire.ack,
                                     memory_order_relaxed) == first_seq);
    TEST_ASSERT(atomic_load_explicit(&test_tcp_sack_wire.left,
                                     memory_order_relaxed) ==
                first_seq + segment);
    TEST_ASSERT(atomic_load_explicit(&test_tcp_sack_wire.right,
                                     memory_order_relaxed) ==
                first_seq + total);

    TEST_ASSERT(test_tcp_drop_rule_attempts(0u) == 2u);
    for (uint32_t i = 1; i < TEST_SACK_SEGMENTS; i++)
        TEST_ASSERT(test_tcp_drop_rule_attempts(i) == 1u);

    client_entry = hold_fd_entry(client);
    accepted_entry = hold_fd_entry(accepted);
    TEST_ASSERT(client_entry && accepted_entry);
    client_pcb = ((Socket *)client_entry->value)->pcb;
    accepted_pcb = ((Socket *)accepted_entry->value)->pcb;
    TEST_ASSERT(client_pcb->sack_blocks_received >= 1u);
    TEST_ASSERT(client_pcb->sack_retransmits == 1u);
    TEST_ASSERT(client_pcb->sack_rto_events == 0u);
    TEST_ASSERT(client_pcb->retransmit_queue.element_number == 0);
    TEST_ASSERT(accepted_pcb->sack_blocks_sent >= 1u);
    TEST_ASSERT(accepted_pcb->recv_sack_count == 0u);
    TEST_ASSERT(accepted_pcb->unordered_skb_count == 0u);
    PUT_REF(accepted_entry);
    PUT_REF(client_entry);

    test_tcp_sack_capture_reset(0);
    test_tcp_drop_rules_reset();
    free(rx);
    free(tx);
    TEST_ASSERT(net_close(accepted) == 0);
    TEST_ASSERT(net_close(client) == 0);
    TEST_ASSERT(net_close(listener) == 0);
    return 0;
}

static int test_tcp_out_of_order_fin(void)
{
    int listener = -1, client = -1, accepted = -1;
    TEST_ASSERT(make_tcp_pair(32110, &listener, &client, &accepted) == 0);
    TEST_ASSERT(net_fcntl(accepted, F_SETFL, O_NONBLOCK) == 0);
    TEST_ASSERT(wait_for_tcp_fully_acked(client) == 0);

    fd_entry *client_entry = hold_fd_entry(client);
    TEST_ASSERT(client_entry);
    tcp_pcb *client_pcb = ((Socket*)client_entry->value)->pcb;
    uint32_t segment = tcp_data_mss(client_pcb);
    client_pcb->snd_cwnd = max(client_pcb->snd_cwnd, segment * 4u);
    PUT_REF(client_entry);

    uint8_t *tx = malloc(segment);
    uint8_t *rx = malloc(segment);
    TEST_ASSERT(tx && rx);
    for (uint32_t i = 0; i < segment; i++)
        tx[i] = (uint8_t)(i * 11u + 5u);

    /* Keep the first full data segment, drop its original transmission, and
     * let the following pure FIN reach the receiver first. */
    test_delay_duplicate_tcp_data_once();
    test_drop_tcp_data_once();
    TEST_ASSERT(net_write(client, tx, segment) == (int)segment);
    TEST_ASSERT(net_shutdown(client, SHUT_WR) == 0);
    TEST_ASSERT(wait_for_queued_fin(accepted) == 0);

    submit_req_2_worker(&test_worker, NULL, replay_delayed_tcp_data, true);
    TEST_ASSERT(wait_for_read_exact(accepted, rx, segment) == 0);
    TEST_ASSERT(memcmp(tx, rx, segment) == 0);

    uint8_t byte;
    TEST_ASSERT(wait_for_read(accepted, &byte, sizeof(byte)) == 0);

    fd_entry *accepted_entry = hold_fd_entry(accepted);
    TEST_ASSERT(accepted_entry);
    tcp_pcb *accepted_pcb = ((Socket*)accepted_entry->value)->pcb;
    TEST_ASSERT(accepted_pcb->tcp_flag.recv_fin);
    TEST_ASSERT(accepted_pcb->state == TCP_STATE_CLOSE_WAIT);
    PUT_REF(accepted_entry);

    free(rx);
    free(tx);
    TEST_ASSERT(net_close(accepted) == 0);
    TEST_ASSERT(net_close(client) == 0);
    TEST_ASSERT(net_close(listener) == 0);
    return 0;
}

#endif

static int test_tcp_linger(void)
{
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons(32105),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    int listener = net_socket(AF_INET, SOCK_STREAM, 0);
    TEST_ASSERT(listener >= 0);
    int reuse = 1;
    TEST_ASSERT(net_setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse,
                               sizeof(reuse)) == 0);
    TEST_ASSERT(net_bind(listener, (struct sockaddr*)&address,
                         sizeof(address)) == 0);
    TEST_ASSERT(net_listen(listener, 2) == 0);

    int client = net_socket(AF_INET, SOCK_STREAM, 0);
    TEST_ASSERT(client >= 0);
    TEST_ASSERT(net_connect(client, (struct sockaddr*)&address,
                            sizeof(address)) == 0);
    int accepted = net_accept(listener, NULL, NULL);
    TEST_ASSERT(accepted >= 0);

    struct linger linger = {.l_onoff = 1, .l_linger = 1};
    TEST_ASSERT(net_setsockopt(client, SOL_SOCKET, SO_LINGER, &linger,
                               sizeof(linger)) == 0);
    TEST_ASSERT(net_close(client) == 0); /* FIN ACK or one-second timeout */
    TEST_ASSERT(net_close(accepted) == 0);

    client = net_socket(AF_INET, SOCK_STREAM, 0);
    TEST_ASSERT(client >= 0);
    TEST_ASSERT(net_connect(client, (struct sockaddr*)&address,
                            sizeof(address)) == 0);
    accepted = net_accept(listener, NULL, NULL);
    TEST_ASSERT(accepted >= 0);

    linger.l_linger = 0;
    TEST_ASSERT(net_setsockopt(client, SOL_SOCKET, SO_LINGER, &linger,
                               sizeof(linger)) == 0);
    TEST_ASSERT(net_close(client) == 0); /* abortive RST close */
    char byte;
    TEST_ASSERT(net_read(accepted, &byte, sizeof(byte)) == -1);
    TEST_ASSERT(errno == ECONNRESET);
    TEST_ASSERT(net_close(accepted) == 0);
    TEST_ASSERT(net_close(listener) == 0);
    return 0;
}

static int test_udp_loopback(void)
{
    const char payload[] = "netfast udp loopback";
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons(32102),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    int receiver = net_socket(AF_INET, SOCK_DGRAM, 0);
    int sender = -1;
    TEST_ASSERT(receiver >= 0);
    TEST_ASSERT(net_bind(receiver, (struct sockaddr *)&address,
                         sizeof(address)) == 0);
    sender = net_socket(AF_INET, SOCK_DGRAM, 0);
    TEST_ASSERT(sender >= 0);
    TEST_ASSERT(net_sendto(sender, payload, sizeof(payload), 0,
                           (struct sockaddr *)&address, sizeof(address)) ==
                (int)sizeof(payload));
    char buffer[64] = {0};
    struct sockaddr_in peer = {0};
    socklen_t peer_len = sizeof(peer);
    TEST_ASSERT(wait_for_recvfrom(receiver, buffer, sizeof(buffer), &peer,
                                  &peer_len) == (int)sizeof(payload));
    TEST_ASSERT(memcmp(buffer, payload, sizeof(payload)) == 0);
    TEST_ASSERT(peer.sin_family == AF_INET && peer.sin_port != 0);
    TEST_ASSERT(net_close(sender) == 0);
    TEST_ASSERT(net_close(receiver) == 0);
    return 0;
}

static int test_request_error_boundary(void)
{
    struct sockaddr_in unreachable = {
        .sin_family = AF_INET,
        .sin_port = htons(32103),
        .sin_addr.s_addr = htonl(0xc0000201u), /* 192.0.2.1 */
    };
    int socket_fd = net_socket(AF_INET, SOCK_DGRAM, 0);
    TEST_ASSERT(socket_fd >= 0);

    errno = 0;
    TEST_ASSERT(net_connect(socket_fd, (struct sockaddr *)&unreachable,
                            sizeof(unreachable)) == -1);
    TEST_ASSERT(errno == EHOSTUNREACH);

    int cq_fd = net_async_create();
    TEST_ASSERT(cq_fd >= 0);
    req *request = net_async_req_create(
        socket_fd, REQ_CONNECT,
        (struct sockaddr *)&unreachable, (socklen_t)sizeof(unreachable));
    TEST_ASSERT(request);
    TEST_ASSERT(net_async_submit(cq_fd, request) == 0);

    req *completed = NULL;
    TEST_ASSERT(net_async_wait(cq_fd, &completed, 1, 1, 2000) == 1);
    TEST_ASSERT(completed == request);
    TEST_ASSERT(net_async_result(completed, NULL) == -EHOSTUNREACH);
    net_async_req_destroy(completed);

    TEST_ASSERT(net_async_close(cq_fd) == 0);
    TEST_ASSERT(net_close(socket_fd) == 0);
    return 0;
}

static int test_async_request_resubmit(void)
{
    int socket_fd = net_socket(AF_INET, SOCK_DGRAM, 0);
    TEST_ASSERT(socket_fd >= 0);
    int cq_fd = net_async_create();
    TEST_ASSERT(cq_fd >= 0);

    int option_values[2] = {1, 0};
    req *request = net_async_req_create(
        socket_fd, REQ_SETSOCKOPT, SOL_SOCKET, SO_REUSEADDR,
        &option_values[0], (socklen_t)sizeof(option_values[0]));
    TEST_ASSERT(request);

    for (uint32_t attempt = 0; attempt < 2; ++attempt) {
        req_argv *argv = net_async_argv(request);
        TEST_ASSERT(argv);
        argv->setsockopt.optval = &option_values[attempt];
        TEST_ASSERT(net_async_submit(cq_fd, request) == 0);

        errno = 0;
        TEST_ASSERT(net_async_submit(cq_fd, request) == -1);
        TEST_ASSERT(errno == EBUSY);

        req *completed = NULL;
        TEST_ASSERT(net_async_wait(cq_fd, &completed, 1, 1, 2000) == 1);
        TEST_ASSERT(completed == request);

        req_type type;
        TEST_ASSERT(net_async_result(completed, &type) == 0);
        TEST_ASSERT(type == REQ_SETSOCKOPT);
        TEST_ASSERT(argv->setsockopt.optval == &option_values[attempt]);

        int actual = -1;
        socklen_t actual_len = sizeof(actual);
        TEST_ASSERT(net_getsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR,
                                   &actual, &actual_len) == 0);
        TEST_ASSERT(actual == option_values[attempt]);
    }

    net_async_req_destroy(request);
    TEST_ASSERT(net_async_close(cq_fd) == 0);
    TEST_ASSERT(net_close(socket_fd) == 0);
    return 0;
}

typedef struct async_wait_test_arg {
    int cq_fd;
    uint32_t min;
    uint32_t max;
    req *completed[8];
    int ret;
    int saved_errno;
} async_wait_test_arg;

static atomic_uint async_wait_test_started;

static void *run_async_wait_test(void *opaque)
{
    async_wait_test_arg *arg = opaque;
    atomic_fetch_add_explicit(&async_wait_test_started, 1,
                              memory_order_release);
    arg->ret = net_async_wait(arg->cq_fd, arg->completed,
                              arg->min, arg->max, 2000);
    arg->saved_errno = errno;
    return NULL;
}

static int test_async_multi_wait(void)
{
    enum { REQUESTS = 12, WAITERS = 4, ROUNDS = 32 };
    static const uint32_t batch[WAITERS] = {1, 2, 4, 5};
    int cq_fd = net_async_create();
    TEST_ASSERT(cq_fd >= 0);

    for (uint32_t round = 0; round < ROUNDS; ++round) {
        req *requests[REQUESTS];
        for (uint32_t i = 0; i < REQUESTS; ++i) {
            requests[i] = net_async_req_create(-1, REQ_SOCKET,
                                                AF_INET, SOCK_DGRAM, 0);
            TEST_ASSERT(requests[i]);
        }

        async_wait_test_arg args[WAITERS] = {0};
        pthread_t threads[WAITERS];
        atomic_store_explicit(&async_wait_test_started, 0,
                              memory_order_relaxed);
        for (uint32_t i = 0; i < WAITERS; ++i) {
            args[i].cq_fd = cq_fd;
            args[i].min = batch[i];
            args[i].max = batch[i];
            TEST_ASSERT(pthread_create(&threads[i], NULL, run_async_wait_test,
                                       &args[i]) == 0);
        }

        uint64_t deadline = read_now_ms() + 1000;
        while (atomic_load_explicit(&async_wait_test_started,
                                    memory_order_acquire) != WAITERS &&
               read_now_ms() < deadline) {
            struct timespec delay = {.tv_nsec = 1000000};
            nanosleep(&delay, NULL);
        }
        TEST_ASSERT(atomic_load_explicit(&async_wait_test_started,
                                        memory_order_acquire) == WAITERS);
        struct timespec arm_delay = {.tv_nsec = 2000000};
        nanosleep(&arm_delay, NULL);

        for (uint32_t i = 0; i < REQUESTS; ++i)
            TEST_ASSERT(net_async_submit(cq_fd, requests[i]) == 0);
        for (uint32_t i = 0; i < WAITERS; ++i) {
            TEST_ASSERT(pthread_join(threads[i], NULL) == 0);
            TEST_ASSERT(args[i].ret == (int)batch[i]);
            for (uint32_t j = 0; j < batch[i]; ++j) {
                req* request = args[i].completed[j];
                req_type type;
                int result = net_async_result(request, &type);
                const req_argv *argv = net_async_argv(request);
                TEST_ASSERT(type == REQ_SOCKET);
                TEST_ASSERT(argv && argv->Socket.family == AF_INET);
                TEST_ASSERT(argv->Socket.type == SOCK_DGRAM);
                TEST_ASSERT(argv->Socket.protocol == 0);
                TEST_ASSERT(result >= 0);
                TEST_ASSERT(net_close(result) == 0);
                net_async_req_destroy(args[i].completed[j]);
            }
        }
    }
    TEST_ASSERT(net_async_close(cq_fd) == 0);
    return 0;
}

static int test_async_multi_wait_close(void)
{
    enum { WAITERS = 4 };
    int cq_fd = net_async_create();
    TEST_ASSERT(cq_fd >= 0);

    async_wait_test_arg args[WAITERS] = {0};
    pthread_t threads[WAITERS];
    atomic_store_explicit(&async_wait_test_started, 0, memory_order_relaxed);
    for (uint32_t i = 0; i < WAITERS; ++i) {
        args[i].cq_fd = cq_fd;
        args[i].min = 1;
        args[i].max = 1;
        TEST_ASSERT(pthread_create(&threads[i], NULL, run_async_wait_test,
                                   &args[i]) == 0);
    }

    uint64_t deadline = read_now_ms() + 1000;
    while (atomic_load_explicit(&async_wait_test_started,
                                memory_order_acquire) != WAITERS &&
           read_now_ms() < deadline) {
        struct timespec delay = {.tv_nsec = 1000000};
        nanosleep(&delay, NULL);
    }
    TEST_ASSERT(atomic_load_explicit(&async_wait_test_started,
                                    memory_order_acquire) == WAITERS);
    struct timespec arm_delay = {.tv_nsec = 10000000};
    nanosleep(&arm_delay, NULL);

    TEST_ASSERT(net_async_close(cq_fd) == 0);
    for (uint32_t i = 0; i < WAITERS; ++i) {
        TEST_ASSERT(pthread_join(threads[i], NULL) == 0);
        TEST_ASSERT(args[i].ret == -1 && args[i].saved_errno == EBADF);
    }
    return 0;
}

int main(void)
{
    TEST_RUN(test_tcp_unit_defaults_and_boundaries);
    TEST_RUN(test_udp_unit_defaults);
    TEST_ASSERT(setup_loopback_runtime() == 0);
    TEST_RUN(test_skb_multisegment_clone_copy);
    TEST_RUN(test_ipv6_extension_fragmentation);
    TEST_RUN(test_bind_ephemeral_ports);
    TEST_RUN(test_tcp_loopback);
#ifndef NDEBUG
    TEST_RUN(test_tcp_sack_ignores_partial_skb);
    TEST_RUN(test_tcp_sack_recovery);
    TEST_RUN(test_tcp_rto_backoff_deadline);
    TEST_RUN(test_tcp_out_of_order_fin);
#endif
    TEST_RUN(test_tcp_linger);
    TEST_RUN(test_udp_loopback);
    TEST_RUN(test_request_error_boundary);
    TEST_RUN(test_async_request_resubmit);
    TEST_RUN(test_async_multi_wait);
    TEST_RUN(test_async_multi_wait_close);

    /* Leave time for queued FIN/ACK packets to complete before process exit. */
    sleep(2);
    atomic_store_explicit(&worker_running, false, memory_order_release);
    TEST_ASSERT(pthread_join(worker_thread, NULL) == 0);
#ifndef NDEBUG
    test_loopback_if->ops = &loopback_ops;
    if (test_delayed_tcp_data)
        PUT_REF(test_delayed_tcp_data);
    PUT_REF(test_loopback_if);
#endif
    puts("All TCP/UDP protocol tests passed.");
    return 0;
}
