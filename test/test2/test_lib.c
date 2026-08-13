#include <arpa/inet.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "base.h"
#include "hash.h"
#include "list.h"
#include "queue.h"
#include "rss.h"
#include "skbuff.h"
#include "thread.h"
#include "trie.h"

#include "test_common.h"

static int int_node_compare(list_node *a, list_node *b)
{
    return a->element < b->element ? -1 : a->element > b->element;
}

static int test_list_and_queue(void)
{
    list_node head = {0};
    list_node *three = create_list_node(3);
    list_node *one = create_list_node(1);
    list_node *two = create_list_node(2);
    TEST_ASSERT(three && one && two);
    TEST_ASSERT(add_list_node_compare(&head, three, int_node_compare) == 0);
    TEST_ASSERT(add_list_node_compare(&head, one, int_node_compare) == 0);
    TEST_ASSERT(add_list_node_compare(&head, two, int_node_compare) == 0);
    TEST_ASSERT(add_list_node_compare(&head, two, int_node_compare) == -1);
    TEST_ASSERT(head.next == one && one->next == two && two->next == three);
    TEST_ASSERT(list_element_exist(&head, 2));
    remove_list_node(two);
    destroy_list_node(two, NULL);
    clear_list_head(&head, NULL);

    queue q;
    list_node a = {.element = 1}, b = {.element = 2}, c = {.element = 3};
    init_queue(&q);
    add_queue(&q, &a);
    add_queue(&q, &b);
    add_queue_first(&q, &c);
    TEST_ASSERT(q.element_number == 3 && queue_exist(&q, 2));
    TEST_ASSERT(pop_queue(&q) == &c);
    TEST_ASSERT(pop_queue_last(&q) == &b);
    TEST_ASSERT(pop_queue(&q) == &a);
    TEST_ASSERT(QUEUE_EMPTY(&q));
    return 0;
}

enum { PRODUCERS = 4, ITEMS_PER_PRODUCER = 600 };

typedef struct mpsc_test_item {
    mpscq_node node;
    uint32_t id;
} mpsc_test_item;

typedef struct producer_arg {
    mpsc_queue *queue;
    mpsc_test_item *items;
    uint32_t first;
} producer_arg;

static void *mpsc_producer(void *opaque)
{
    producer_arg *arg = opaque;
    for (uint32_t i = 0; i < ITEMS_PER_PRODUCER; ++i)
        mpscq_push(arg->queue, &arg->items[arg->first + i].node);
    return NULL;
}

static int test_mpsc_queue_concurrency(void)
{
    enum { TOTAL = PRODUCERS * ITEMS_PER_PRODUCER };
    mpsc_queue queue;
    mpsc_test_item items[TOTAL];
    bool seen[TOTAL];
    pthread_t threads[PRODUCERS];
    producer_arg args[PRODUCERS];
    memset(seen, 0, sizeof(seen));
    mpscq_init(&queue);

    for (uint32_t i = 0; i < TOTAL; ++i)
        items[i].id = i;
    for (uint32_t i = 0; i < PRODUCERS; ++i) {
        args[i] = (producer_arg){.queue = &queue, .items = items,
                                 .first = i * ITEMS_PER_PRODUCER};
        TEST_ASSERT(pthread_create(&threads[i], NULL, mpsc_producer,
                                   &args[i]) == 0);
    }

    uint32_t received = 0;
    while (received < TOTAL) {
        mpscq_node *node = mpscq_pop(&queue);
        if (!node) {
            sched_yield();
            continue;
        }
        mpsc_test_item *item = (mpsc_test_item *)((uint8_t *)node -
            offsetof(mpsc_test_item, node));
        TEST_ASSERT(item->id < TOTAL && !seen[item->id]);
        seen[item->id] = true;
        received++;
    }
    for (uint32_t i = 0; i < PRODUCERS; ++i)
        TEST_ASSERT(pthread_join(threads[i], NULL) == 0);
    TEST_ASSERT(mpscq_is_empty(&queue));
    return 0;
}

typedef struct hash_thread_arg {
    hash *table;
    struct hash_test_item *items;
    uint32_t start;
    uint32_t count;
} hash_thread_arg;

typedef struct hash_test_item {
    uint32_t key;
    uint64_t value;
    hash_node hash_node;
} hash_test_item;

static void *hash_writer(void *opaque)
{
    hash_thread_arg *arg = opaque;
    for (uint32_t i = 0; i < arg->count; ++i) {
        hash_test_item *item = &arg->items[arg->start + i];
        if (!hash_add_node(arg->table, &item->hash_node))
            return (void *)1;
    }
    return NULL;
}

static int test_safe_hash_concurrency(void)
{
    enum { THREADS = 4, PER_THREAD = 400 };
    hash_test_item *items = calloc(THREADS * PER_THREAD, sizeof(*items));
    TEST_ASSERT(items);
    for (uint32_t i = 0; i < THREADS * PER_THREAD; ++i) {
        items[i].key = i;
        items[i].value = (uint64_t)i + 1u;
    }
    hash *table = hash_create_safe(32,
        HASH_KEY_OFFSET(hash_test_item, hash_node, key), sizeof(uint32_t));
    pthread_t threads[THREADS];
    hash_thread_arg args[THREADS];
    TEST_ASSERT(table);
    for (uint32_t i = 0; i < THREADS; ++i) {
        args[i] = (hash_thread_arg){.table = table, .items = items,
                                    .start = i * PER_THREAD,
                                    .count = PER_THREAD};
        TEST_ASSERT(pthread_create(&threads[i], NULL, hash_writer,
                                   &args[i]) == 0);
    }
    for (uint32_t i = 0; i < THREADS; ++i) {
        void *result = NULL;
        TEST_ASSERT(pthread_join(threads[i], &result) == 0 && result == NULL);
    }
    for (uint32_t key = 0; key < THREADS * PER_THREAD; ++key) {
        hash_node *node = hash_find_node(table, &key);
        hash_test_item *item = node
            ? HASH_CONTAINER_OF(node, hash_test_item, hash_node) : NULL;
        TEST_ASSERT(item && item->value == (uint64_t)key + 1u);
    }

    uint32_t key = 23;
    hash_node *node = hash_find_node(table, &key);
    hash_test_item *item = node
        ? HASH_CONTAINER_OF(node, hash_test_item, hash_node) : NULL;
    TEST_ASSERT(item && item->value == 24);
    for (uint32_t i = 0; i < THREADS * PER_THREAD; ++i)
        hash_del_node(table, &items[i].hash_node);
    TEST_ASSERT(hash_is_empty(table));
    hash_destroy(table);
    free(items);
    return 0;
}

static int trie_add(trie_node *node, uint64_t element)
{
    node->exist_element = true;
    node->element = element;
    return 0;
}

static int trie_delete(trie_node *node, uint64_t element)
{
    if (node->exist_element && node->element == element) {
        node->exist_element = false;
        node->element = 0;
    }
    return 0;
}

static uint64_t trie_search(trie_node *node, void *unused)
{
    (void)unused;
    return node->element;
}

static int test_trie_ipv4_ipv6(void)
{
    trie v4 = {
        .type = TRIE_IPV4, .cb_add = trie_add, .cb_delete = trie_delete,
        .cb_search = trie_search, .use_rwlock = true,
        .rwlock = PTHREAD_RWLOCK_INITIALIZER,
    };
    uint32_t net10 = inet_addr("10.0.0.0");
    uint32_t net101 = inet_addr("10.1.0.0");
    uint32_t host = inet_addr("10.1.2.3");
    TEST_ASSERT(add_trie_element(&v4, net10, 8, 10) == 0);
    TEST_ASSERT(add_trie_element(&v4, net101, 16, 20) == 0);
    TEST_ASSERT(search_trie_element(&v4, host, 32, true, NULL) == 20);
    TEST_ASSERT(search_trie_element(&v4, host, 32, false, NULL) == 0);
    TEST_ASSERT(delete_trie_element(&v4, net101, 16, 20) == 0);
    TEST_ASSERT(search_trie_element(&v4, host, 32, true, NULL) == 10);
    TEST_ASSERT(add_trie_element(&v4, net10, 33, 1) == -1);
    trie_clear(&v4, NULL);
    TRIE_DESTROY_RWLOCK(&v4);

    trie v6 = {
        .type = TRIE_IPV6, .cb_add = trie_add, .cb_delete = trie_delete,
        .cb_search = trie_search, .use_rwlock = true,
        .rwlock = PTHREAD_RWLOCK_INITIALIZER,
    };
    struct in6_addr pfx32, pfx48, host6;
    TEST_ASSERT(inet_pton(AF_INET6, "2001:db8::", &pfx32) == 1);
    TEST_ASSERT(inet_pton(AF_INET6, "2001:db8:1::", &pfx48) == 1);
    TEST_ASSERT(inet_pton(AF_INET6, "2001:db8:1::42", &host6) == 1);
    TEST_ASSERT(add_trie_element(&v6, (uintptr_t)&pfx32, 32, 32) == 0);
    TEST_ASSERT(add_trie_element(&v6, (uintptr_t)&pfx48, 48, 48) == 0);
    TEST_ASSERT(search_trie_element(&v6, (uintptr_t)&host6, 128, true,
                                    NULL) == 48);
    TEST_ASSERT(delete_trie_element(&v6, (uintptr_t)&pfx48, 48, 48) == 0);
    TEST_ASSERT(search_trie_element(&v6, (uintptr_t)&host6, 128, true,
                                    NULL) == 32);
    trie_clear(&v6, NULL);
    TRIE_DESTROY_RWLOCK(&v6);
    return 0;
}

static atomic_int timer_fired;

static void test_timer_callback(task *task)
{
    (void)task;
    atomic_fetch_add_explicit(&timer_fired, 1, memory_order_relaxed);
}

static int test_timer_and_notify_queue(void)
{
    thread *thread = create_thread();
    TEST_ASSERT(thread);
    current_time_ms = read_now_ms();
    task *timer = create_task(TASK_TYPE_TIMER);
    TEST_ASSERT(timer);
    timer->cb_timer = test_timer_callback;
    timer->timeout = current_time_ms + 5;
    atomic_store(&timer_fired, 0);
    TEST_ASSERT(register_task(thread, timer) == 0);
    for (int i = 0; i < 100 && atomic_load(&timer_fired) == 0; ++i) {
        struct timespec delay = {.tv_nsec = 1000000};
        nanosleep(&delay, NULL);
        current_time_ms = read_now_ms();
        (void)thread_step(thread);
    }
    TEST_ASSERT(atomic_load(&timer_fired) == 1);
    destroy_task(timer);

    notify_queue notify;
    mpscq_node first, second;
    TEST_ASSERT(notify_queue_init(&notify) == 0);
    notify_queue_push(&notify, &first);
    notify_queue_push(&notify, &second);
    struct pollfd pfd = {.fd = notify.efd, .events = POLLIN};
    TEST_ASSERT(poll(&pfd, 1, 100) == 1 && (pfd.revents & POLLIN));
    notify_queue_drain(&notify);
    TEST_ASSERT(notify_queue_pop(&notify) == &first);
    TEST_ASSERT(notify_queue_pop(&notify) == &second);
    TEST_ASSERT(notify_queue_is_empty(&notify));
    notify_queue_close(&notify);
    destroy_thread(thread);
    return 0;
}

static int test_checksum_and_rss(void)
{
    uint8_t packet[] = {0x45, 0x00, 0x00, 0x54, 0x12, 0x34, 0x40, 0x00,
                        0x40, 0x01, 0, 0, 192, 0, 2, 1, 198, 51, 100, 2};
    uint16_t sum = checksum(packet, sizeof(packet), 0);
    memcpy(&packet[10], &sum, sizeof(sum));
    TEST_ASSERT(checksum(packet, sizeof(packet), 0) == 0);

    /* AF_XDP checksum metadata expects the transport checksum field to hold
     * the uncomplemented pseudo-header sum.  Simulate the device completing
     * that partial checksum and verify the resulting TCP segment. */
    uint8_t segment[27] = {
        0x04, 0xd2, 0x00, 0x50, 0, 0, 0, 1,
        0, 0, 0, 0, 0x50, 0x18, 0x10, 0,
        0, 0, 0, 0, 'n', 'e', 't', 'f', 'a', 's', 't'
    };
    uint32_t saddr = inet_addr("192.0.2.1");
    uint32_t daddr = inet_addr("198.51.100.2");
    uint16_t seed = skb_checksum_protocol(NULL, sizeof(segment), saddr,
                                          daddr, IPPROTO_TCP);
    memcpy(&segment[16], &seed, sizeof(seed));
    uint16_t completed = checksum(segment, sizeof(segment), 0);
    memcpy(&segment[16], &completed, sizeof(completed));
    TEST_ASSERT(checksum_protocol(segment, sizeof(segment), saddr, daddr,
                                  IPPROTO_TCP) == 0);

    uint8_t key[TOEPLITZ_RSS_KEY_LEN];
    uint32_t key_len = 0;
    memcpy(key, toeplitz_rss_get_key(&key_len), sizeof(key));
    uint8_t tuple[] = {192, 0, 2, 1, 198, 51, 100, 2, 0x12, 0x34, 0x56, 0x78};
    uint32_t first = toeplitz_hash(key, key_len, tuple, sizeof(tuple));
    uint32_t second = toeplitz_hash(key, key_len, tuple, sizeof(tuple));
    TEST_ASSERT(key_len == TOEPLITZ_RSS_KEY_LEN && first == second);
    TEST_ASSERT(toeplitz_hash(key, 3, tuple, sizeof(tuple)) == 0);
    return 0;
}

int main(void)
{
    TEST_RUN(test_list_and_queue);
    TEST_RUN(test_mpsc_queue_concurrency);
    TEST_RUN(test_safe_hash_concurrency);
    TEST_RUN(test_trie_ipv4_ipv6);
    TEST_RUN(test_timer_and_notify_queue);
    TEST_RUN(test_checksum_and_rss);
    puts("All lib and concurrency tests passed.");
    return 0;
}
