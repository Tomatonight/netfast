#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <unistd.h>
#include <xdp/xsk.h>
#include <errno.h>
#include <sys/mman.h>
#include <signal.h>
#include <assert.h>
#include <linux/capability.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <sys/socket.h>
#include <poll.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

#include <sys/ioctl.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>

#include "if.h"
#include "queue.h"
#include "worker.h"
#include "thread.h"
#include "skbuff.h"
#include "ether.h"
#include "ip.h"
#include "ipv6.h"
#include "udp.h"
#include "tcp.h"
#include "icmp.h"
#include "init.h"
#include "log.h"
#include "xdp.h"

_Static_assert(XDP_UMEM_FRAME_CNT != 0 &&
               (XDP_UMEM_FRAME_CNT & (XDP_UMEM_FRAME_CNT - 1U)) == 0,
               "XDP_UMEM_FRAME_CNT must be a power of two");

xdp_frame_pool g_xdp_frame_pool = {0};

static if_xdp* xdp_tx_pick(if_info* info, skbuff* skb);
static int xdp_tx_send(if_xdp* ix, skbuff* skb);
static void if_xdp_unbind_socket(if_xdp* ix);
static void xdp_if_write(task* tk);


static struct xsk_umem*      g_xdp_umem = NULL;
static struct xsk_ring_prod  g_umem_fq = {0};
static struct xsk_ring_cons  g_umem_cq = {0};

static spinlock_t    g_xdp_umem_lock;

typedef struct xdp_prog_shared {
    int ifindex;
    int xsks_map_fd;
    uint32_t xdp_attach_mode;
    struct bpf_object* xdp_obj;
    struct bpf_link* xdp_link;
    struct xdp_prog_shared* next;
} xdp_prog_shared;

static void destroy_xdp_prog_shared(xdp_prog_shared* shared);

static xdp_prog_shared* g_xdp_prog_list = NULL;

void xdp_cleanup_programs(void)
{
    xdp_prog_shared* it = g_xdp_prog_list;
    while (it) {
        xdp_prog_shared* next = it->next;
        if (it->xsks_map_fd > 0) {
            for (__u32 key = 0; key < 32; ++key)
                (void)bpf_map_delete_elem(it->xsks_map_fd, &key);
        }
        destroy_xdp_prog_shared(it);
        it = next;
    }
    g_xdp_prog_list = NULL;
}

static inline void *idx_to_ptr(uint32_t idx)
{
	return (uint8_t *)g_xdp_frame_pool.buffer +
	       (size_t)idx * g_xdp_frame_pool.frame_size;
}

static inline uint32_t ptr_to_idx(void *ptr)
{
	return (uint32_t)(((uintptr_t)ptr - (uintptr_t)g_xdp_frame_pool.buffer)
	                  / g_xdp_frame_pool.frame_size);
}

/*
 * Global lock-free MPMC frame pool.
 *
 * The ring stores frame indexes. Any thread may allocate (dequeue) or free
 * (enqueue) a frame. Each slot has a sequence number which distinguishes
 * different turns of the circular array and publishes slot readiness.
 *
 * Requirements:
 *   - num_frames/ring_size must be a power of two;
 *   - a frame must not be freed twice;
 *   - destroy must run only after all alloc/free users have stopped.
 */
static inline bool xdp_frame_ptr_valid(const void *ptr)
{

    uintptr_t base = (uintptr_t)g_xdp_frame_pool.buffer;
    uintptr_t addr = (uintptr_t)ptr;
    uintptr_t size = (uintptr_t)g_xdp_frame_pool.frame_size *
                     (uintptr_t)g_xdp_frame_pool.num_frames;

    if (addr < base || addr >= base + size)
        return false;

    return ((addr - base) % g_xdp_frame_pool.frame_size) == 0;
}

/* Multi-consumer dequeue: obtain one free frame index. */
static bool xdp_frame_pool_pop_idx(uint32_t *out_idx)
{

    uint64_t pos = atomic_load_explicit(
        &g_xdp_frame_pool.dequeue_pos,
        memory_order_relaxed);

    xdp_frame_slot *slot;

    for (;;) {
        slot = &g_xdp_frame_pool.slots[
            (uint32_t)pos & g_xdp_frame_pool.ring_mask];

        uint64_t seq = atomic_load_explicit(
            &slot->sequence,
            memory_order_acquire);

        intptr_t diff = (intptr_t)seq - (intptr_t)(pos + 1U);

        if (diff == 0) {
            if (atomic_compare_exchange_weak_explicit(
                    &g_xdp_frame_pool.dequeue_pos,
                    &pos,
                    pos + 1U,
                    memory_order_relaxed,
                    memory_order_relaxed)) {
                break;
            }
        } else if (diff < 0) {
            /* No frame is currently available. */
            return false;
        } else {
            pos = atomic_load_explicit(
                &g_xdp_frame_pool.dequeue_pos,
                memory_order_relaxed);
        }
    }

    uint32_t idx = slot->frame_idx;
    if (idx >= g_xdp_frame_pool.num_frames) {
        ERR_LOG("xdp: invalid frame index dequeued idx=%u\n", idx);
        abort();
    }

    *out_idx = idx;

    /* Release this ring slot to the producer side for the next turn. */
    atomic_store_explicit(
        &slot->sequence,
        pos + g_xdp_frame_pool.ring_size,
        memory_order_release);

    return true;
}

/* Multi-producer enqueue: return one frame index to the free pool. */
static bool xdp_frame_pool_push_idx(uint32_t frame_idx)
{
    if (frame_idx >= g_xdp_frame_pool.num_frames ||
        !g_xdp_frame_pool.slots)
        return false;

    uint64_t pos = atomic_load_explicit(
        &g_xdp_frame_pool.enqueue_pos,
        memory_order_relaxed);

    xdp_frame_slot *slot;

    for (;;) {
        slot = &g_xdp_frame_pool.slots[
            (uint32_t)pos & g_xdp_frame_pool.ring_mask];

        uint64_t seq = atomic_load_explicit(
            &slot->sequence,
            memory_order_acquire);

        intptr_t diff = (intptr_t)seq - (intptr_t)pos;

        if (diff == 0) {
            if (atomic_compare_exchange_weak_explicit(
                    &g_xdp_frame_pool.enqueue_pos,
                    &pos,
                    pos + 1U,
                    memory_order_relaxed,
                    memory_order_relaxed)) {
                break;
            }
        } else if (diff < 0) {
            /* A consumer can reserve a dequeue position before publishing
             * the ring slot back to producers.  Only report a genuinely full
             * ring; otherwise retry until that in-flight consumer releases
             * the slot. */
            uint64_t dequeue = atomic_load_explicit(
                &g_xdp_frame_pool.dequeue_pos,
                memory_order_acquire);
            if (pos - dequeue >= g_xdp_frame_pool.ring_size)
                return false;
            pos = atomic_load_explicit(
                &g_xdp_frame_pool.enqueue_pos,
                memory_order_relaxed);
            sched_yield();
        } else {
            pos = atomic_load_explicit(
                &g_xdp_frame_pool.enqueue_pos,
                memory_order_relaxed);
        }
    }

    slot->frame_idx = frame_idx;

    /* Publish frame_idx to consumers. */
    atomic_store_explicit(
        &slot->sequence,
        pos + 1U,
        memory_order_release);

    return true;
}

/* ── Public API: pointer interface, index-based MPMC ring internally. ── */
uint32_t xdp_frame_alloc_batch(void **out, uint32_t max)
{
    uint32_t got = 0;

    while (got < max) {
        uint32_t idx;
        if (!xdp_frame_pool_pop_idx(&idx))
            break;
        out[got++] = idx_to_ptr(idx);
    }

    return got;
}

uint32_t xdp_frame_free_batch(void *const *frames, uint32_t n)
{

    uint32_t pushed = 0;

    for (uint32_t i = 0; i < n; ++i) {
        if (!xdp_frame_ptr_valid(frames[i])) {
            ERR_LOG("xdp: invalid frame pointer=%p\n", frames[i]);
            continue;
        }

        uint32_t idx = ptr_to_idx(frames[i]);
        if (!xdp_frame_pool_push_idx(idx)) {
            ERR_LOG("xdp: frame pool push failed idx=%u; "
                    "possible duplicate free or pool corruption\n", idx);
            continue;
        }

        pushed++;
    }

    return pushed;
}

uint32_t xdp_frame_pool_available(void)
{
    uint64_t enqueue = atomic_load_explicit(&g_xdp_frame_pool.enqueue_pos,
                                            memory_order_acquire);
    uint64_t dequeue = atomic_load_explicit(&g_xdp_frame_pool.dequeue_pos,
                                            memory_order_acquire);
    uint64_t available = enqueue - dequeue;
    if (available > g_xdp_frame_pool.num_frames)
        available = g_xdp_frame_pool.num_frames;
    return (uint32_t)available;
}

int xdp_frame_pool_init(void)
{
    frame_global_cache_reset();
    memset(&g_xdp_frame_pool, 0, sizeof(g_xdp_frame_pool));

    g_xdp_frame_pool.frame_size = XDP_UMEM_FRAME_SIZE;
    g_xdp_frame_pool.num_frames = XDP_UMEM_FRAME_CNT;
    g_xdp_frame_pool.ring_size  = XDP_UMEM_FRAME_CNT;

    g_xdp_frame_pool.ring_mask = g_xdp_frame_pool.ring_size - 1U;

    uint64_t buffer_size =
        (uint64_t)g_xdp_frame_pool.frame_size *
        (uint64_t)g_xdp_frame_pool.num_frames;

    int err = posix_memalign(
        &g_xdp_frame_pool.buffer,
        (size_t)getpagesize(),
        (size_t)buffer_size);

    if (err != 0) {
        ERR_LOG("xdp: frame pool buffer alloc failed err=%d(%s)\n",
                err, strerror(err));
        return -1;
    }

    g_xdp_frame_pool.slots = calloc(
        g_xdp_frame_pool.ring_size,
        sizeof(*g_xdp_frame_pool.slots));

    if (!g_xdp_frame_pool.slots) {
        ERR_LOG("xdp: frame pool ring alloc failed\n");
        free(g_xdp_frame_pool.buffer);
        g_xdp_frame_pool.buffer = NULL;
        return -1;
    }

    /*
     * The free-frame ring starts full:
     * positions [0, ring_size) already contain frame indexes [0, N).
     */
    atomic_init(&g_xdp_frame_pool.dequeue_pos, 0);
    atomic_init(&g_xdp_frame_pool.enqueue_pos,
                (uint64_t)g_xdp_frame_pool.ring_size);

    for (uint64_t i = 0; i < g_xdp_frame_pool.ring_size; ++i) {
        g_xdp_frame_pool.slots[i].frame_idx = (uint32_t)i;
        atomic_init(&g_xdp_frame_pool.slots[i].sequence, i + 1U);
        page_info* page = idx_to_ptr((uint32_t)i);
        atomic_init(&page->generation, 0U);
    }

    frame_global_cache_init();

    return 0;
}

void xdp_frame_pool_destroy(void)
{
    /*
     * All workers, callbacks and AF_XDP ring users must be stopped before
     * entering this function. Lock-free data structures do not make
     * concurrent destruction safe.
     */
    frame_global_cache_reset();
    free(g_xdp_frame_pool.slots);
    free(g_xdp_frame_pool.buffer);
    memset(&g_xdp_frame_pool, 0, sizeof(g_xdp_frame_pool));
}

inline int xdp_frame_alloc(void **frame)
{

    uint32_t idx;
    if (!xdp_frame_pool_pop_idx(&idx))
        return -1;
    *frame = idx_to_ptr(idx);
    return 0;
}

inline void xdp_frame_free(void *frame)
{
    if (!xdp_frame_ptr_valid(frame)) {
        ERR_LOG("xdp: invalid frame pointer=%p\n", frame);
        return;
    }

    uint32_t idx = ptr_to_idx(frame);
    if (!xdp_frame_pool_push_idx(idx))
        ERR_LOG("xdp: frame pool push failed idx=%u; "
                "possible duplicate free or pool corruption\n", idx);
}

static int xdp_umem_create(void)
{


    uint64_t umem_size =
        (uint64_t)g_xdp_frame_pool.frame_size * g_xdp_frame_pool.num_frames;
    struct xsk_umem_opts opts = {
        .sz = sizeof(opts),
        .size = umem_size,
        .fill_size = XDP_FILL_QUEUE_SIZE,
        .comp_size = XDP_COMP_QUEUE_SIZE,
        .frame_size = XDP_UMEM_FRAME_SIZE,
        .frame_headroom = frame_rx_headroom(),
        .flags = XDP_UMEM_TX_METADATA_LEN |
                 XDP_UMEM_UNALIGNED_CHUNK_FLAG,
        .tx_metadata_len = XDP_TX_METADATA_LEN,
    };

    memset(&g_umem_fq, 0, sizeof(g_umem_fq));
    memset(&g_umem_cq, 0, sizeof(g_umem_cq));

    g_xdp_umem = xsk_umem__create_opts(g_xdp_frame_pool.buffer,
                                       &g_umem_fq, &g_umem_cq, &opts);
    int err = (int)libxdp_get_error(g_xdp_umem);
    if (err != 0) {
        g_xdp_umem = NULL;
        ERR_LOG("xdp: xsk_umem__create failed err=%d(%s)\n", err, strerror(-err));
        return -1;
    }

    return 0;
}


static int xdp_umem_delete(void)
{

    int err = xsk_umem__delete(g_xdp_umem);
    if (err != 0)
        return err;

    g_xdp_umem = NULL;
    memset(&g_umem_fq, 0, sizeof(g_umem_fq));
    memset(&g_umem_cq, 0, sizeof(g_umem_cq));
    return 0;
}

int xdp_init(void)
{
    spin_lock_init(&g_xdp_umem_lock);

    if (atexit(xdp_cleanup_programs) != 0)
            return -1;

    if (xdp_frame_pool_init() != 0) {
        ERR_LOG("xdp: global frame pool init failed\n");
        return -1;
    }

    return xdp_umem_create();
}


static inline uint64_t umem_frame_addr(uint64_t addr)
{
    uint64_t raw = xsk_umem__extract_addr(addr);
    return raw - raw % g_xdp_frame_pool.frame_size;
}

static inline void umem_release_addr(uint64_t addr)
{
    xdp_frame_free(xsk_umem__get_data(g_xdp_frame_pool.buffer,
                                      umem_frame_addr(addr)));
}

/* Drain all four rings on teardown, returning frames to pool and releasing
 * data_buf refs.  Must be called before xsk_socket__delete. */
static void xdp_drain_ring_pending(if_xdp* ix)
{
	/* ── RX ring: return unconsumed frames to pool ── */
	uint32_t rx_idx = 0;
	uint32_t rx_n = xsk_ring_cons__peek(&ix->rx, XDP_RX_QUEUE_SIZE, &rx_idx);
	for (uint32_t j = 0; j < rx_n; ++j) {
		const struct xdp_desc* desc = xsk_ring_cons__rx_desc(&ix->rx, rx_idx + j);
		if (desc)
			umem_release_addr(desc->addr);
	}
	if (rx_n)
		xsk_ring_cons__release(&ix->rx, rx_n);

	/* ── TX ring: release data_buf refs for all pending descs ── */
	const __u32 tx_cons = *ix->tx.consumer;
	const __u32 tx_prod  = *ix->tx.producer;
	for (__u32 i = tx_cons; i != tx_prod; ++i) {
		struct xdp_desc* d = xsk_ring_prod__tx_desc(&ix->tx, i);
		if (!d) continue;
		uint64_t raw = xsk_umem__extract_addr(d->addr);
		uint64_t fa = umem_frame_addr(d->addr);
		void* frame  = xsk_umem__get_data(g_xdp_frame_pool.buffer, fa);
		if (frame) {
				uint8_t* data = xsk_umem__get_data(g_xdp_frame_pool.buffer, raw);
				frame_slot* slot = frame_slot_from_addr(frame, data);
				PUT_REF(slot);
		}
	}

	/* ── FQ ring: return un-consumed frames to pool ── */
	const __u32 fq_cons = *ix->fq.consumer;
	const __u32 fq_prod  = *ix->fq.producer;
	for (__u32 i = fq_cons; i != fq_prod; ++i) {
		umem_release_addr(*xsk_ring_prod__fill_addr(&ix->fq, i));
	}
}

//填充提供给内核用于接收的frame
static void umem_refill_fq(if_xdp* ix, struct xsk_ring_prod *fq)
{
    uint32_t idx = 0;
    uint32_t n = xsk_prod_nb_free(fq, XDP_FILL_QUEUE_SIZE);
    if (n == 0)
        return;

    n = xsk_ring_prod__reserve(fq, n, &idx);
    if (n == 0)
        return;

    for (uint32_t i = 0; i < n; ++i) {
        frame_slot* slot = frame_slot_alloc(FRAME_SLOT_MAX_SIZE);
        if (!slot) {
            fq->cached_prod -= (n - i);
            WARN_LOG("xdp: fq refill shortfall at %u/%u\n", i, n);
            return;
        }
        *xsk_ring_prod__fill_addr(fq, idx + i) =
            (uint64_t)((uint8_t *)slot->page - (uint8_t *)g_xdp_frame_pool.buffer);
    }

    xsk_ring_prod__submit(fq, n);

    if (ix && xsk_ring_prod__needs_wakeup(fq)) {
        recvfrom(xsk_socket__fd(ix->xsk),
                NULL, 0,
                MSG_DONTWAIT, 
                NULL, NULL);
    }
}

static void umem_complete_tx(struct xsk_ring_cons* cq)
{
    uint32_t idx = 0;
    uint32_t n   = xsk_ring_cons__peek(cq, XDP_COMP_QUEUE_SIZE, &idx);

    for (uint32_t i = 0; i < n; ++i) {
        uint64_t addr = *xsk_ring_cons__comp_addr(cq, idx + i);
        uint64_t raw  = xsk_umem__extract_addr(addr);
        uint64_t frame_addr = umem_frame_addr(addr);
        void* frame = xsk_umem__get_data(g_xdp_frame_pool.buffer, frame_addr);
        if (frame) {
            uint8_t* data = xsk_umem__get_data(g_xdp_frame_pool.buffer, raw);
            frame_slot* slot = frame_slot_from_addr(frame, data);
            PUT_REF(slot);
        }
    }

    xsk_ring_cons__release(cq, n);
}


static void xdp_tx_update_watch(if_xdp* ix)
{

    int desired_type = ix->pending_tx_queue.element_number
        ? TASK_TYPE_FD_RW : TASK_TYPE_FD_READ;
    if (ix->tk->task_type == desired_type)
        return;

    ix->tk->task_type = desired_type;
    if (register_task(ix->tk->parent_thread, ix->tk) != 0) {
        ERR_LOG("xdp: update TX poll watch failed if=%s q=%u",
                ix->info ? ix->info->name : "?", ix->queue_id);
    }
}

static inline void xdp_tx_kick(if_xdp* ix)
{
    if (xsk_ring_prod__needs_wakeup(&ix->tx)) {
        ssize_t ret = sendto(xsk_socket__fd(ix->xsk), NULL, 0, MSG_DONTWAIT,
                             NULL, 0);
        if (ret < 0 && errno != EAGAIN && errno != EBUSY)
            WARN_LOG("xdp: TX wakeup failed if=%s errno=%d(%s)",
                      ix->info ? ix->info->name : "?", errno,
                      strerror(errno));
    }
}

static inline void xdp_tx_flush(if_xdp* ix)
{
    if (!ix->tx_kick_pending && !ix->pending_tx_queue.element_number)
        return;

    xdp_tx_kick(ix);
    ix->tx_kick_pending = 0;
}

static void xdp_tx_kick_loop(task* tk)
{
    if_xdp* ix = (if_xdp*)tk->argv;

    umem_complete_tx(&ix->cq);
    xdp_tx_flush(ix);
}

/* Submit an skb without retaining skb itself.  The TX descriptors retain the
 * data_buf references until they are returned through the completion ring. */
static int xdp_tx_submit(if_xdp* ix, skbuff* skb)
{
    uint8_t* packet = skb_start(skb);
    uint32_t frames = skb->data_num;

    uint32_t tx_idx = 0;
    umem_refill_fq(ix, &ix->fq);
    umem_complete_tx(&ix->cq);

    uint32_t reserved = xsk_ring_prod__reserve(&ix->tx, frames, &tx_idx);
    if (reserved != frames) {
        if (reserved)
            ix->tx.cached_prod -= reserved;
        return -EAGAIN;
    }

    struct xsk_tx_metadata* meta =
        (struct xsk_tx_metadata*)(packet - XDP_TX_METADATA_LEN);
    meta->flags = 0;

    if (skb->tx_checksum_offset) {
        meta->flags = XDP_TXMD_FLAGS_CHECKSUM;
        meta->request.csum_start =
            (uint16_t)((uint8_t*)skb->l4_hdr - packet);
        meta->request.csum_offset = skb->tx_checksum_offset;
    }

    data_info* di = &skb->data0;
    for (uint32_t i = 0; i < frames; ++i, di = di->next) {
        frame_slot* slot = di->slot;
        struct xdp_desc* d = xsk_ring_prod__tx_desc(&ix->tx, tx_idx + i);
        d->addr = (uint64_t)(di->start -
                             (uint8_t*)g_xdp_frame_pool.buffer);
        d->len = di->end - di->start;
        d->options = 0;
        if (i == 0 && meta->flags)
            d->options |= XDP_TX_METADATA;
        INC_REF(slot);
    }

    xsk_ring_prod__submit(&ix->tx, frames);
    ix->tx_kick_pending += frames;
    if (ix->tx_kick_pending >= XDP_TX_KICK_THRESHOLD)
        xdp_tx_flush(ix);
    return 0;
}

static int xdp_tx_enqueue(if_xdp* ix, skbuff* skb)
{
    if (ix->pending_tx_frames >= XDP_TX_PENDING_FRAME_LIMIT)
        return 0;

    INC_REF(skb);
    add_queue(&ix->pending_tx_queue, &skb->tx_node);
    ix->pending_tx_frames++;
    xdp_tx_update_watch(ix);
    return 0;
}

static void xdp_tx_drain_pending(if_xdp* ix)
{
    if (!ix->pending_tx_queue.element_number)
        return;

    umem_complete_tx(&ix->cq);
    while (ix->pending_tx_queue.element_number) {
        skbuff* skb = SKB_FROM_TX_NODE(get_queue_first(&ix->pending_tx_queue));
        if (!skb)
            break;

        int ret = xdp_tx_submit(ix, skb);
        if (ret == -EAGAIN) {
            umem_complete_tx(&ix->cq);
            ret = xdp_tx_submit(ix, skb);
        }
        if (ret == -EAGAIN)
            break;

        (void)pop_queue(&ix->pending_tx_queue);
        ix->pending_tx_frames--;
        if (ret < 0) {
            WARN_LOG("xdp: drop pending TX skb if=%s q=%u err=%d",
                     ix->info ? ix->info->name : "?", ix->queue_id, -ret);
        }
        PUT_REF(skb);
    }

    xdp_tx_update_watch(ix);
}

static void xdp_tx_drop_pending(if_xdp* ix)
{
    skbuff* skb;
    while ((skb = SKB_FROM_TX_NODE(pop_queue(&ix->pending_tx_queue))) != NULL) {
        PUT_REF(skb);
    }
    ix->pending_tx_frames = 0;
}

static void if_xdp_detach_mode(int ifindex, __u32 flags)
{
    int err;
    err = bpf_xdp_detach(ifindex, flags, NULL);
    if (err == 0 || err == -ENOENT || err == -ENXIO || err == -EOPNOTSUPP)
        return;

    WARN_LOG("xdp: detach existing prog failed ifindex=%d flags=0x%x err=%d(%s)\n",
             ifindex, flags, err, strerror(-err));
}

static void if_xdp_detach_existing_prog(int ifindex)
{
    if_xdp_detach_mode(ifindex, XDP_FLAGS_SKB_MODE);
    if_xdp_detach_mode(ifindex, XDP_FLAGS_DRV_MODE);
    if_xdp_detach_mode(ifindex, XDP_FLAGS_HW_MODE);
}

static __u32 if_xdp_mode_flags(uint32_t mode)
{
    if (mode == XDP_MODE_SKB)
        return XDP_FLAGS_SKB_MODE;
    if (mode == XDP_MODE_NATIVE)
        return XDP_FLAGS_DRV_MODE;
    if (mode == XDP_MODE_HW)
        return XDP_FLAGS_HW_MODE;
    return 0;
}

#ifdef DEBUG
static const char* if_xdp_mode_name(uint32_t mode)
{
    if (mode == XDP_MODE_SKB)
        return "skb";
    if (mode == XDP_MODE_NATIVE)
        return "native";
    if (mode == XDP_MODE_HW)
        return "hw";
    return "unspec";
}
#endif

static xdp_prog_shared* find_xdp_prog_shared(int ifindex)
{
    xdp_prog_shared* it = g_xdp_prog_list;
    while (it) {
        if (it->ifindex == ifindex)
            return it;
        it = it->next;
    }
    return NULL;
}

static void destroy_xdp_prog_shared(xdp_prog_shared* shared)
{
    if (shared->xdp_link) {
        int err = bpf_link__destroy(shared->xdp_link);
        if (err != 0) {
            WARN_LOG("xdp: destroy shared xdp link failed ifindex=%d err=%d\n",
                     shared->ifindex, err);
        }
    } else {
        __u32 flags = if_xdp_mode_flags(shared->xdp_attach_mode);
        if (flags)
            if_xdp_detach_mode(shared->ifindex, flags);
    }

    if (shared->xdp_obj)
        bpf_object__close(shared->xdp_obj);

    free(shared);
}

static void if_xdp_release_redirect_prog(if_xdp* ix)
{
    ix->prog_shared      = NULL;
    ix->xdp_obj          = NULL;
    ix->xdp_link         = NULL;
    ix->xsks_map_fd      = -1;
    ix->ifindex          = 0;
    ix->xdp_attach_mode  = XDP_MODE_UNSPEC;
}

static int if_xdp_attach_redirect_prog(if_xdp* ix)
{

    ix->ifindex  = (int)if_nametoindex(ix->info->name);
    if (ix->ifindex <= 0) {
        WARN_LOG("xdp: if_nametoindex failed if=%s\n", ix->info->name);
        return -1;
    }

    xdp_prog_shared* shared = find_xdp_prog_shared(ix->ifindex);
    if (shared) {
        ix->prog_shared = shared;
        ix->xdp_obj = shared->xdp_obj;
        ix->xdp_link = shared->xdp_link;
        ix->xsks_map_fd = shared->xsks_map_fd;
        ix->xdp_attach_mode = shared->xdp_attach_mode;
        return 0;
    }

    if (get_current_worker() != main_worker) {
        return -1;
    }

    const char* obj_path = XDP_REDIRECT_BPF_OBJ_PATH;

    struct bpf_object_open_opts open_opts = {
        .sz = sizeof(open_opts),
    };
    struct bpf_object* obj = bpf_object__open_file(obj_path, &open_opts);
    long open_err = libbpf_get_error(obj);
    if (open_err) {
        ERR_LOG("xdp: open xdp prog failed path=%s err=%ld\n", obj_path, open_err);
        return -1;
    }

    struct bpf_program* prog = bpf_object__find_program_by_name(obj, "xdp_redirect");
    if (!prog)
        prog = bpf_object__next_program(obj, NULL);
    if (!prog) {
        ERR_LOG("xdp: find program failed path=%s\n", obj_path);
        bpf_object__close(obj);
        return -1;
    }

    int err = bpf_object__load(obj);
    if (err != 0) {
        ERR_LOG("xdp: load xdp obj failed path=%s err=%d(%s)\n",
                obj_path, err, strerror(-err));
        bpf_object__close(obj);
        return -1;
    }

    int prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        ERR_LOG("xdp: get xdp prog fd failed path=%s fd=%d\n", obj_path, prog_fd);
        bpf_object__close(obj);
        return -1;
    }

    if_xdp_detach_existing_prog(ix->ifindex);

    static const uint32_t attach_modes[] = {
        XDP_MODE_NATIVE,
        XDP_MODE_SKB,
    };

    int attach_err = -EOPNOTSUPP;
    uint32_t attached_mode = XDP_MODE_UNSPEC;
    for (size_t i = 0; i < sizeof(attach_modes) / sizeof(attach_modes[0]); i++) {
        uint32_t mode = attach_modes[i];
        attach_err = bpf_xdp_attach(ix->ifindex, prog_fd,
                                    if_xdp_mode_flags(mode), NULL);
        if (attach_err == 0) {
            attached_mode = mode;
            break;
        }

        DEBUG_LOG("xdp: attach redirect prog failed if=%s mode=%s err=%d(%s)\n",
                  ix->info->name, if_xdp_mode_name(mode), attach_err,
                  strerror(-attach_err));
    }

    if (attached_mode == XDP_MODE_UNSPEC) {
        ERR_LOG("xdp: attach redirect prog failed if=%s err=%d(%s)\n",
                ix->info->name, attach_err, strerror(-attach_err));
        bpf_object__close(obj);
        return -1;
    }
    ix->xdp_attach_mode = attached_mode;

    int map_fd = bpf_object__find_map_fd_by_name(obj, "xsks_map");
    if (map_fd <= 0) {
        ERR_LOG("xdp: find xsks_map fd failed path=%s\n", obj_path);
        if_xdp_detach_mode(ix->ifindex, if_xdp_mode_flags(ix->xdp_attach_mode));
        bpf_object__close(obj);
        return -1;
    }

    shared = calloc(1, sizeof(*shared));
    if (!shared) {
        if_xdp_detach_mode(ix->ifindex, if_xdp_mode_flags(ix->xdp_attach_mode));
        bpf_object__close(obj);
        ERR_LOG("xdp: allocate shared redirect state failed if=%s\n", ix->info->name);
        return -1;
    }

    shared->ifindex = ix->ifindex;
    shared->xsks_map_fd = map_fd;
    shared->xdp_attach_mode = ix->xdp_attach_mode;
    shared->xdp_obj = obj;
    shared->xdp_link = NULL;
    shared->next = g_xdp_prog_list;
    g_xdp_prog_list = shared;

    ix->prog_shared = shared;
    ix->xdp_obj     = obj;
    ix->xdp_link    = NULL;
    ix->xsks_map_fd = map_fd;

    return 0;
}

static int if_xdp_bind_socket(if_xdp* ix)
{
    const uint32_t queue_id = ix->queue_id;

    if (if_xdp_attach_redirect_prog(ix) != 0)
        return -1;

    uint32_t xdp_flags = if_xdp_mode_flags(ix->xdp_attach_mode);

    uint16_t bind_flags = XDP_USE_NEED_WAKEUP;

    struct xsk_socket_config cfg = {
        .rx_size      = XDP_RX_QUEUE_SIZE,
        .tx_size      = XDP_TX_QUEUE_SIZE,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags    = xdp_flags,
        .bind_flags   = bind_flags,
    };

    ix->xsk = NULL;

    int err;
    spin_lock(&g_xdp_umem_lock);
    if (!g_xdp_umem && xdp_umem_create() != 0) {
        spin_unlock(&g_xdp_umem_lock);
        if_xdp_release_redirect_prog(ix);
        return -1;
    }
    err = xsk_socket__create_shared(&ix->xsk, ix->info->name, queue_id,
                                    g_xdp_umem,
                                    &ix->rx, &ix->tx,
                                    &ix->fq, &ix->cq,
                                    &cfg);
    spin_unlock(&g_xdp_umem_lock);

    if (err != 0) {
        ERR_LOG("xdp : xsk_socket__create failed if=%s q=%u err=%d(%s) bind_flags=0x%x libbpf_flags=0x%x\n",
                ix->info->name, queue_id, err, strerror(-err),
                (unsigned int)cfg.bind_flags, (unsigned int)cfg.libbpf_flags);
        if_xdp_release_redirect_prog(ix);
        return -1;
    }

    int xsk_fd = xsk_socket__fd(ix->xsk);
    if (xsk_fd < 0) {
        ERR_LOG("xdp: xsk_socket__fd invalid if=%s fd=%d\n", ix->info->name, xsk_fd);
        if_xdp_unbind_socket(ix);
        if_xdp_release_redirect_prog(ix);
        return -1;
    }

    __u32 key   = queue_id;
    __u32 value = (__u32)xsk_fd;
    if (bpf_map_update_elem(ix->xsks_map_fd, &key, &value, 0) != 0) {
        ERR_LOG("xdp: update xsks_map failed if=%s map_fd=%d q=%u errno=%d(%s)\n",
            ix->info->name, ix->xsks_map_fd, queue_id, errno, strerror(errno));
        if_xdp_unbind_socket(ix);
        if_xdp_release_redirect_prog(ix);
        return -1;
    }

    DEBUG_LOG("xdp: xsk create ok if=%s fd=%d bind_flags=0x%x\n",
               ix->info->name, xsk_socket__fd(ix->xsk), (unsigned int)cfg.bind_flags);

	    /* 初始填充 FQ，使内核可以把到达的包写入 UMEM。 */
    umem_refill_fq(ix, &ix->fq);
    return 0;
}

static void if_xdp_unbind_socket(if_xdp* ix)
{
    xdp_drain_ring_pending(ix);
    if (ix->xsk) {
        int err;

        spin_lock(&g_xdp_umem_lock);
        xsk_socket__delete(ix->xsk);
        ix->xsk = NULL;
        err = xdp_umem_delete();
        spin_unlock(&g_xdp_umem_lock);

        if (err != 0 && err != -EBUSY)
            WARN_LOG("xdp: xsk_umem__delete failed err=%d(%s)",
                     err, strerror(-err));
    }
}

static int if_set_hw_rss_toeplitz(if_info* info, int queues)
{
    /* Interfaces omitted from open_if do not own AF_XDP queues.  A single
     * queue needs no traffic distribution and may legitimately expose no
     * ETHTOOL_GRSSH/SRSSH support, as with a one-queue virtio-net device. */
    if (!info || queues <= 1)
        return 0;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;

    struct ifreq ifr = {0};
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", info->name);

    struct {
        struct ethtool_sset_info info;
        __u32 count;
    } sset = {
        .info = {
            .cmd = ETHTOOL_GSSET_INFO,
            .sset_mask = UINT64_C(1) << ETH_SS_FEATURES,
        },
    };
    ifr.ifr_data = (void*)&sset;
    if (ioctl(fd, SIOCETHTOOL, &ifr) != 0 ||
        !(sset.info.sset_mask & (UINT64_C(1) << ETH_SS_FEATURES)) ||
        sset.count == 0) {
        ERR_LOG("xdp: get feature count failed if=%s errno=%d(%s)",
                info->name, errno, strerror(errno));
        close(fd);
        return -1;
    }

    size_t strings_size = sizeof(struct ethtool_gstrings) +
                          (size_t)sset.count * ETH_GSTRING_LEN;
    struct ethtool_gstrings* strings = calloc(1, strings_size);
    if (!strings) {
        close(fd);
        return -1;
    }
    strings->cmd = ETHTOOL_GSTRINGS;
    strings->string_set = ETH_SS_FEATURES;
    strings->len = sset.count;
    ifr.ifr_data = (void*)strings;
    if (ioctl(fd, SIOCETHTOOL, &ifr) != 0) {
        ERR_LOG("xdp: get feature names failed if=%s errno=%d(%s)",
                info->name, errno, strerror(errno));
        free(strings);
        close(fd);
        return -1;
    }

    uint32_t rxhash_index = UINT32_MAX;
    for (uint32_t i = 0; i < strings->len; i++) {
        const char* name = (const char*)strings->data +
                           (size_t)i * ETH_GSTRING_LEN;
        if (strncmp(name, "rx-hashing", ETH_GSTRING_LEN) == 0) {
            rxhash_index = i;
            break;
        }
    }
    free(strings);
    if (rxhash_index == UINT32_MAX) {
        errno = EOPNOTSUPP;
        ERR_LOG("xdp: rx-hashing feature missing if=%s", info->name);
        close(fd);
        return -1;
    }

    uint32_t feature_blocks = (sset.count + 31u) / 32u;
    size_t get_size = sizeof(struct ethtool_gfeatures) +
                      (size_t)feature_blocks *
                      sizeof(struct ethtool_get_features_block);
    struct ethtool_gfeatures* get_features = calloc(1, get_size);
    if (!get_features) {
        close(fd);
        return -1;
    }
    get_features->cmd = ETHTOOL_GFEATURES;
    get_features->size = feature_blocks;
    ifr.ifr_data = (void*)get_features;
    if (ioctl(fd, SIOCETHTOOL, &ifr) != 0) {
        ERR_LOG("xdp: get features failed if=%s errno=%d(%s)",
                info->name, errno, strerror(errno));
        free(get_features);
        close(fd);
        return -1;
    }

    uint32_t block = rxhash_index / 32u;
    uint32_t bit = UINT32_C(1) << (rxhash_index % 32u);
    bool rxhash_active = (get_features->features[block].active & bit) != 0;
    bool rxhash_available =
        (get_features->features[block].available & bit) != 0;
    free(get_features);
    if (!rxhash_active) {
        if (!rxhash_available) {
            errno = EOPNOTSUPP;
            ERR_LOG("xdp: rx-hashing cannot be enabled if=%s", info->name);
            close(fd);
            return -1;
        }

        size_t set_size = sizeof(struct ethtool_sfeatures) +
                          (size_t)feature_blocks *
                          sizeof(struct ethtool_set_features_block);
        struct ethtool_sfeatures* set_features = calloc(1, set_size);
        if (!set_features) {
            close(fd);
            return -1;
        }
        set_features->cmd = ETHTOOL_SFEATURES;
        set_features->size = feature_blocks;
        set_features->features[block].valid = bit;
        set_features->features[block].requested = bit;
        ifr.ifr_data = (void*)set_features;
        int set_ret = ioctl(fd, SIOCETHTOOL, &ifr);
        free(set_features);
        if (set_ret != 0) {
            ERR_LOG("xdp: enable rx-hashing failed if=%s errno=%d(%s)",
                    info->name, errno, strerror(errno));
            close(fd);
            return -1;
        }
    }

    /* A zero-sized GRSSH request only returns the variable payload sizes. */
    struct ethtool_rxfh query = { .cmd = ETHTOOL_GRSSH };
    ifr.ifr_data = (void*)&query;
    int ioctl_ret = ioctl(fd, SIOCETHTOOL, &ifr);
    if (ioctl_ret != 0) {
        if (ioctl_ret > 0)
            errno = EIO;
        ERR_LOG("xdp: get RSS sizes failed if=%s ret=%d errno=%d(%s)",
                info->name, ioctl_ret, errno, strerror(errno));
        close(fd);
        return -1;
    }

    if (query.indir_size == 0 ||
        query.indir_size > (SIZE_MAX - sizeof(struct ethtool_rxfh) -
                            query.key_size) / sizeof(__u32)) {
        errno = query.indir_size ? EOVERFLOW : EOPNOTSUPP;
        ERR_LOG("xdp: invalid RSS sizes if=%s indir=%u key=%u",
                info->name, query.indir_size, query.key_size);
        close(fd);
        return -1;
    }

    size_t config_size = (size_t)query.indir_size * sizeof(__u32) +
                         (size_t)query.key_size;
    struct ethtool_rxfh* rxfh = calloc(1, sizeof(*rxfh) + config_size);
    if (!rxfh) {
        close(fd);
        return -1;
    }

    /* Fetch the current table and key.  Keeping the returned key matters on
     * drivers whose key size differs from NetFast's configured key. */
    rxfh->cmd = ETHTOOL_GRSSH;
    rxfh->indir_size = query.indir_size;
    rxfh->key_size = query.key_size;
    ifr.ifr_data = (void*)rxfh;
    ioctl_ret = ioctl(fd, SIOCETHTOOL, &ifr);
    if (ioctl_ret != 0) {
        if (ioctl_ret > 0)
            errno = EIO;
        ERR_LOG("xdp: get RSS config failed if=%s ret=%d errno=%d(%s)",
                info->name, ioctl_ret, errno, strerror(errno));
        free(rxfh);
        close(fd);
        return -1;
    }
    if (rxfh->indir_size > query.indir_size || rxfh->key_size > query.key_size) {
        errno = EOVERFLOW;
        ERR_LOG("xdp: RSS sizes changed if=%s indir=%u/%u key=%u/%u",
                info->name, rxfh->indir_size, query.indir_size,
                rxfh->key_size, query.key_size);
        free(rxfh);
        close(fd);
        return -1;
    }

    __u32* indir = rxfh->rss_config;
    __u8* hw_key = (__u8*)(indir + rxfh->indir_size);
    uint32_t key_len = 0;
    const uint8_t* key = toeplitz_rss_get_key(&key_len);

    rxfh->cmd = ETHTOOL_SRSSH;

    for (__u32 i = 0; i < rxfh->indir_size; ++i)
        indir[i] = (__u32)(i % (unsigned)queues);

    if (key && key_len > 0 && rxfh->key_size == key_len)
        memcpy(hw_key, key, key_len);

    ioctl_ret = ioctl(fd, SIOCETHTOOL, &ifr);
    if (ioctl_ret != 0) {
        if (ioctl_ret > 0)
            errno = EIO;
        ERR_LOG("xdp: set RSS config failed if=%s ret=%d errno=%d(%s)",
                info->name, ioctl_ret, errno, strerror(errno));
        free(rxfh);
        close(fd);
        return -1;
    }

    free(rxfh);
    close(fd);
    return 0;
}

int xdp_if_start(if_info *info)
{
    /* Netlink reports every link, whereas only open_if entries are AF_XDP
     * interfaces.  Leave all other links untouched. */
    if (!info)
        return 0;

    int queues = cfg_get_if_queues(info->name);
    if (queues <= 0)
        return 0;

    worker* w = get_current_worker();
    int w_idx = (int)(w - g_workers);

    /* RSS configuration is performed once by the main worker. */
    if (w == main_worker && queues > 1 &&
        if_set_hw_rss_toeplitz(info, queues) < 0) {
        ERR_LOG("xdp: RSS configuration failed if=%s", info->name);
    }

    /* Create XSK for every queue assigned to this worker
       (stride = g_worker_num). */
    for (int q = w_idx; q < queues; q += g_worker_num) {
        if (info->xdp_data[q]) {
            continue;
        }
		if_xdp* ix = calloc(1, sizeof(*ix));
        if (!ix) {
            ERR_LOG("xdp: calloc if_xdp failed");
			(void)xdp_if_stop(info);
            return -1;
        }

        ix->info     = info;
        ix->queue_id = (uint32_t)q;
        init_queue(&ix->pending_tx_queue);
        if (if_xdp_bind_socket(ix) != 0) {
            ERR_LOG("xdp: bind failed if=%s q=%d", info->name, q);
            free(ix);
			(void)xdp_if_stop(info);
            return -1;
        }

        ix->tk = create_task(TASK_TYPE_FD_READ);
        if (!ix->tk) {
            ERR_LOG("xdp: create_task failed if=%s q=%d", info->name, q);
            if_xdp_unbind_socket(ix);
			if_xdp_release_redirect_prog(ix);
            free(ix);
			(void)xdp_if_stop(info);
            return -1;
        }

        ix->tk->fd      = xsk_socket__fd(ix->xsk);
        ix->tk->cb_read = xdp_if_read;
        ix->tk->cb_write = xdp_if_write;
        ix->tk->cb_err  = NULL;
        ix->tk->argv    = (uint64_t)ix;   /* xdp_if_read recovers ix directly */

        if (register_task(w->master, ix->tk) != 0) {
            ERR_LOG("xdp: register_task failed if=%s q=%d", info->name, q);
            destroy_task(ix->tk);
            if_xdp_unbind_socket(ix);
            if_xdp_release_redirect_prog(ix);
            free(ix);
			(void)xdp_if_stop(info);
            return -1;
        }

        ix->tx_kick_task = create_task(TASK_TYPE_LOOP);
        if (!ix->tx_kick_task) {
            ERR_LOG("xdp: create TX kick task failed if=%s q=%d", info->name, q);
            destroy_task(ix->tk);
            if_xdp_unbind_socket(ix);
			if_xdp_release_redirect_prog(ix);
            free(ix);
			(void)xdp_if_stop(info);
            return -1;
        }
        ix->tx_kick_task->cb_loop = xdp_tx_kick_loop;
        ix->tx_kick_task->argv = (uint64_t)ix;
        if (register_task(w->master, ix->tx_kick_task) != 0) {
            ERR_LOG("xdp: register TX kick task failed if=%s q=%d", info->name, q);
            destroy_task(ix->tx_kick_task);
            destroy_task(ix->tk);
            if_xdp_unbind_socket(ix);
			if_xdp_release_redirect_prog(ix);
            free(ix);
			(void)xdp_if_stop(info);
            return -1;
        }

	        info->xdp_data[q] = ix;
	        DEBUG_LOG("xdp: started if=%s q=%d fd=%d", info->name, q, ix->tk->fd);
	    }

    return 0;
}

int xdp_if_stop(if_info *info)
{
    int queues = cfg_get_if_queues(info->name);

    if (queues <= 0)
        return 0;

    worker* w = get_current_worker();
    int w_idx = (int)(w - g_workers);

    for (int q = w_idx; q < queues; q += g_worker_num) {
        if_xdp* ix = (if_xdp*)info->xdp_data[q];
        if (!ix)
            continue;

	        DEBUG_LOG("xdp: stopping if=%s q=%d", info->name, q);
	        info->xdp_data[q] = NULL;

			/* Stop callbacks before touching rings. */
			destroy_task(ix->tx_kick_task);
			ix->tx_kick_task = NULL;
		if (ix->tk) {
			unregister_task(ix->tk);
			destroy_task(ix->tk);
			ix->tk = NULL;
		}
        xdp_tx_drop_pending(ix);
        umem_complete_tx(&ix->cq);

		if_xdp_release_redirect_prog(ix);
        if_xdp_unbind_socket(ix);
        free(ix);
    }

    /* Main worker stops last: all queues are gone, safe to detach XDP. */
    if (w == main_worker) {
        int ifindex = (int)if_nametoindex(info->name);
        xdp_prog_shared** prev = &g_xdp_prog_list;
        xdp_prog_shared* it = g_xdp_prog_list;
        while (it) {
            if (it->ifindex == ifindex) {
                *prev = it->next;
                destroy_xdp_prog_shared(it);
                break;
            }
            prev = &it->next;
            it = it->next;
        }
    }

    return 0;
}

void xdp_if_read(task *tk)
{
    if_xdp* ix = (if_xdp*)tk->argv;
    if_info* info = ix->info;


    struct xsk_ring_cons* rx  = &ix->rx;
    const uint32_t cap = g_xdp_frame_pool.frame_size > frame_rx_headroom()
        ? g_xdp_frame_pool.frame_size - frame_rx_headroom() : 0;

    uint32_t drained = 0;
    while (drained < XDP_RX_QUEUE_SIZE) {
        uint32_t idx = 0;
        uint32_t budget = min(XDP_RX_BATCH_SIZE,
                              XDP_RX_QUEUE_SIZE - drained);
        uint32_t n = xsk_ring_cons__peek(rx, budget, &idx);
        if (n == 0)
            break;

    for (uint32_t i = 0; i < n; ) {
        /* ---- start of a new packet (first frame: XDP_PKT_CONTD is NOT set) ---- */
        const struct xdp_desc* desc = xsk_ring_cons__rx_desc(rx, idx + i);
        if (!desc) {
            ERR_LOG("xdp: rx_desc NULL\n");
            i++;
            continue;
        }
		if (ix->rx_drop_contd) {
			bool more = (desc->options & XDP_PKT_CONTD) != 0;
			uint64_t raw = xsk_umem__extract_addr(desc->addr);
			umem_release_addr(raw - raw % g_xdp_frame_pool.frame_size);
			ix->rx_drop_contd = more;
			i++;
			continue;
		}

        if (desc->len == 0) {
			ix->rx_drop_contd = (desc->options & XDP_PKT_CONTD) != 0;
            uint64_t raw_addr   = xsk_umem__extract_addr(desc->addr);
            uint64_t frame_addr = raw_addr;
            if ((raw_addr % g_xdp_frame_pool.frame_size) != 0)
                frame_addr = raw_addr - (raw_addr % g_xdp_frame_pool.frame_size);
            umem_release_addr(frame_addr);
            i++;
            continue;
        }

        if (desc->len > cap) {
			ix->rx_drop_contd = (desc->options & XDP_PKT_CONTD) != 0;
            WARN_LOG("xdp: drop oversize desc len=%u cap=%u if=%s\n", desc->len, cap,
                     info ? info->name : "?");
            uint64_t raw_addr   = xsk_umem__extract_addr(desc->addr);
            uint64_t frame_addr = raw_addr;
            if ((raw_addr % g_xdp_frame_pool.frame_size) != 0)
                frame_addr = raw_addr - (raw_addr % g_xdp_frame_pool.frame_size);
            umem_release_addr(frame_addr);
            i++;
            continue;
        }
        /* ---- build scatter-gather skb: collect first frame + all CONTD frames ---- */
        data_info*  infos[SKB_DATA_MAX_NUM];
        uint32_t    frame_count = 0;
		bool packet_bad = false;
		bool more = false;

        do {
            const struct xdp_desc* d = xsk_ring_cons__rx_desc(rx, idx + i);
			more = d && ((d->options & XDP_PKT_CONTD) != 0);
            if (!d || d->len == 0) {
                if (d && d->len == 0) {
                    uint64_t z_raw = xsk_umem__extract_addr(d->addr);
                    uint64_t z_fa  = z_raw;
                    if ((z_raw % g_xdp_frame_pool.frame_size) != 0)
                        z_fa = z_raw - (z_raw % g_xdp_frame_pool.frame_size);
                    umem_release_addr(z_fa);
                }
				packet_bad = true;
                i++;
				if (!more) break;
				continue;
            }

            uint64_t raw_addr   = xsk_umem__extract_addr(d->addr);
            uint64_t frame_addr = raw_addr;
            uint64_t data_addr  = xsk_umem__add_offset_to_addr(d->addr);

            if ((raw_addr % g_xdp_frame_pool.frame_size) != 0) {
                frame_addr = raw_addr - (raw_addr % g_xdp_frame_pool.frame_size);
                data_addr  = raw_addr;
            }

            void* frame = xsk_umem__get_data(g_xdp_frame_pool.buffer, frame_addr);
            if (!frame) {
                umem_release_addr(frame_addr);
				packet_bad = true;
                i++;
				if (!more) break;
				continue;
            }

            uint8_t*  payload = (uint8_t*)xsk_umem__get_data(g_xdp_frame_pool.buffer, data_addr);
            if (!payload) {
                umem_release_addr(frame_addr);
				packet_bad = true;
                i++;
				if (!more) break;
				continue;
            }
			if (packet_bad || d->len > cap || frame_count >= SKB_DATA_MAX_NUM) {
				umem_release_addr(frame_addr);
				packet_bad = true;
				i++;
				if (!more) break;
				continue;
			}

            uint32_t chunk = d->len;

            frame_slot* slot = frame_slot_from_addr(frame, payload);
            if (!slot) {
                umem_release_addr(frame_addr);
				packet_bad = true;
                i++;
				if (!more) break;
				continue;
            }
            /* The kernel has consumed the FQ descriptor.  Transfer its
             * existing frame reference to data_info; taking another one here
             * would keep every received frame permanently out of the pool. */
            uint32_t pkt_offset = (uint32_t)(payload - slot->data);
            data_info* ni = create_data_info(slot, pkt_offset, pkt_offset + chunk);
            if (!ni) {
                PUT_REF(slot);
				packet_bad = true;
                i++;
				if (!more) break;
				continue;
            }
            infos[frame_count++] = ni;
            i++;

			/* XDP_PKT_CONTD on the current descriptor means another follows. */
            if (!more)
                break;
			if (i >= n) {
				packet_bad = true;
				ix->rx_drop_contd = true;
                break;
			}

        } while (1);

		if (packet_bad) {
			for (uint32_t f = 0; f < frame_count; ++f)
				free_data_info(infos[f]);
			continue;
		}

        if (frame_count == 0)
            continue;

        /* terminate the info array */
        if (frame_count < SKB_DATA_MAX_NUM)
            infos[frame_count] = NULL;

		skbuff* skb = skb_alloc_with_data_info(infos);
	        if (!skb) {
	            ERR_LOG("xdp: skb allocation failed\n");
	            for (uint32_t f = 0; f < frame_count; f++)
	                free_data_info(infos[f]);
	            continue;
	        }
        /* Only native and HW-offload modes guarantee HW checksum validation.
         * In generic/SKB mode the kernel stack never validates before AF_XDP
         * userspace receives the packet. */
        if (info->hw_rx_checksum_enabled &&
            (ix->xdp_attach_mode == XDP_MODE_NATIVE ||
             ix->xdp_attach_mode == XDP_MODE_HW))
            skb->flag.is_hw_rcv_checksum = 1;
        GET_REF(skb->recv_if, info);
        if (info->ops->recv) {
            (void)info->ops->recv(info, skb);
        }

        PUT_REF(skb);
    }

    xsk_ring_cons__release(rx, n);
    umem_refill_fq(ix, &ix->fq);
    umem_complete_tx(&ix->cq);
    drained += n;
	}
}

static void xdp_if_write(task* tk)
{
    if_xdp* ix = (if_xdp*)tk->argv;
    xdp_tx_drain_pending(ix);
}

int xdp_if_send(if_info *info, skbuff *skb)
{
    if_xdp* ix = xdp_tx_pick(info, skb);
    if (!ix)
        return -ENETDOWN;

    return xdp_tx_send(ix, skb);
}

static int xdp_tx_send(if_xdp* ix, skbuff* skb)
{
    if (ix->pending_tx_queue.element_number)
        return xdp_tx_enqueue(ix, skb);

    int ret = xdp_tx_submit(ix, skb);
    if (ret != -EAGAIN)
        return ret;

    return xdp_tx_enqueue(ix, skb);
}

/* Pick a TX queue owned by the current worker using skb-address hash. */
static if_xdp* xdp_tx_pick(if_info* info, skbuff* skb)
{
    worker* w = get_current_worker();
    int w_idx = (int)(w - g_workers);
    int queues = cfg_get_if_queues(info->name);

    if (w_idx >= queues)
        return NULL;

    int n_owned = 1 + (queues - 1 - w_idx) / g_worker_num;
    uint32_t pick = (uint32_t)((uintptr_t)skb) % (uint32_t)n_owned;
    int q = w_idx + (int)pick * g_worker_num;
    return (if_xdp*)info->xdp_data[q];
}

static int xdp_process_send(skbuff* skb)
{
    return xdp_if_send(skb->route->if_info, skb);
}

int xdp_transmit_skb(struct if_info *info, skbuff *skb)
{
    if_xdp* ix = xdp_tx_pick(info, skb);
    if (ix)
        return xdp_tx_send(ix, skb);

    int queues = cfg_get_if_queues(info->name);
    if (queues <= 0)
        return -ENETDOWN;
    uint32_t h = (uint32_t)((uintptr_t)skb);
    int pick = (int)(h % (uint32_t)queues);
    worker* txw = &g_workers[pick % g_worker_num];

    transmit_skb_2_worker(txw, skb, xdp_process_send);
    return 0;
}
