#ifndef XDP_H
#define XDP_H

#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>

#include <xdp/xsk.h>
#include "queue.h"
#include "frame_cache.h"

struct task;
struct if_info;
struct skbuff;
struct xsk_socket;
struct bpf_link;
struct bpf_object;
typedef struct req req;

// AF_XDP核心配置（全局共享�?
#define XDP_TX_METADATA_LEN FRAME_TX_METADATA_LEN
#define XDP_ALIGN16(value) FRAME_ALIGN16(value)
#define XDP_RX_FRAME_HEADROOM FRAME_SLOT_FULL_HEADROOM
#define XDP_UMEM_FRAME_MAX_DATA_LEN FRAME_SLOT_SIZE_6

// XDP BPF 程序路径
#define XDP_REDIRECT_BPF_OBJ_PATH "/usr/local/lib/bpf/xdp_redirect.bpf.o"

#define XDP_UMEM_FRAME_SIZE FRAME_PAGE_SIZE

#define XDP_UMEM_FRAME_CNT (64U * 1024U)     // 全局 XDP frame 池：64K * 4KB = 256MB

#define XDP_FILL_QUEUE_SIZE 2048U // FILL队列大小

#define XDP_COMP_QUEUE_SIZE 2048U // COMP队列大小

#define XDP_RX_QUEUE_SIZE 1024U      // 每个XSK的RX队列大小

#define XDP_TX_QUEUE_SIZE 1024U     // 每个XSK的TX队列大小

#define XDP_TX_KICK_THRESHOLD 64U

#define XDP_TX_PENDING_FRAME_LIMIT (XDP_TX_QUEUE_SIZE * 4U) //tx ring 满暂存大小

#define XDP_RX_BATCH_SIZE 256U



typedef struct xdp_frame_slot {
    _Atomic uint64_t sequence;    // distinguishes turns of the ring
    uint32_t frame_idx;
} xdp_frame_slot;

typedef struct xdp_frame_pool {
    void *buffer;
    uint32_t frame_size;
    uint32_t num_frames;

    xdp_frame_slot *slots;
    uint32_t ring_size;
    uint32_t ring_mask;

    _Atomic uint64_t enqueue_pos;  // next producer slot
    _Atomic uint64_t dequeue_pos;  // next consumer slot
} xdp_frame_pool;

extern xdp_frame_pool g_xdp_frame_pool;

/* ── Public API (unchanged signatures) ─────────────────────── */
int xdp_frame_pool_init(void);

int  xdp_frame_alloc(void **frame);
void xdp_frame_free(void *frame);


typedef struct if_xdp {
	struct xsk_socket *xsk;
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct task* tk;
	struct task* tx_kick_task;
	struct if_info* info;
	void* prog_shared;
	struct bpf_object* xdp_obj;
	struct bpf_link* xdp_link;
	int xsks_map_fd;
	int ifindex;
	uint32_t queue_id;
	uint32_t xdp_attach_mode;
	queue pending_tx_queue;
	uint32_t pending_tx_frames;
	uint32_t tx_kick_pending;
	bool rx_drop_contd;
} if_xdp;

int xdp_if_start(struct if_info *info);

int xdp_if_stop(struct if_info *info);

void xdp_if_read(struct task *tk);

int xdp_if_send(struct if_info *info, struct skbuff *skb);

int xdp_transmit_skb(struct if_info *info, struct skbuff *skb);


int xdp_init(void);

void xdp_cleanup_programs(void);


#endif
