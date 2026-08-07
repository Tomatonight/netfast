#ifndef FRAME_CACHE_H
#define FRAME_CACHE_H

#include <stdatomic.h>
#include <stdint.h>
#include <xdp/xsk.h>

#include "base.h"

#define FRAME_PAGE_SIZE 4096U
#define FRAME_ALIGN16(value) (((uint32_t)(value) + 15U) & ~15U)
#define FRAME_TX_METADATA_LEN ((uint32_t)sizeof(struct xsk_tx_metadata))

#define FRAME_SLOT_CLASS_COUNT 6U
#define FRAME_SLOT_SIZE_1 128U
#define FRAME_SLOT_SIZE_2 254U
#define FRAME_SLOT_SIZE_3 512U
#define FRAME_SLOT_SIZE_4 1024U
#define FRAME_SLOT_SIZE_5 1800U
#define FRAME_SLOT_DEFAULT_DATA_LEN FRAME_SLOT_SIZE_6

/* The local cache is deliberately small enough to stay hot in one worker.
 * The shared cache absorbs cross-thread frees and short traffic bursts. */
#define THREAD_FRAME_CACHE_LIMIT 64U
#define THREAD_FRAME_CACHE_LOW 32U
#define GLOBAL_FRAME_CACHE_LIMIT 1024U

typedef struct page_info page_info;
typedef struct frame_slot frame_slot;

typedef struct frame_cache_entry {
    page_info* page;
    uint32_t generation;
    uint16_t slot_index;
} frame_cache_entry;

typedef struct frame_cache {
    frame_cache_entry entries[FRAME_SLOT_CLASS_COUNT]
                             [THREAD_FRAME_CACHE_LIMIT];
    uint16_t count[FRAME_SLOT_CLASS_COUNT];
} frame_cache;

/* page_info and every frame_slot live in the UMEM frame itself.  page.ref has
 * one reference per live or cached slot; cache eviction of the final free
 * slot returns the raw frame. */
struct page_info {
    ref_info ref;
    frame_slot* free_slot_list;
    atomic_uint used_number;
    atomic_uint generation;
    uint32_t slot_stride;
    uint16_t slot_size;
    uint16_t slot_count;
    uint16_t first_slot_offset;
};

struct frame_slot {
    ref_info ref;
    page_info* page;
    frame_slot* next_free;
    uint8_t* data;
    uint32_t generation;
    uint16_t slot_size;
    uint16_t index;
};

/* The final size class consumes one complete UMEM frame.  Metadata remains
 * at the front, so slot_size is the frame's usable data capacity. */
#define FRAME_SLOT_FULL_HEADROOM \
    FRAME_ALIGN16(FRAME_ALIGN16(sizeof(page_info)) + sizeof(frame_slot) + \
                  FRAME_TX_METADATA_LEN)
#define FRAME_SLOT_SIZE_6 (FRAME_PAGE_SIZE - FRAME_SLOT_FULL_HEADROOM)
#define FRAME_SLOT_MAX_SIZE FRAME_SLOT_SIZE_6

typedef struct data_info {
    frame_slot* slot;
    uint8_t* start;
    uint8_t* end;
    struct data_info* next;
    uint32_t size;
} data_info;

void free_data_info(data_info* info);
data_info* alloc_data_info(uint32_t size);
data_info* create_data_info(frame_slot* slot, uint32_t start, uint32_t end);
void copy_data_info(data_info* dst, const data_info* src);

frame_slot* frame_slot_alloc(uint32_t min_data_len);
uint32_t frame_slot_alloc_batch(frame_slot** out, uint32_t max,
                                uint32_t min_data_len);
frame_slot* frame_slot_init_rx(void* frame, uint8_t* data,
                               uint32_t data_len);
frame_slot* frame_slot_from_addr(void* frame, const uint8_t* addr);
uint32_t frame_rx_headroom(void);

void frame_global_cache_init(void);
void frame_cache_init(frame_cache* cache);
void frame_cache_reset(frame_cache* cache);
void frame_global_cache_reset(void);

page_info* create_page_info(void);

#endif
