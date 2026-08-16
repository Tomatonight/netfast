#include "frame_cache.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "worker.h"
#include "thread.h"
#include "xdp.h"

static void destroy_page_info(void* ptr);
static void destroy_frame_slot(void* ptr);

_Static_assert(THREAD_FRAME_CACHE_LOW > 0 &&
               THREAD_FRAME_CACHE_LOW < THREAD_FRAME_CACHE_LIMIT,
               "thread cache low watermark must be below its limit");
_Static_assert(XDP_UMEM_FRAME_SIZE >=
                   XDP_ALIGN16(sizeof(page_info)) +
                   XDP_ALIGN16(sizeof(frame_slot) + XDP_TX_METADATA_LEN +
                               FRAME_SLOT_MAX_SIZE),
               "a frame must hold page_info and at least one maximum slot");

static inline frame_cache* get_local_frame_cache(void)
{
    worker* current = get_current_worker();
    return &current->master->frame_cache;
}


typedef struct global_frame_cache_slot {
    _Atomic uint64_t sequence;
    frame_slot* entry;
} global_frame_cache_slot;

typedef struct global_frame_cache_class {
    global_frame_cache_slot slots[GLOBAL_FRAME_CACHE_LIMIT];
    _Alignas(64) _Atomic uint64_t enqueue_pos;
    _Alignas(64) _Atomic uint64_t dequeue_pos;
} global_frame_cache_class;

typedef struct global_frame_cache {
    global_frame_cache_class classes[FRAME_SLOT_CLASS_COUNT];
} global_frame_cache;

static global_frame_cache g_frame_cache;

static const uint16_t g_frame_slot_sizes[FRAME_SLOT_CLASS_COUNT] = {
    FRAME_SLOT_SIZE_1,
    FRAME_SLOT_SIZE_2,
    FRAME_SLOT_SIZE_3,
    FRAME_SLOT_SIZE_4,
    FRAME_SLOT_SIZE_5,
    FRAME_SLOT_SIZE_6,
};

void frame_global_cache_init(void)
{
    for (uint32_t cls = 0; cls < FRAME_SLOT_CLASS_COUNT; ++cls) {
        global_frame_cache_class* cache =
            &g_frame_cache.classes[cls];
        atomic_init(&cache->enqueue_pos, 0);
        atomic_init(&cache->dequeue_pos, 0);
        for (uint64_t i = 0; i < GLOBAL_FRAME_CACHE_LIMIT; ++i)
            atomic_init(&cache->slots[i].sequence, i);
    }
}

static uint32_t global_cache_class_enqueue_batch(
    global_frame_cache_class* cache, frame_slot* const* entries,
    uint32_t max_entries)
{
    if (!max_entries)
        return 0;
    if (max_entries > GLOBAL_FRAME_CACHE_LIMIT)
        max_entries = GLOBAL_FRAME_CACHE_LIMIT;

    uint64_t pos = atomic_load_explicit(&cache->enqueue_pos,
                                        memory_order_relaxed);

    for (;;) {
        uint32_t ready = 0;
        bool stale = false;
        while (ready < max_entries) {
            uint64_t entry_pos = pos + ready;
            global_frame_cache_slot* slot =
                &cache->slots[entry_pos &
                              (GLOBAL_FRAME_CACHE_LIMIT - 1U)];
            uint64_t sequence = atomic_load_explicit(&slot->sequence,
                                                     memory_order_acquire);
            intptr_t diff = (intptr_t)sequence - (intptr_t)entry_pos;
            if (diff == 0) {
                ++ready;
                continue;
            }
            if (diff > 0)
                stale = true;
            break;
        }

        if (stale) {
            pos = atomic_load_explicit(&cache->enqueue_pos,
                                       memory_order_relaxed);
            continue;
        }
        if (!ready)
            return 0;

        uint64_t next = pos + ready;
        if (!atomic_compare_exchange_weak_explicit(
                &cache->enqueue_pos, &pos, next,
                memory_order_relaxed, memory_order_relaxed))
            continue;

        for (uint32_t i = 0; i < ready; ++i) {
            uint64_t entry_pos = pos + i;
            global_frame_cache_slot* slot =
                &cache->slots[entry_pos &
                              (GLOBAL_FRAME_CACHE_LIMIT - 1U)];
            slot->entry = entries[i];
            atomic_store_explicit(&slot->sequence, entry_pos + 1U,
                                  memory_order_release);
        }
        return ready;
    }
}

static uint32_t global_cache_class_dequeue_batch(
    global_frame_cache_class* cache, frame_slot** entries,
    uint32_t max_entries)
{
    if (!max_entries)
        return 0;
    if (max_entries > GLOBAL_FRAME_CACHE_LIMIT)
        max_entries = GLOBAL_FRAME_CACHE_LIMIT;

    uint64_t pos = atomic_load_explicit(&cache->dequeue_pos,
                                        memory_order_relaxed);

    for (;;) {
        uint32_t ready = 0;
        bool stale = false;
        while (ready < max_entries) {
            uint64_t entry_pos = pos + ready;
            global_frame_cache_slot* slot =
                &cache->slots[entry_pos &
                              (GLOBAL_FRAME_CACHE_LIMIT - 1U)];
            uint64_t sequence = atomic_load_explicit(&slot->sequence,
                                                     memory_order_acquire);
            intptr_t diff = (intptr_t)sequence -
                            (intptr_t)(entry_pos + 1U);
            if (diff == 0) {
                ++ready;
                continue;
            }
            if (diff > 0)
                stale = true;
            break;
        }

        if (stale) {
            pos = atomic_load_explicit(&cache->dequeue_pos,
                                       memory_order_relaxed);
            continue;
        }
        if (!ready)
            return 0;

        uint64_t next = pos + ready;
        if (!atomic_compare_exchange_weak_explicit(
                &cache->dequeue_pos, &pos, next,
                memory_order_relaxed, memory_order_relaxed))
            continue;

        for (uint32_t i = 0; i < ready; ++i) {
            uint64_t entry_pos = pos + i;
            global_frame_cache_slot* slot =
                &cache->slots[entry_pos &
                              (GLOBAL_FRAME_CACHE_LIMIT - 1U)];
            entries[i] = slot->entry;
            atomic_store_explicit(
                &slot->sequence,
                entry_pos + GLOBAL_FRAME_CACHE_LIMIT,
                memory_order_release);
        }
        return ready;
    }
}

static uint32_t global_cache_enqueue_batch(
    uint8_t size_class, frame_slot* const* entries,
    uint32_t max_entries)
{
    assert(size_class < FRAME_SLOT_CLASS_COUNT);
    return global_cache_class_enqueue_batch(
        &g_frame_cache.classes[size_class], entries, max_entries);
}

static uint32_t global_cache_dequeue_batch(
    uint8_t size_class, frame_slot** entries,
    uint32_t max_entries)
{
    assert(size_class < FRAME_SLOT_CLASS_COUNT);
    return global_cache_class_dequeue_batch(
        &g_frame_cache.classes[size_class], entries, max_entries);
}

static inline uint32_t align_up_u32(uint32_t value, uint32_t align)
{
    return (value + align - 1U) & ~(align - 1U);
}

static inline int frame_size_class(uint32_t min_data_len)
{
    if (min_data_len == 0)
        min_data_len = FRAME_SLOT_DEFAULT_DATA_LEN;
    for (uint32_t i = 0; i < FRAME_SLOT_CLASS_COUNT; ++i) {
        if (min_data_len <= g_frame_slot_sizes[i])
            return (int)i;
    }
    return -1;
}

static inline int frame_slot_size_class(uint16_t slot_size)
{
    for (uint32_t i = 0; i < FRAME_SLOT_CLASS_COUNT; ++i) {
        if (slot_size == g_frame_slot_sizes[i])
            return (int)i;
    }
    return -1;
}

uint32_t frame_rx_headroom(void)
{
    return XDP_RX_FRAME_HEADROOM;
}

void frame_cache_init(frame_cache* cache)
{
    memset(cache, 0, sizeof(*cache));
}

void frame_cache_reset(frame_cache* cache)
{
    for (uint32_t cls = 0; cls < FRAME_SLOT_CLASS_COUNT; ++cls) {
        for (uint16_t i = 0; i < cache->count[cls]; ++i)
            PUT_REF(cache->entries[cls][i]->page);
    }
    memset(cache, 0, sizeof(*cache));
}

void frame_global_cache_reset(void)
{
    for (uint32_t cls = 0; cls < FRAME_SLOT_CLASS_COUNT; ++cls) {
        frame_slot* entries[THREAD_FRAME_CACHE_LOW];
        uint32_t count;
        do {
            count = global_cache_class_dequeue_batch(
                &g_frame_cache.classes[cls], entries,
                THREAD_FRAME_CACHE_LOW);
            for (uint32_t i = 0; i < count; ++i)
                PUT_REF(entries[i]->page);
        } while (count);
    }
}

static bool local_cache_push(frame_cache* cache, uint8_t size_class,
                             frame_slot* slot)
{
    uint16_t n = cache->count[size_class];
    if (n >= THREAD_FRAME_CACHE_LIMIT)
        return false;
    cache->entries[size_class][n] = slot;
    cache->count[size_class] = n + 1U;
    return true;
}

static void local_cache_spill(frame_cache* cache, uint8_t size_class)
{

    uint16_t count = cache->count[size_class];
    if (count <= THREAD_FRAME_CACHE_LOW)
        return;

    uint32_t spill_count = count - THREAD_FRAME_CACHE_LOW;
    frame_slot** entries =
        &cache->entries[size_class][THREAD_FRAME_CACHE_LOW];
    cache->count[size_class] = THREAD_FRAME_CACHE_LOW;

    uint32_t pushed = global_cache_enqueue_batch(size_class, entries,
                                                  spill_count);
    for (uint32_t i = pushed; i < spill_count; ++i)
        PUT_REF(entries[i]->page);
}


static void cache_free_slot(frame_slot* slot)
{
    int size_class = frame_slot_size_class(slot->slot_size);
    if (size_class < 0) {
        PUT_REF(slot->page);
        return;
    }
    frame_cache* cache = get_local_frame_cache();
    if (!local_cache_push(cache, (uint8_t)size_class, slot)) {
        local_cache_spill(cache, (uint8_t)size_class);
        bool cached = local_cache_push(cache, (uint8_t)size_class, slot);
        assert(cached);
        (void)cached;
    }
}

static frame_slot* cache_slot_acquire(frame_slot* slot)
{
    /* The local cache owns this slot exclusively.  Entries dequeued from the
     * shared cache also have a single consumer, so no compare/exchange is
     * needed on the allocation fast path. */
    assert(atomic_load_explicit(&slot->ref.ref_cnt,
                                memory_order_relaxed) == 0);
    atomic_store_explicit(&slot->ref.ref_cnt, 1, memory_order_relaxed);
    atomic_store_explicit(&slot->ref.useful, true, memory_order_release);
    return slot;
}

static frame_slot* local_cache_pop(frame_cache* cache, uint8_t size_class)
{
    assert(cache);
    assert(size_class < FRAME_SLOT_CLASS_COUNT);
    if (!cache->count[size_class])
        return NULL;
    uint16_t n = --cache->count[size_class];
    return cache_slot_acquire(cache->entries[size_class][n]);
}

static uint32_t local_cache_refill(frame_cache* cache, uint8_t size_class)
{
    assert(cache);
    assert(size_class < FRAME_SLOT_CLASS_COUNT);
    uint16_t count = cache->count[size_class];
    uint32_t room = THREAD_FRAME_CACHE_LIMIT - count;
    uint32_t want = min(THREAD_FRAME_CACHE_LOW, room);
    uint32_t added = global_cache_dequeue_batch(
        size_class, &cache->entries[size_class][count], want);
    cache->count[size_class] = count + (uint16_t)added;
    return added;
}

static void init_slot(frame_slot* slot, page_info* page, uint8_t* data,
                      uint16_t slot_size, bool allocated)
{
    atomic_init(&slot->ref.ref_cnt, allocated ? 1 : 0);
    atomic_init(&slot->ref.useful, allocated);
    slot->ref.free_info = destroy_frame_slot;
    slot->page = page;
    slot->data = data;
    slot->slot_size = slot_size;
}

static frame_slot* alloc_slot_page(uint8_t size_class, frame_cache* cache)
{
    page_info* page = NULL;
    if (xdp_frame_alloc((void**)&page) != 0)
        return NULL;

    uint32_t slot_offset = align_up_u32((uint32_t)sizeof(*page), 16U);
    uint32_t stride = align_up_u32((uint32_t)sizeof(frame_slot) +
                                   XDP_TX_METADATA_LEN +
                                   g_frame_slot_sizes[size_class], 16U);
    uint32_t count = (g_xdp_frame_pool.frame_size - slot_offset) / stride;

    INIT_REF(page, destroy_page_info);
    atomic_store_explicit(&page->ref.ref_cnt, (int)count,
                          memory_order_release);

    frame_slot* first = NULL;
    for (uint32_t i = 0; i < count; ++i) {
        frame_slot* slot = (frame_slot*)((uint8_t*)page + slot_offset +
                                        (size_t)i * stride);
        uint8_t* data = (uint8_t*)slot + sizeof(*slot) +
                        XDP_TX_METADATA_LEN;
        init_slot(slot, page, data, g_frame_slot_sizes[size_class], i == 0);
        if (i == 0) {
            first = slot;
            continue;
        }
        if (!local_cache_push(cache, size_class, slot)) {
            local_cache_spill(cache, size_class);
            bool cached = local_cache_push(cache, size_class, slot);
            assert(cached);
            (void)cached;
        }
    }
    return first;
}

static frame_slot* frame_slot_alloc_class(uint8_t size_class,
                                          frame_cache* cache)
{
    frame_slot* slot = local_cache_pop(cache, size_class);
    if (!slot && local_cache_refill(cache, size_class))
        slot = local_cache_pop(cache, size_class);
    if (!slot)
        slot = alloc_slot_page(size_class, cache);
    return slot;
}

frame_slot* frame_slot_alloc(uint32_t min_data_len)
{
    int size_class = frame_size_class(min_data_len);
    if (size_class < 0)
        return NULL;
    return frame_slot_alloc_class((uint8_t)size_class,
                                   get_local_frame_cache());
}

static void destroy_frame_slot(void* ptr)
{
    frame_slot* slot = ptr;
    atomic_store_explicit(&slot->ref.useful, false, memory_order_release);
    /* The live slot's page reference is transferred to the cache entry. */
    cache_free_slot(slot);

}

static void destroy_page_info(void* ptr)
{
    xdp_frame_free(ptr);
}

void free_data_info(data_info* info)
{
    if (!info)
        return;
    PUT_REF(info->slot);
    free(info);
}
data_info* alloc_data_info(uint32_t size)
{
    frame_slot* slot = frame_slot_alloc(size);
    if (!slot)
        return NULL;
    data_info* info = malloc(sizeof(*info));
    if (!info) {
        PUT_REF(slot);
        return NULL;
    }
    info->slot = slot;
    info->start = slot->data;
    info->end = slot->data;
    info->next = NULL;
    info->size = size ? size : slot->slot_size;
    return info;
}
data_info* create_data_info(frame_slot* slot, uint32_t start, uint32_t end)
{
    if (start > end)
        return NULL;
    bool allocated = slot == NULL;
    if (!slot) {
        slot = frame_slot_alloc(end);
    }
    if (!slot || end > slot->slot_size)
        goto fail;

    data_info* info = malloc(sizeof(*info));
    if (!info)
        goto fail;
    info->slot = slot;
    info->start = slot->data + start;
    info->end = slot->data + end;
    info->next = NULL;
    info->size = slot->slot_size;
    return info;

fail:
    if (allocated)
        PUT_REF(slot);
    return NULL;
}

void copy_data_info(data_info* dst, const data_info* src)
{
    *dst = *src;
    dst->next = NULL;
    INC_REF(dst->slot);
}
