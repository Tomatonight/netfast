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
    return (&current->master->frame_cache);
}


typedef struct global_frame_cache_slot {
    _Atomic uint64_t sequence;
    frame_cache_entry entry;
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
    global_frame_cache_class* cache, const frame_cache_entry* entries,
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
    global_frame_cache_class* cache, frame_cache_entry* entries,
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
    uint8_t size_class, const frame_cache_entry* entries,
    uint32_t max_entries)
{
    assert(size_class < FRAME_SLOT_CLASS_COUNT);
    return global_cache_class_enqueue_batch(
        &g_frame_cache.classes[size_class], entries, max_entries);
}

static uint32_t global_cache_dequeue_batch(
    uint8_t size_class, frame_cache_entry* entries,
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

static inline bool page_in_umem(const page_info* page)
{

    uintptr_t base = (uintptr_t)g_xdp_frame_pool.buffer;
    uintptr_t addr = (uintptr_t)page;
    uintptr_t bytes = (uintptr_t)g_xdp_frame_pool.frame_size *
                      g_xdp_frame_pool.num_frames;
    return addr >= base && addr < base + bytes &&
           ((addr - base) % g_xdp_frame_pool.frame_size) == 0;
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
            PUT_REF(cache->entries[cls][i].page);
    }
    memset(cache, 0, sizeof(*cache));
}

void frame_global_cache_reset(void)
{
    for (uint32_t cls = 0; cls < FRAME_SLOT_CLASS_COUNT; ++cls) {
        frame_cache_entry entries[THREAD_FRAME_CACHE_LOW];
        uint32_t count;
        do {
            count = global_cache_class_dequeue_batch(
                &g_frame_cache.classes[cls], entries,
                THREAD_FRAME_CACHE_LOW);
            for (uint32_t i = 0; i < count; ++i)
                PUT_REF(entries[i].page);
        } while (count);
    }
}

static inline frame_slot* page_slot_at(page_info* page, uint16_t index)
{
    assert(page);
    assert(index < page->slot_count);
    return (frame_slot*)((uint8_t*)page + page->first_slot_offset +
                         (size_t)index * page->slot_stride);
}

static inline frame_cache_entry cache_entry_from_slot(const frame_slot* slot)
{
    return (frame_cache_entry){
        .page = slot->page,
        .generation = slot->generation,
        .slot_index = slot->index,
    };
}

static bool local_cache_push(frame_cache* cache, uint8_t size_class,
                             frame_slot* slot)
{
    uint16_t n = cache->count[size_class];
    if (n >= THREAD_FRAME_CACHE_LIMIT)
        return false;
    cache->entries[size_class][n] = cache_entry_from_slot(slot);
    cache->count[size_class] = n + 1U;
    return true;
}

static void local_cache_spill(frame_cache* cache, uint8_t size_class)
{

    uint16_t count = cache->count[size_class];
    if (count <= THREAD_FRAME_CACHE_LOW)
        return;

    uint32_t spill_count = count - THREAD_FRAME_CACHE_LOW;
    frame_cache_entry* entries =
        &cache->entries[size_class][THREAD_FRAME_CACHE_LOW];
    cache->count[size_class] = THREAD_FRAME_CACHE_LOW;

    uint32_t pushed = global_cache_enqueue_batch(size_class, entries,
                                                  spill_count);
    for (uint32_t i = pushed; i < spill_count; ++i)
        PUT_REF(entries[i].page);
}


static void cache_free_slot(frame_slot* slot)
{
    int size_class = frame_slot_size_class(slot->slot_size);
    if (size_class < 0) {
        PUT_REF(slot->page);
        return;
    }
    frame_cache* cache = get_local_frame_cache();
    if (!cache) {
        PUT_REF(slot->page);
        return;
    }
    if (!local_cache_push(cache, (uint8_t)size_class, slot)) {
        local_cache_spill(cache, (uint8_t)size_class);
        bool cached = local_cache_push(cache, (uint8_t)size_class, slot);
        assert(cached);
        (void)cached;
    }
}

static frame_slot* cache_entry_acquire(frame_cache_entry entry)
{
    page_info* page = entry.page;
    if (!page_in_umem(page) ||
        atomic_load_explicit(&page->generation, memory_order_acquire) !=
            entry.generation)
        return NULL;

    assert(entry.slot_index < page->slot_count);

    frame_slot* slot = page_slot_at(page, entry.slot_index);
    assert(slot->page == page);
    assert(slot->generation == entry.generation);
    assert(slot->slot_size == page->slot_size);

    int expected = 0;
    if (!atomic_compare_exchange_strong_explicit(
            &slot->ref.ref_cnt, &expected, 1,
            memory_order_acq_rel, memory_order_acquire)) {
        PUT_REF(page);
        return NULL;
    }
    atomic_store_explicit(&slot->ref.useful, true, memory_order_release);
    atomic_fetch_add_explicit(&page->used_number, 1U, memory_order_relaxed);
    return slot;
}

static frame_slot* local_cache_pop(frame_cache* cache, uint8_t size_class)
{
    assert(cache);
    assert(size_class < FRAME_SLOT_CLASS_COUNT);
    while (cache->count[size_class]) {
        uint16_t n = --cache->count[size_class];
        frame_cache_entry entry = cache->entries[size_class][n];
        frame_slot* slot = cache_entry_acquire(entry);
        if (slot)
            return slot;
    }
    return NULL;
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

static void init_slot(frame_slot* slot, page_info* page, uint16_t index,
                      uint32_t generation, uint8_t* data, bool allocated)
{
    atomic_init(&slot->ref.ref_cnt, allocated ? 1 : 0);
    atomic_init(&slot->ref.useful, allocated);
    slot->ref.free_info = destroy_frame_slot;
    slot->page = page;
    slot->next_free = NULL;
    slot->data = data;
    slot->generation = generation;
    slot->slot_size = page->slot_size;
    slot->index = index;
}

static frame_slot* alloc_slot_page(uint8_t size_class, frame_cache* local_cache)
{
    page_info* page = NULL;
    if (xdp_frame_alloc((void**)&page) != 0)
        return NULL;

    uint32_t generation = atomic_fetch_add_explicit(
        &page->generation, 1U, memory_order_acq_rel) + 1U;
    uint32_t slot_offset = align_up_u32((uint32_t)sizeof(*page), 16U);
    uint32_t stride = align_up_u32((uint32_t)sizeof(frame_slot) +
                                   XDP_TX_METADATA_LEN +
                                   g_frame_slot_sizes[size_class], 16U);
    uint32_t count = (g_xdp_frame_pool.frame_size - slot_offset) / stride;

    INIT_REF(page, destroy_page_info);
    atomic_store_explicit(&page->ref.ref_cnt, (int)count,
                          memory_order_release);
    page->free_slot_list = NULL;
    atomic_init(&page->used_number, 1U);
    page->slot_stride = stride;
    page->slot_size = g_frame_slot_sizes[size_class];
    page->slot_count = (uint16_t)count;
    page->first_slot_offset = (uint16_t)slot_offset;

    frame_slot* first = NULL;
    for (uint16_t i = 0; i < page->slot_count; ++i) {
        frame_slot* slot = page_slot_at(page, i);
        uint8_t* data = (uint8_t*)slot + sizeof(*slot) +
                        XDP_TX_METADATA_LEN;
        init_slot(slot, page, i, generation, data, i == 0);
        if (i == 0) {
            first = slot;
        } else {
            slot->next_free = page->free_slot_list;
            page->free_slot_list = slot;
        }
    }

    while (page->free_slot_list) {
        frame_slot* slot = page->free_slot_list;
        page->free_slot_list = slot->next_free;
        slot->next_free = NULL;
        if (!local_cache) {
            PUT_REF(page);
            continue;
        }
        if (!local_cache_push(local_cache, size_class, slot)) {
            local_cache_spill(local_cache, size_class);
            local_cache_push(local_cache, size_class, slot);
        }
        continue;
    }
    return first;
}

static frame_slot* frame_slot_alloc_class(uint8_t size_class,
                                          frame_cache* local_cache)
{
    frame_slot* slot = NULL;
    if (local_cache) {
        slot = local_cache_pop(local_cache, size_class);
        if (!slot && local_cache_refill(local_cache, size_class))
            slot = local_cache_pop(local_cache, size_class);
    }
    if (!slot)
        slot = alloc_slot_page(size_class, local_cache);
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

uint32_t frame_slot_alloc_batch(frame_slot** out, uint32_t max,
                                uint32_t min_data_len)
{
    if (!out)
        return 0;
    int size_class = frame_size_class(min_data_len);
    if (size_class < 0)
        return 0;
    frame_cache* local_cache = get_local_frame_cache();

    uint32_t got = 0;
    while (got < max) {
        if (local_cache) {
            frame_slot* slot = local_cache_pop(local_cache,
                                                (uint8_t)size_class);
            if (slot) {
                out[got++] = slot;
                continue;
            }
            if (local_cache_refill(local_cache, (uint8_t)size_class))
                continue;
        }

        frame_slot* slot = alloc_slot_page((uint8_t)size_class, local_cache);
        if (!slot)
            break;
        out[got++] = slot;
    }
    return got;
}

frame_slot* frame_slot_init_rx(void* frame, uint8_t* data, uint32_t data_len)
{
    if (!frame || !data)
        return NULL;
    page_info* page = frame;
    uint32_t generation = atomic_fetch_add_explicit(
        &page->generation, 1U, memory_order_acq_rel) + 1U;
    uint32_t slot_offset = align_up_u32((uint32_t)sizeof(*page), 16U);
    frame_slot* slot = (frame_slot*)((uint8_t*)page + slot_offset);

    INIT_REF(page, destroy_page_info);
    page->free_slot_list = NULL;
    atomic_init(&page->used_number, 1U);
    page->slot_stride = 0;
    page->slot_size = data_len > UINT16_MAX ? UINT16_MAX : (uint16_t)data_len;
    page->slot_count = 1;
    page->first_slot_offset = (uint16_t)slot_offset;
    init_slot(slot, page, 0, generation, data, true);
    return slot;
}

frame_slot* frame_slot_from_addr(void* frame, const uint8_t* addr)
{
    page_info* page = frame;
    if (!page || !addr || !page->slot_count)
        return NULL;

    uintptr_t first = (uintptr_t)page + page->first_slot_offset;
    uintptr_t target = (uintptr_t)addr;
    if (target < first)
        return NULL;

    uint16_t index = 0;
    if (page->slot_count > 1) {
        uint64_t relative = target - first;
        uint64_t candidate = relative / page->slot_stride;
        if (candidate >= page->slot_count)
            return NULL;
        index = (uint16_t)candidate;
    }

    uint32_t generation = atomic_load_explicit(&page->generation,
                                                memory_order_acquire);
    frame_slot* slot = page_slot_at(page, index);
    return slot->page == page && slot->generation == generation &&
           addr >= slot->data && addr < slot->data + slot->slot_size
               ? slot : NULL;
}

static void destroy_frame_slot(void* ptr)
{
    frame_slot* slot = ptr;
    page_info* page = slot->page;
    atomic_store_explicit(&slot->ref.useful, false, memory_order_release);
    atomic_fetch_sub_explicit(&page->used_number, 1U, memory_order_relaxed);
    /* The live slot's page reference is transferred to the cache entry. */
    cache_free_slot(slot);

}

static void destroy_page_info(void* ptr)
{
    page_info* page = ptr;
    atomic_fetch_add_explicit(&page->generation, 1U, memory_order_acq_rel);
    xdp_frame_free(page);
}

page_info* create_page_info(void)
{
    page_info* page = NULL;
    if (xdp_frame_alloc((void**)&page) != 0)
        return NULL;
    (void)atomic_fetch_add_explicit(&page->generation, 1U,
                                    memory_order_acq_rel);
    INIT_REF(page, destroy_page_info);
    page->free_slot_list = NULL;
    atomic_init(&page->used_number, 0U);
    page->slot_stride = 0;
    page->slot_size = 0;
    page->slot_count = 0;
    page->first_slot_offset = 0;
    return page;
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
