#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "hash.h"

typedef struct benchmark_key {
    uint32_t words[3];
} benchmark_key;

typedef struct benchmark_item {
    benchmark_key key;
    uint64_t value;
    hash_node hash_node;
} benchmark_item;

static double elapsed_seconds(const struct timespec* start,
                              const struct timespec* end)
{
    return (double)(end->tv_sec - start->tv_sec) +
           (double)(end->tv_nsec - start->tv_nsec) / 1000000000.0;
}

static void mark_time(struct timespec* value)
{
    clock_gettime(CLOCK_MONOTONIC, value);
}

int main(int argc, char** argv)
{
    uint32_t count = argc > 1 ? (uint32_t)strtoul(argv[1], NULL, 10)
                              : 200000u;
    uint32_t lookups = argc > 2 ? (uint32_t)strtoul(argv[2], NULL, 10)
                                : 3000000u;
    uint32_t rounds = argc > 3 ? (uint32_t)strtoul(argv[3], NULL, 10) : 3u;
    if (!count || !lookups || !rounds)
        return 2;

    benchmark_item* items = calloc(count, sizeof(*items));
    if (!items)
        return 1;
    for (uint32_t i = 0; i < count; i++) {
        items[i].key.words[0] = i;
        items[i].key.words[1] = i * 2654435761u;
        items[i].key.words[2] = i ^ 0xa5a5a5a5u;
        items[i].value = (uint64_t)i + 1u;
    }

    double create_time = 0.0;
    double insert_time = 0.0;
    double lookup_time = 0.0;
    double delete_time = 0.0;
    double destroy_time = 0.0;
    uint64_t checksum = 0;

    for (uint32_t round = 0; round < rounds; round++) {
        struct timespec begin, end;
        mark_time(&begin);
        hash* table = hash_create_safe(262144u,
            HASH_KEY_OFFSET(benchmark_item, hash_node, key),
            sizeof(benchmark_key));
        mark_time(&end);
        if (!table)
            return 1;
        create_time += elapsed_seconds(&begin, &end);

        mark_time(&begin);
        for (uint32_t i = 0; i < count; i++) {
            if (!hash_add_node(table, &items[i].hash_node))
                return 1;
        }
        mark_time(&end);
        insert_time += elapsed_seconds(&begin, &end);

        uint32_t state = 0x12345678u ^ round;
        mark_time(&begin);
        for (uint32_t i = 0; i < lookups; i++) {
            state = state * 1664525u + 1013904223u;
            hash_node* node = hash_find_node(
                table, &items[state % count].key);
            benchmark_item* item = node
                ? HASH_CONTAINER_OF(node, benchmark_item, hash_node) : NULL;
            if (!item)
                return 1;
            checksum += item->value;
        }
        mark_time(&end);
        lookup_time += elapsed_seconds(&begin, &end);

        mark_time(&begin);
        for (uint32_t i = 0; i < count; i++)
            hash_del_node(table, &items[i].hash_node);
        mark_time(&end);
        delete_time += elapsed_seconds(&begin, &end);

        mark_time(&begin);
        hash_destroy(table);
        mark_time(&end);
        destroy_time += elapsed_seconds(&begin, &end);
    }

    uint64_t mutations = (uint64_t)count * rounds;
    uint64_t lookup_operations = (uint64_t)lookups * rounds;
    printf("hash benchmark: entries=%u lookups=%u rounds=%u checksum=%" PRIu64 "\n",
           count, lookups, rounds, checksum);
    printf("create: %.6f s total, %.2f tables/s\n", create_time,
           rounds / create_time);
    printf("insert: %.6f s total, %.2f Mops/s\n", insert_time,
           mutations / insert_time / 1000000.0);
    printf("lookup: %.6f s total, %.2f Mops/s\n", lookup_time,
           lookup_operations / lookup_time / 1000000.0);
    printf("delete: %.6f s total, %.2f Mops/s\n", delete_time,
           mutations / delete_time / 1000000.0);
    printf("destroy: %.6f s total, %.2f tables/s\n", destroy_time,
           rounds / destroy_time);
    free(items);
    return 0;
}
