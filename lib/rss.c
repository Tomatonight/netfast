#include "rss.h"

#include "worker.h"

/* 编译内置的默认 RSS Toeplitz key（40 B）。 */
const uint8_t TOEPLITZ_RSS_DEFAULT_KEY[TOEPLITZ_RSS_KEY_LEN] = {
    0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
    0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
    0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
    0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
    0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
};

const uint8_t* toeplitz_rss_get_key(uint32_t* out_len)
{
    if (out_len)
        *out_len = TOEPLITZ_RSS_KEY_LEN;
    return TOEPLITZ_RSS_DEFAULT_KEY;
}

uint32_t toeplitz_hash(const uint8_t* key, uint32_t key_len,
                       const uint8_t* data, uint32_t data_len)
{
    if (key_len < 4)
        return 0;

    uint32_t key_window = ((uint32_t)key[0] << 24) |
                          ((uint32_t)key[1] << 16) |
                          ((uint32_t)key[2] << 8) |
                          key[3];
    uint32_t key_position = 4;
    uint32_t hash = 0;

    for (uint32_t i = 0; i < data_len; ++i) {
        uint8_t data_byte = data[i];
        uint8_t key_byte = key_position < key_len ? key[key_position++] : 0;

        for (uint8_t mask = 0x80; mask != 0; mask >>= 1) {
            if (data_byte & mask)
                hash ^= key_window;
            key_window = (key_window << 1) | ((key_byte & mask) != 0);
        }
    }

    return hash;
}

worker* select_worker_by_tuple(sa_family_t family,
    const uint8_t* saddr, const uint8_t* daddr,
    uint16_t sport, uint16_t dport)
{
    if (!g_workers || g_worker_num <= 0)
        return NULL;

    uint8_t tuple[36];
    uint32_t tuple_len = family == AF_INET6 ? 36U : 12U;
    uint32_t addr_len = family == AF_INET6 ? 16U : 4U;
    memcpy(tuple, saddr, addr_len);
    memcpy(tuple + addr_len, daddr, addr_len);
    memcpy(tuple + 2U * addr_len, &sport, sizeof(sport));
    memcpy(tuple + 2U * addr_len + sizeof(sport), &dport, sizeof(dport));

    uint32_t key_len;
    const uint8_t* key = toeplitz_rss_get_key(&key_len);
    uint32_t hash = toeplitz_hash(key, key_len, tuple, tuple_len);
    return &g_workers[hash % (uint32_t)g_worker_num];
}
