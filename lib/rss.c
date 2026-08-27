#include "rss.h"

#include "worker.h"

/* 16-bit 周期使地址和端口的源/目的块交换后仍得到相同 Toeplitz hash。
 * 软件 worker 选择和网卡硬件 RSS 必须使用同一组字节。 */
const uint8_t TOEPLITZ_RSS_DEFAULT_KEY[TOEPLITZ_RSS_KEY_LEN] = {
    0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
    0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
    0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
    0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
    0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
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

worker* rss_select_worker_by_tuple(sa_family_t family,
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
