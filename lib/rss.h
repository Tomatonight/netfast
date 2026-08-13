#ifndef RSS_H
#define RSS_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>

#define TOEPLITZ_RSS_KEY_LEN 40


extern const uint8_t TOEPLITZ_RSS_DEFAULT_KEY[TOEPLITZ_RSS_KEY_LEN];

const uint8_t* toeplitz_rss_get_key(uint32_t* out_len);

uint32_t toeplitz_hash(const uint8_t* key, uint32_t key_len,
                       const uint8_t* data, uint32_t data_len);

typedef struct worker worker;

extern worker* g_workers;
extern int g_worker_num;

worker* select_worker_by_tuple(sa_family_t family,
    const uint8_t* saddr, const uint8_t* daddr,
    uint16_t sport, uint16_t dport);

#endif /* RSS_H */
