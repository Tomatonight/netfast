#include "base.h"
#include <arpa/inet.h>

__thread uint64_t current_time_ms
    __attribute__((tls_model("initial-exec")));

uint32_t checksum_partial(const void* buff, uint32_t len, uint32_t start_sum)
{
	const uint8_t* data = buff;
	uint32_t sum = start_sum;

	while (len > 1) {
		uint16_t word;
		memcpy(&word, data, sizeof(word));
		sum += word;
		data += 2;
		len -= 2;
	}
	if (len == 1) {
		uint16_t tail = 0;
		memcpy(&tail, data, 1);
		sum += tail;
	}
	return sum;
}

/* IPv4 pseudo header for TCP/UDP checksum calculation */
typedef struct __attribute__((packed)) pseudo_head {
	uint32_t saddr;
	uint32_t daddr;
	uint8_t  zero;
	uint8_t  proto;
	uint16_t len;
} pseudo_head;

uint16_t checksum(const void* buff, uint32_t len, uint32_t start_sum)
{
	uint32_t sum = checksum_partial(buff, len, start_sum);
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);
	return (uint16_t)~sum;
}

uint16_t checksum_protocol(const void* data, uint32_t len,
                           uint32_t saddr, uint32_t daddr, uint8_t protocol)
{
	pseudo_head head = {
		.saddr = saddr,
		.daddr = daddr,
		.zero  = 0,
		.proto = protocol,
		.len   = htons((uint16_t)len),
	};
	return checksum(data, len, checksum_partial(&head, sizeof(head), 0));
}

