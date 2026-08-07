#ifndef ETHER_H
#define ETHER_H

#include <stdbool.h>
#include <stdint.h>
#include "if.h"

extern const if_ops ether_ops;

typedef struct ether_hdr {
	uint8_t dmac[6];
	uint8_t smac[6];
	uint16_t ether_type;
} __attribute__((packed)) ether_hdr;

bool mac_same(const uint8_t* a, const uint8_t* b);
bool mac_boardcast(const uint8_t* mac);

#define ETHER_TYPE_IPV4   0x0800
#define ETHER_TYPE_ARP    0x0806
#define ETHER_TYPE_IPV6   0x86DD
#define ETHER_TYPE_8021Q  0x8100
#define ETHER_TYPE_8021AD 0x88A8

int ether_up(if_info* info);
int ether_down(if_info* info);
int ether_recv(if_info* info, skbuff* skb);
int ether_send(if_info* info, skbuff* skb);
int ether_create(if_info* new_info, struct nlmsghdr *nlh);
void ether_update(if_info* info, struct nlmsghdr *nlh);
void ether_destroy(if_info* info);
#endif
