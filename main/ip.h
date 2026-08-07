#ifndef IP_H
#define IP_H

#include <stdint.h>

typedef struct skbuff skbuff;

#define MAX_IP_HDR_WITH_OPT_LEN 60

#define IPV4_VHL_VERSION(vhl)   ((uint8_t)(((vhl) >> 4) & 0x0F))
#define IPV4_VHL_IHL(vhl)       ((uint8_t)((vhl) & 0x0F))
#define IPV4_MAKE_VHL(ver, ihl) ((uint8_t)((((ver) & 0x0F) << 4) | ((ihl) & 0x0F)))

#define IPV4_FRAG_OFF_MASK 0x1FFFu
#define IPV4_FRAG_DF       0x4000u
#define IPV4_FRAG_MF       0x2000u

typedef struct ipv4_hdr {
    uint8_t vhl;

    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;

    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
    uint32_t options[0];
} __attribute__((packed)) ipv4_hdr;
const char* ip_to_str(uint32_t ip);
int ipv4_init(void);
int ipv4_recv(skbuff* skb);
int ipv4_output(skbuff* skb);
int ipv4_forward(skbuff* skb);

#endif
