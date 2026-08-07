#ifndef NETLINK_H
#define NETLINK_H

#include <stdint.h>

typedef struct worker worker;
struct task;

int netlink_init(worker* w);
void netlink_recv_cb(struct task* tk);
int netlink_get_xsk_features(uint32_t ifindex, uint64_t* features);

#endif
