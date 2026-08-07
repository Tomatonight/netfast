#ifndef LOOPBACK_H
#define LOOPBACK_H

#include "if.h"

extern const if_ops loopback_ops;

int loopback_send(if_info* info, skbuff* skb);
int loopback_create(if_info* info, struct nlmsghdr *nlh);
void loopback_update(if_info* info, struct nlmsghdr *nlh);

int loopback_init(void);

#endif
