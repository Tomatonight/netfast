#ifndef REQ_SOCKET_H
#define REQ_SOCKET_H

#include "fd_entry.h"

int socket_req(int family, int type, int protocol);

extern const fd_entry_ops socket_fd_ops;

#endif /* REQ_SOCKET_H */
