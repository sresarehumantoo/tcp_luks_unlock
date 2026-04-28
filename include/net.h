#ifndef LUKS_UNLOCK_NET_H
#define LUKS_UNLOCK_NET_H

#include <stddef.h>

int net_listen(const char *addr, int port);    /* -1 on error */
int net_connect(const char *host, int port);   /* -1 on error */

int net_read_full(int fd, void *buf, size_t n);   /* 0 ok, -1 err, -2 EOF */
int net_write_full(int fd, const void *buf, size_t n); /* 0 ok, -1 err */

#endif
