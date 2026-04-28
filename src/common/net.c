#include "net.h"
#include "log.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int net_listen(const char *addr, int port) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        log_err("socket: %s", strerror(errno));
        return -1;
    }
    int yes = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    if (!addr || addr[0] == '\0' || strcmp(addr, "0.0.0.0") == 0) {
        sa.sin_addr.s_addr = htonl(INADDR_ANY);
    } else if (inet_pton(AF_INET, addr, &sa.sin_addr) != 1) {
        log_err("invalid listen address: %s", addr);
        close(s);
        return -1;
    }
    if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        log_err("bind %s:%d: %s", addr ? addr : "0.0.0.0", port, strerror(errno));
        close(s);
        return -1;
    }
    if (listen(s, 16) < 0) {
        log_err("listen: %s", strerror(errno));
        close(s);
        return -1;
    }
    return s;
}

int net_connect(const char *host, int port) {
    char portbuf[16];
    snprintf(portbuf, sizeof(portbuf), "%d", port);

    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    int rc = getaddrinfo(host, portbuf, &hints, &res);
    if (rc != 0) {
        log_err("getaddrinfo %s: %s", host, gai_strerror(rc));
        return -1;
    }

    int fd = -1;
    for (struct addrinfo *p = res; p; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) log_err("connect %s:%d failed: %s", host, port, strerror(errno));
    return fd;
}

int net_read_full(int fd, void *buf, size_t n) {
    unsigned char *p = (unsigned char *)buf;
    while (n > 0) {
        ssize_t r = read(fd, p, n);
        if (r == 0) return -2;
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += r;
        n -= (size_t)r;
    }
    return 0;
}

int net_write_full(int fd, const void *buf, size_t n) {
    const unsigned char *p = (const unsigned char *)buf;
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += (size_t)w;
        n -= (size_t)w;
    }
    return 0;
}
