#include "config.h"
#include "keyfile.h"
#include "log.h"
#include "net.h"
#include "proto.h"
#include "server.h"

#include <pthread.h>
#include <signal.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct {
    int fd;
    const server_config_t *cfg;
    const uint8_t *pk;
    const uint8_t *sk;
} thread_arg_t;

static void *thread_entry(void *p) {
    thread_arg_t *a = (thread_arg_t *)p;
    server_handle_connection(a->fd, a->cfg, a->pk, a->sk);
    free(a);
    return NULL;
}

static void usage(const char *p) {
    fprintf(stderr, "usage: %s [-c /path/to/server.conf]\n", p);
}

int main(int argc, char **argv) {
    const char *conf = "/etc/luks-unlock/server.conf";
    int opt;
    while ((opt = getopt(argc, argv, "c:h")) != -1) {
        switch (opt) {
            case 'c': conf = optarg; break;
            case 'h': usage(argv[0]); return 0;
            default:  usage(argv[0]); return 1;
        }
    }

    if (sodium_init() < 0) {
        log_err("libsodium init failed");
        return 1;
    }

    static server_config_t cfg;
    if (config_load_server(conf, &cfg) != 0) return 1;
    log_set_level(cfg.log_level);

    static uint8_t pk[PROTO_ID_PK_BYTES], sk[PROTO_ID_SK_BYTES];
    if (keyfile_load(cfg.identity_key, pk, sk) != 0) {
        log_err("failed to load server identity from %s", cfg.identity_key);
        return 1;
    }
    char pkhex[PROTO_ID_PK_BYTES * 2 + 1];
    hex_encode(pkhex, sizeof(pkhex), pk, PROTO_ID_PK_BYTES);
    log_info("server identity: %s", pkhex);

    int lfd = net_listen(cfg.listen_addr, cfg.listen_port);
    if (lfd < 0) return 1;
    log_info("listening on %s:%d", cfg.listen_addr, cfg.listen_port);

    signal(SIGPIPE, SIG_IGN);

    while (1) {
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) {
            log_warn("accept failed");
            continue;
        }
        thread_arg_t *a = calloc(1, sizeof(*a));
        if (!a) { close(cfd); continue; }
        a->fd = cfd;
        a->cfg = &cfg;
        a->pk = pk;
        a->sk = sk;

        pthread_t tid;
        if (pthread_create(&tid, NULL, thread_entry, a) != 0) {
            log_err("pthread_create failed");
            close(cfd);
            free(a);
            continue;
        }
        pthread_detach(tid);
    }
    return 0;
}
