#include "config.h"
#include "keyfile.h"
#include "log.h"
#include "net.h"
#include "proto.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void usage(const char *p) {
    fprintf(stderr,
            "usage: %s [-c CONF] [-1]\n"
            "  -c CONF   path to client.conf (default /etc/luks-unlock/client.conf)\n"
            "  -1        try once and exit on any failure (no retry loop)\n",
            p);
}

static int write_passphrase(const char *path, const uint8_t *buf, size_t len) {
    int fd;
    int opened = 0;
    if (strcmp(path, "-") == 0) {
        fd = STDOUT_FILENO;
    } else {
        fd = open(path, O_WRONLY | O_CREAT, 0600);
        if (fd < 0) {
            log_err("open %s: %s", path, strerror(errno));
            return -1;
        }
        opened = 1;
    }
    int rc = net_write_full(fd, buf, len);
    if (rc == 0) {
        const char nl = '\n';
        rc = net_write_full(fd, &nl, 1);
    }
    if (opened) close(fd);
    return rc;
}

int main(int argc, char **argv) {
    const char *conf = "/etc/luks-unlock/client.conf";
    int once = 0;
    int opt;
    while ((opt = getopt(argc, argv, "c:1h")) != -1) {
        switch (opt) {
            case 'c': conf = optarg; break;
            case '1': once = 1; break;
            case 'h': usage(argv[0]); return 0;
            default:  usage(argv[0]); return 1;
        }
    }

    if (sodium_init() < 0) {
        log_err("libsodium init failed");
        return 1;
    }

    client_config_t cfg;
    if (config_load_client(conf, &cfg) != 0) return 1;
    log_set_level(cfg.log_level);

    if (cfg.server_host[0] == '\0' || cfg.server_pubkey_hex[0] == '\0') {
        log_err("server_host and server_pubkey must be set in %s", conf);
        return 1;
    }
    uint8_t server_pk[PROTO_ID_PK_BYTES];
    if (hex_decode(server_pk, sizeof(server_pk), cfg.server_pubkey_hex) != 0) {
        log_err("invalid server_pubkey in %s (need %d hex chars)",
                conf, (int)PROTO_ID_PK_BYTES * 2);
        return 1;
    }

    uint8_t pk[PROTO_ID_PK_BYTES], sk[PROTO_ID_SK_BYTES];
    if (keyfile_load(cfg.identity_key, pk, sk) != 0) {
        log_err("failed to load client identity from %s", cfg.identity_key);
        return 1;
    }
    char pkhex[PROTO_ID_PK_BYTES * 2 + 1];
    hex_encode(pkhex, sizeof(pkhex), pk, PROTO_ID_PK_BYTES);
    log_info("client identity: %s", pkhex);

    signal(SIGPIPE, SIG_IGN);

    int retry = cfg.retry_seconds > 0 ? cfg.retry_seconds : 5;

    while (1) {
        int fd = net_connect(cfg.server_host, cfg.server_port);
        if (fd < 0) {
            if (once) return 2;
            sleep(retry);
            continue;
        }
        log_info("connected to %s:%d", cfg.server_host, cfg.server_port);

        proto_session_t s = { .fd = -1 };
        if (proto_handshake_client(fd, pk, sk, server_pk, &s) != 0) {
            close(fd);
            if (once) return 3;
            sleep(retry);
            continue;
        }

        uint8_t passphrase[PROTO_MAX_MSG];
        size_t plen = 0;
        int rc = proto_recv(&s, passphrase, sizeof(passphrase), &plen);
        proto_close(&s);
        if (rc != 0) {
            log_warn("did not receive key (rc=%d)", rc);
            sodium_memzero(passphrase, sizeof(passphrase));
            if (once) return 4;
            sleep(retry);
            continue;
        }

        log_info("received key (%zu bytes), writing to %s", plen, cfg.output_path);
        rc = write_passphrase(cfg.output_path, passphrase, plen);
        sodium_memzero(passphrase, sizeof(passphrase));
        if (rc != 0) {
            log_err("failed to write passphrase to %s", cfg.output_path);
            return 5;
        }
        return 0;
    }
}
