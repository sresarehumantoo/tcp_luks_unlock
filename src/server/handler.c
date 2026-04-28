#include "server.h"
#include "keystore.h"
#include "keyfile.h"
#include "log.h"
#include "proto.h"

#include <sodium.h>
#include <string.h>
#include <unistd.h>

static int authz_cb(const uint8_t pk[PROTO_ID_PK_BYTES], void *ctx) {
    const char *dir = (const char *)ctx;
    return keystore_has(dir, pk);
}

void server_handle_connection(int fd,
                              const server_config_t *cfg,
                              const uint8_t pk[PROTO_ID_PK_BYTES],
                              const uint8_t sk[PROTO_ID_SK_BYTES]) {
    proto_session_t s = { .fd = -1 };
    if (proto_handshake_server(fd, pk, sk, authz_cb,
                               (void *)cfg->keystore_dir, &s) != 0) {
        close(fd);
        return;
    }

    char hex[PROTO_ID_PK_BYTES * 2 + 1];
    hex_encode(hex, sizeof(hex), s.peer_long_pk, PROTO_ID_PK_BYTES);
    log_info("authenticated client %s", hex);

    uint8_t passphrase[PROTO_MAX_MSG];
    size_t plen = 0;
    if (keystore_lookup(cfg->keystore_dir, s.peer_long_pk,
                        passphrase, sizeof(passphrase), &plen) != 0) {
        log_warn("no key for client %s", hex);
        proto_close(&s);
        return;
    }

    if (proto_send_final(&s, passphrase, plen) != 0) {
        log_warn("failed to send key to %s", hex);
    } else {
        log_info("delivered key to %s (%zu bytes)", hex, plen);
    }

    sodium_memzero(passphrase, sizeof(passphrase));
    proto_close(&s);
}
