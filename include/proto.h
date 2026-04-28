#ifndef LUKS_UNLOCK_PROTO_H
#define LUKS_UNLOCK_PROTO_H

#include <stddef.h>
#include <stdint.h>
#include <sodium.h>

#define PROTO_MAGIC      "LUK1"
#define PROTO_MAGIC_LEN  4
#define PROTO_ID_PK_BYTES crypto_sign_PUBLICKEYBYTES
#define PROTO_ID_SK_BYTES crypto_sign_SECRETKEYBYTES
#define PROTO_MAX_MSG    4096

/*
 * Wire format:
 *
 *   HELLO (132 bytes, both directions):
 *     magic[4] || long_pk[32] || eph_pk[32] || sig[64]
 *
 *   Client signs: magic || pinned_server_pk || client_long_pk || client_eph_pk
 *   Server signs: magic || server_long_pk   || client_long_pk
 *                       || client_eph_pk    || server_eph_pk
 *
 *   After mutual verification, server pushes a secretstream header (24 bytes)
 *   followed by length-prefixed encrypted frames (u16be length || ciphertext).
 *   Server-to-client direction only.
 */

typedef struct {
    int  fd;
    int  is_server;
    crypto_secretstream_xchacha20poly1305_state ss;
    uint8_t peer_long_pk[PROTO_ID_PK_BYTES];
} proto_session_t;

typedef int (*proto_authz_fn)(const uint8_t pk[PROTO_ID_PK_BYTES], void *ctx);

int proto_handshake_client(int fd,
                           const uint8_t my_pk[PROTO_ID_PK_BYTES],
                           const uint8_t my_sk[PROTO_ID_SK_BYTES],
                           const uint8_t expected_server_pk[PROTO_ID_PK_BYTES],
                           proto_session_t *out);

int proto_handshake_server(int fd,
                           const uint8_t my_pk[PROTO_ID_PK_BYTES],
                           const uint8_t my_sk[PROTO_ID_SK_BYTES],
                           proto_authz_fn is_authorized,
                           void *ctx,
                           proto_session_t *out);

int proto_send_final(proto_session_t *s, const void *buf, size_t len);
int proto_recv(proto_session_t *s, void *buf, size_t buflen, size_t *out_len);

void proto_close(proto_session_t *s);

#endif
