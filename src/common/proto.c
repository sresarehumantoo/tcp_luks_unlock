#include "proto.h"
#include "net.h"
#include "log.h"

#include <string.h>
#include <unistd.h>

#define MAGIC_LEN     PROTO_MAGIC_LEN
#define EPH_PK_BYTES  crypto_kx_PUBLICKEYBYTES
#define EPH_SK_BYTES  crypto_kx_SECRETKEYBYTES
#define SIG_BYTES     crypto_sign_BYTES
#define HELLO_BYTES   (MAGIC_LEN + PROTO_ID_PK_BYTES + EPH_PK_BYTES + SIG_BYTES)
#define ABYTES        crypto_secretstream_xchacha20poly1305_ABYTES
#define HEADERBYTES   crypto_secretstream_xchacha20poly1305_HEADERBYTES

static int read_hello(int fd, uint8_t out[HELLO_BYTES]) {
    int rc = net_read_full(fd, out, HELLO_BYTES);
    if (rc != 0) {
        log_warn("handshake read failed");
        return -1;
    }
    if (memcmp(out, PROTO_MAGIC, MAGIC_LEN) != 0) {
        log_warn("handshake magic mismatch");
        return -1;
    }
    return 0;
}

int proto_handshake_client(int fd,
                           const uint8_t my_pk[PROTO_ID_PK_BYTES],
                           const uint8_t my_sk[PROTO_ID_SK_BYTES],
                           const uint8_t expected_server_pk[PROTO_ID_PK_BYTES],
                           proto_session_t *out) {
    uint8_t eph_pk[EPH_PK_BYTES], eph_sk[EPH_SK_BYTES];
    crypto_kx_keypair(eph_pk, eph_sk);

    uint8_t hello_c[HELLO_BYTES];
    memcpy(hello_c, PROTO_MAGIC, MAGIC_LEN);
    memcpy(hello_c + MAGIC_LEN, my_pk, PROTO_ID_PK_BYTES);
    memcpy(hello_c + MAGIC_LEN + PROTO_ID_PK_BYTES, eph_pk, EPH_PK_BYTES);

    uint8_t cli_sig_in[MAGIC_LEN + PROTO_ID_PK_BYTES + PROTO_ID_PK_BYTES + EPH_PK_BYTES];
    size_t off = 0;
    memcpy(cli_sig_in + off, PROTO_MAGIC, MAGIC_LEN);                off += MAGIC_LEN;
    memcpy(cli_sig_in + off, expected_server_pk, PROTO_ID_PK_BYTES); off += PROTO_ID_PK_BYTES;
    memcpy(cli_sig_in + off, my_pk, PROTO_ID_PK_BYTES);              off += PROTO_ID_PK_BYTES;
    memcpy(cli_sig_in + off, eph_pk, EPH_PK_BYTES);

    crypto_sign_detached(hello_c + MAGIC_LEN + PROTO_ID_PK_BYTES + EPH_PK_BYTES,
                         NULL, cli_sig_in, sizeof(cli_sig_in), my_sk);

    if (net_write_full(fd, hello_c, HELLO_BYTES) != 0) {
        log_warn("handshake send failed");
        return -1;
    }

    uint8_t hello_s[HELLO_BYTES];
    if (read_hello(fd, hello_s) != 0) return -1;

    const uint8_t *server_long_pk = hello_s + MAGIC_LEN;
    const uint8_t *server_eph_pk  = hello_s + MAGIC_LEN + PROTO_ID_PK_BYTES;
    const uint8_t *server_sig     = hello_s + MAGIC_LEN + PROTO_ID_PK_BYTES + EPH_PK_BYTES;

    if (memcmp(server_long_pk, expected_server_pk, PROTO_ID_PK_BYTES) != 0) {
        log_err("server identity does not match pinned key");
        return -1;
    }

    uint8_t srv_sig_in[MAGIC_LEN + PROTO_ID_PK_BYTES + PROTO_ID_PK_BYTES
                       + EPH_PK_BYTES + EPH_PK_BYTES];
    off = 0;
    memcpy(srv_sig_in + off, PROTO_MAGIC, MAGIC_LEN);                  off += MAGIC_LEN;
    memcpy(srv_sig_in + off, server_long_pk, PROTO_ID_PK_BYTES);       off += PROTO_ID_PK_BYTES;
    memcpy(srv_sig_in + off, my_pk, PROTO_ID_PK_BYTES);                off += PROTO_ID_PK_BYTES;
    memcpy(srv_sig_in + off, eph_pk, EPH_PK_BYTES);                    off += EPH_PK_BYTES;
    memcpy(srv_sig_in + off, server_eph_pk, EPH_PK_BYTES);

    if (crypto_sign_verify_detached(server_sig, srv_sig_in, sizeof(srv_sig_in),
                                    server_long_pk) != 0) {
        log_err("server signature invalid");
        return -1;
    }

    uint8_t rx_key[crypto_kx_SESSIONKEYBYTES], tx_key[crypto_kx_SESSIONKEYBYTES];
    if (crypto_kx_client_session_keys(rx_key, tx_key, eph_pk, eph_sk, server_eph_pk) != 0) {
        log_err("kx failed");
        return -1;
    }

    uint8_t header[HEADERBYTES];
    if (net_read_full(fd, header, sizeof(header)) != 0) {
        log_warn("secretstream header read failed");
        return -1;
    }
    if (crypto_secretstream_xchacha20poly1305_init_pull(&out->ss, header, rx_key) != 0) {
        log_err("secretstream init pull failed");
        return -1;
    }

    sodium_memzero(eph_sk, sizeof(eph_sk));
    sodium_memzero(rx_key, sizeof(rx_key));
    sodium_memzero(tx_key, sizeof(tx_key));

    out->fd = fd;
    out->is_server = 0;
    memcpy(out->peer_long_pk, server_long_pk, PROTO_ID_PK_BYTES);
    return 0;
}

int proto_handshake_server(int fd,
                           const uint8_t my_pk[PROTO_ID_PK_BYTES],
                           const uint8_t my_sk[PROTO_ID_SK_BYTES],
                           proto_authz_fn is_authorized,
                           void *ctx,
                           proto_session_t *out) {
    uint8_t hello_c[HELLO_BYTES];
    if (read_hello(fd, hello_c) != 0) return -1;

    const uint8_t *client_long_pk = hello_c + MAGIC_LEN;
    const uint8_t *client_eph_pk  = hello_c + MAGIC_LEN + PROTO_ID_PK_BYTES;
    const uint8_t *client_sig     = hello_c + MAGIC_LEN + PROTO_ID_PK_BYTES + EPH_PK_BYTES;

    if (!is_authorized(client_long_pk, ctx)) {
        log_warn("rejecting unauthorized client");
        return -1;
    }

    uint8_t cli_sig_in[MAGIC_LEN + PROTO_ID_PK_BYTES + PROTO_ID_PK_BYTES + EPH_PK_BYTES];
    size_t off = 0;
    memcpy(cli_sig_in + off, PROTO_MAGIC, MAGIC_LEN);            off += MAGIC_LEN;
    memcpy(cli_sig_in + off, my_pk, PROTO_ID_PK_BYTES);          off += PROTO_ID_PK_BYTES;
    memcpy(cli_sig_in + off, client_long_pk, PROTO_ID_PK_BYTES); off += PROTO_ID_PK_BYTES;
    memcpy(cli_sig_in + off, client_eph_pk, EPH_PK_BYTES);

    if (crypto_sign_verify_detached(client_sig, cli_sig_in, sizeof(cli_sig_in),
                                    client_long_pk) != 0) {
        log_warn("client signature invalid");
        return -1;
    }

    uint8_t eph_pk[EPH_PK_BYTES], eph_sk[EPH_SK_BYTES];
    crypto_kx_keypair(eph_pk, eph_sk);

    uint8_t hello_s[HELLO_BYTES];
    memcpy(hello_s, PROTO_MAGIC, MAGIC_LEN);
    memcpy(hello_s + MAGIC_LEN, my_pk, PROTO_ID_PK_BYTES);
    memcpy(hello_s + MAGIC_LEN + PROTO_ID_PK_BYTES, eph_pk, EPH_PK_BYTES);

    uint8_t srv_sig_in[MAGIC_LEN + PROTO_ID_PK_BYTES + PROTO_ID_PK_BYTES
                       + EPH_PK_BYTES + EPH_PK_BYTES];
    off = 0;
    memcpy(srv_sig_in + off, PROTO_MAGIC, MAGIC_LEN);            off += MAGIC_LEN;
    memcpy(srv_sig_in + off, my_pk, PROTO_ID_PK_BYTES);          off += PROTO_ID_PK_BYTES;
    memcpy(srv_sig_in + off, client_long_pk, PROTO_ID_PK_BYTES); off += PROTO_ID_PK_BYTES;
    memcpy(srv_sig_in + off, client_eph_pk, EPH_PK_BYTES);       off += EPH_PK_BYTES;
    memcpy(srv_sig_in + off, eph_pk, EPH_PK_BYTES);

    crypto_sign_detached(hello_s + MAGIC_LEN + PROTO_ID_PK_BYTES + EPH_PK_BYTES,
                         NULL, srv_sig_in, sizeof(srv_sig_in), my_sk);

    if (net_write_full(fd, hello_s, HELLO_BYTES) != 0) {
        log_warn("handshake send failed");
        return -1;
    }

    uint8_t rx_key[crypto_kx_SESSIONKEYBYTES], tx_key[crypto_kx_SESSIONKEYBYTES];
    if (crypto_kx_server_session_keys(rx_key, tx_key, eph_pk, eph_sk, client_eph_pk) != 0) {
        log_err("kx failed");
        return -1;
    }

    uint8_t header[HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_init_push(&out->ss, header, tx_key);

    if (net_write_full(fd, header, sizeof(header)) != 0) {
        log_warn("secretstream header send failed");
        return -1;
    }

    sodium_memzero(eph_sk, sizeof(eph_sk));
    sodium_memzero(rx_key, sizeof(rx_key));
    sodium_memzero(tx_key, sizeof(tx_key));

    out->fd = fd;
    out->is_server = 1;
    memcpy(out->peer_long_pk, client_long_pk, PROTO_ID_PK_BYTES);
    return 0;
}

int proto_send_final(proto_session_t *s, const void *buf, size_t len) {
    if (!s->is_server) return -1;
    if (len > PROTO_MAX_MSG) return -1;

    uint8_t ct[PROTO_MAX_MSG + ABYTES];
    unsigned long long ct_len = 0;
    crypto_secretstream_xchacha20poly1305_push(
        &s->ss, ct, &ct_len,
        (const unsigned char *)buf, len, NULL, 0,
        crypto_secretstream_xchacha20poly1305_TAG_FINAL);

    uint8_t lenbuf[2];
    lenbuf[0] = (uint8_t)(ct_len >> 8);
    lenbuf[1] = (uint8_t)(ct_len & 0xff);
    if (net_write_full(s->fd, lenbuf, 2) != 0) return -1;
    if (net_write_full(s->fd, ct, (size_t)ct_len) != 0) return -1;
    return 0;
}

int proto_recv(proto_session_t *s, void *buf, size_t buflen, size_t *out_len) {
    if (s->is_server) return -1;

    uint8_t lenbuf[2];
    int rc = net_read_full(s->fd, lenbuf, 2);
    if (rc != 0) return rc;
    size_t ct_len = ((size_t)lenbuf[0] << 8) | lenbuf[1];
    if (ct_len < ABYTES || ct_len > PROTO_MAX_MSG + ABYTES) {
        log_warn("framed length out of range: %zu", ct_len);
        return -1;
    }
    size_t pt_max = ct_len - ABYTES;
    if (pt_max > buflen) {
        log_warn("decrypted message would overflow caller buffer (%zu > %zu)",
                 pt_max, buflen);
        return -1;
    }

    uint8_t ct[PROTO_MAX_MSG + ABYTES];
    if (net_read_full(s->fd, ct, ct_len) != 0) return -1;

    unsigned long long pt_len = 0;
    unsigned char tag = 0;
    if (crypto_secretstream_xchacha20poly1305_pull(
            &s->ss, (unsigned char *)buf, &pt_len, &tag,
            ct, ct_len, NULL, 0) != 0) {
        log_warn("secretstream pull failed (auth/decrypt)");
        return -1;
    }
    *out_len = (size_t)pt_len;
    (void)tag;
    return 0;
}

void proto_close(proto_session_t *s) {
    if (s->fd >= 0) close(s->fd);
    s->fd = -1;
    sodium_memzero(&s->ss, sizeof(s->ss));
}
