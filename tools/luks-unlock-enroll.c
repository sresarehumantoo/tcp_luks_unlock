#include "keyfile.h"
#include "proto.h"

#include <errno.h>
#include <fcntl.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr,
                "usage: %s KEYSTORE_DIR CLIENT_PUBKEY_HEX\n"
                "  reads passphrase from stdin, writes it to\n"
                "  KEYSTORE_DIR/<client_pubkey_hex> (mode 0600).\n", argv[0]);
        return 1;
    }
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium init failed\n");
        return 1;
    }

    uint8_t pk[PROTO_ID_PK_BYTES];
    if (hex_decode(pk, sizeof(pk), argv[2]) != 0) {
        fprintf(stderr, "invalid client pubkey hex (need %d hex chars)\n",
                (int)PROTO_ID_PK_BYTES * 2);
        return 1;
    }

    uint8_t buf[PROTO_MAX_MSG];
    size_t n = 0;
    while (n < sizeof(buf)) {
        ssize_t r = read(STDIN_FILENO, buf + n, sizeof(buf) - n);
        if (r == 0) break;
        if (r < 0) {
            if (errno == EINTR) continue;
            perror("read stdin");
            return 1;
        }
        n += (size_t)r;
    }
    if (n == sizeof(buf)) {
        fprintf(stderr, "passphrase too large (max %zu bytes)\n", sizeof(buf) - 1);
        sodium_memzero(buf, sizeof(buf));
        return 1;
    }
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) n--;
    if (n == 0) {
        fprintf(stderr, "empty passphrase on stdin\n");
        return 1;
    }

    /* Build path with normalized lowercase hex so server lookup matches. */
    char hex[PROTO_ID_PK_BYTES * 2 + 1];
    hex_encode(hex, sizeof(hex), pk, sizeof(pk));
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", argv[1], hex);

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        fprintf(stderr, "open %s: %s\n", path, strerror(errno));
        sodium_memzero(buf, sizeof(buf));
        return 1;
    }
    ssize_t w = write(fd, buf, n);
    sodium_memzero(buf, sizeof(buf));
    close(fd);
    if (w != (ssize_t)n) {
        fprintf(stderr, "short write to %s\n", path);
        return 1;
    }
    fprintf(stderr, "wrote %s (%zu bytes)\n", path, n);
    return 0;
}
