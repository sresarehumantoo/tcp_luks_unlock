#include "keyfile.h"
#include "log.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int keyfile_generate(uint8_t pk[crypto_sign_PUBLICKEYBYTES],
                     uint8_t sk[crypto_sign_SECRETKEYBYTES]) {
    crypto_sign_keypair(pk, sk);
    return 0;
}

int keyfile_save(const char *path,
                 const uint8_t sk[crypto_sign_SECRETKEYBYTES]) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        log_err("open %s: %s", path, strerror(errno));
        return -1;
    }
    ssize_t w = write(fd, sk, crypto_sign_SECRETKEYBYTES);
    int rc = (w == (ssize_t)crypto_sign_SECRETKEYBYTES) ? 0 : -1;
    if (rc != 0) log_err("short write to %s", path);
    close(fd);
    return rc;
}

int keyfile_load(const char *path,
                 uint8_t pk[crypto_sign_PUBLICKEYBYTES],
                 uint8_t sk[crypto_sign_SECRETKEYBYTES]) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        log_err("open %s: %s", path, strerror(errno));
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) < 0) {
        log_err("fstat %s: %s", path, strerror(errno));
        close(fd);
        return -1;
    }
    if ((st.st_mode & 077) != 0) {
        log_warn("identity file %s is group/world accessible (mode %o)",
                 path, (unsigned)(st.st_mode & 0777));
    }
    if (st.st_size != (off_t)crypto_sign_SECRETKEYBYTES) {
        log_err("identity file %s wrong size (%lld, expected %d)",
                path, (long long)st.st_size, (int)crypto_sign_SECRETKEYBYTES);
        close(fd);
        return -1;
    }
    ssize_t r = read(fd, sk, crypto_sign_SECRETKEYBYTES);
    close(fd);
    if (r != (ssize_t)crypto_sign_SECRETKEYBYTES) {
        log_err("short read from %s", path);
        return -1;
    }
    crypto_sign_ed25519_sk_to_pk(pk, sk);
    return 0;
}

static const char hex_chars[] = "0123456789abcdef";

void hex_encode(char *out, size_t outlen, const uint8_t *in, size_t inlen) {
    if (outlen < inlen * 2 + 1) {
        if (outlen) out[0] = '\0';
        return;
    }
    for (size_t i = 0; i < inlen; i++) {
        out[i * 2]     = hex_chars[in[i] >> 4];
        out[i * 2 + 1] = hex_chars[in[i] & 0xf];
    }
    out[inlen * 2] = '\0';
}

static int nyb(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int hex_decode(uint8_t *out, size_t outlen, const char *in) {
    if (!in) return -1;
    if (strlen(in) != outlen * 2) return -1;
    for (size_t i = 0; i < outlen; i++) {
        int hi = nyb(in[i * 2]);
        int lo = nyb(in[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}
