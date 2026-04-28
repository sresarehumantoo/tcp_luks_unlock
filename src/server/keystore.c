#include "keystore.h"
#include "keyfile.h"
#include "log.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void path_for(char *out, size_t outlen, const char *dir,
                     const uint8_t pk[PROTO_ID_PK_BYTES]) {
    char hex[PROTO_ID_PK_BYTES * 2 + 1];
    hex_encode(hex, sizeof(hex), pk, PROTO_ID_PK_BYTES);
    snprintf(out, outlen, "%s/%s", dir, hex);
}

int keystore_has(const char *dir, const uint8_t client_pk[PROTO_ID_PK_BYTES]) {
    char path[512];
    path_for(path, sizeof(path), dir, client_pk);
    return access(path, R_OK) == 0;
}

int keystore_lookup(const char *dir,
                    const uint8_t client_pk[PROTO_ID_PK_BYTES],
                    uint8_t *out, size_t outlen, size_t *out_len) {
    char path[512];
    path_for(path, sizeof(path), dir, client_pk);

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        log_warn("open %s: %s", path, strerror(errno));
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) < 0) {
        log_err("fstat %s: %s", path, strerror(errno));
        close(fd);
        return -1;
    }
    if ((size_t)st.st_size > outlen) {
        log_err("keystore entry %s too large (%lld bytes)", path, (long long)st.st_size);
        close(fd);
        return -1;
    }
    ssize_t r = read(fd, out, (size_t)st.st_size);
    close(fd);
    if (r < 0) {
        log_err("read %s: %s", path, strerror(errno));
        return -1;
    }
    /* Trim a single trailing newline if present so `echo pass > keyfile` works. */
    while (r > 0 && (out[r - 1] == '\n' || out[r - 1] == '\r')) r--;
    *out_len = (size_t)r;
    return 0;
}
