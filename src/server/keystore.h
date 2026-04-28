#ifndef LUKS_UNLOCK_KEYSTORE_H
#define LUKS_UNLOCK_KEYSTORE_H

#include <stddef.h>
#include <stdint.h>
#include "proto.h"

int keystore_has(const char *dir, const uint8_t client_pk[PROTO_ID_PK_BYTES]);

int keystore_lookup(const char *dir,
                    const uint8_t client_pk[PROTO_ID_PK_BYTES],
                    uint8_t *out, size_t outlen, size_t *out_len);

#endif
