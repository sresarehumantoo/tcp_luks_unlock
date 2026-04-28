#ifndef LUKS_UNLOCK_SERVER_H
#define LUKS_UNLOCK_SERVER_H

#include "config.h"
#include "proto.h"

void server_handle_connection(int fd,
                              const server_config_t *cfg,
                              const uint8_t pk[PROTO_ID_PK_BYTES],
                              const uint8_t sk[PROTO_ID_SK_BYTES]);

#endif
