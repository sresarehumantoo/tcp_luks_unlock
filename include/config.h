#ifndef LUKS_UNLOCK_CONFIG_H
#define LUKS_UNLOCK_CONFIG_H

typedef struct {
    char listen_addr[64];
    int  listen_port;
    char identity_key[256];
    char keystore_dir[256];
    int  log_level;
} server_config_t;

typedef struct {
    char server_host[128];
    int  server_port;
    char server_pubkey_hex[65];
    char identity_key[256];
    char output_path[256];   /* "-" means stdout */
    int  retry_seconds;
    int  log_level;
} client_config_t;

int config_load_server(const char *path, server_config_t *cfg);
int config_load_client(const char *path, client_config_t *cfg);

#endif
