#include "config.h"
#include "log.h"
#include "ini.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>

static int level_from_str(const char *s) {
    if (!s) return 1;
    if (strcasecmp(s, "debug") == 0) return 0;
    if (strcasecmp(s, "info")  == 0) return 1;
    if (strcasecmp(s, "warn")  == 0) return 2;
    if (strcasecmp(s, "error") == 0) return 3;
    return 1;
}

static void copy(char *dst, size_t dstlen, const char *src) {
    if (!src) return;
    strncpy(dst, src, dstlen - 1);
    dst[dstlen - 1] = '\0';
}

#define MATCH(s, n) (strcmp(section, (s)) == 0 && strcmp(name, (n)) == 0)

static int server_handler(void *user, const char *section, const char *name, const char *value) {
    server_config_t *c = (server_config_t *)user;
    if      (MATCH("server", "listen"))        copy(c->listen_addr, sizeof(c->listen_addr), value);
    else if (MATCH("server", "port"))          c->listen_port = atoi(value);
    else if (MATCH("server", "identity_key")) copy(c->identity_key, sizeof(c->identity_key), value);
    else if (MATCH("server", "keystore"))     copy(c->keystore_dir, sizeof(c->keystore_dir), value);
    else if (MATCH("server", "log_level"))    c->log_level = level_from_str(value);
    else { log_warn("unknown config key: [%s] %s", section, name); }
    return 1;
}

static int client_handler(void *user, const char *section, const char *name, const char *value) {
    client_config_t *c = (client_config_t *)user;
    if      (MATCH("client", "server_host"))    copy(c->server_host, sizeof(c->server_host), value);
    else if (MATCH("client", "server_port"))    c->server_port = atoi(value);
    else if (MATCH("client", "server_pubkey")) copy(c->server_pubkey_hex, sizeof(c->server_pubkey_hex), value);
    else if (MATCH("client", "identity_key"))  copy(c->identity_key, sizeof(c->identity_key), value);
    else if (MATCH("client", "output"))        copy(c->output_path, sizeof(c->output_path), value);
    else if (MATCH("client", "retry_seconds")) c->retry_seconds = atoi(value);
    else if (MATCH("client", "log_level"))     c->log_level = level_from_str(value);
    else { log_warn("unknown config key: [%s] %s", section, name); }
    return 1;
}

int config_load_server(const char *path, server_config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    copy(cfg->listen_addr,  sizeof(cfg->listen_addr),  "0.0.0.0");
    cfg->listen_port = 8080;
    copy(cfg->identity_key, sizeof(cfg->identity_key), "/etc/luks-unlock/server.key");
    copy(cfg->keystore_dir, sizeof(cfg->keystore_dir), "/var/lib/luks-unlock/keys");
    cfg->log_level = 1;
    if (ini_parse(path, server_handler, cfg) < 0) {
        log_err("can't load %s", path);
        return -1;
    }
    return 0;
}

int config_load_client(const char *path, client_config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->server_port = 8080;
    copy(cfg->identity_key, sizeof(cfg->identity_key), "/etc/luks-unlock/client.key");
    copy(cfg->output_path,  sizeof(cfg->output_path),  "/lib/cryptsetup/passfifo");
    cfg->retry_seconds = 5;
    cfg->log_level = 1;
    if (ini_parse(path, client_handler, cfg) < 0) {
        log_err("can't load %s", path);
        return -1;
    }
    return 0;
}
