#ifndef LUKS_UNLOCK_LOG_H
#define LUKS_UNLOCK_LOG_H

void log_set_level(int level);   /* 0=debug 1=info 2=warn 3=error */

void log_debug(const char *fmt, ...);
void log_info(const char *fmt, ...);
void log_warn(const char *fmt, ...);
void log_err(const char *fmt, ...);

#endif
