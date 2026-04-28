#include "log.h"

#include <stdarg.h>
#include <stdio.h>
#include <time.h>

static int s_level = 1;

void log_set_level(int level) { s_level = level; }

static void vlog(int lvl, const char *tag, const char *fmt, va_list ap) {
    if (lvl < s_level) return;
    char ts[32];
    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm);
    fprintf(stderr, "%s [%s] ", ts, tag);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
}

void log_debug(const char *fmt, ...) { va_list ap; va_start(ap, fmt); vlog(0, "DBG", fmt, ap); va_end(ap); }
void log_info (const char *fmt, ...) { va_list ap; va_start(ap, fmt); vlog(1, "INF", fmt, ap); va_end(ap); }
void log_warn (const char *fmt, ...) { va_list ap; va_start(ap, fmt); vlog(2, "WRN", fmt, ap); va_end(ap); }
void log_err  (const char *fmt, ...) { va_list ap; va_start(ap, fmt); vlog(3, "ERR", fmt, ap); va_end(ap); }
