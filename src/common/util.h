#ifndef PAYRELAY_UTIL_H
#define PAYRELAY_UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

/* Monotonic milliseconds, for timeouts and rate limiting. */
long long now_ms(void);

/* Local time as YYYYMMDDhhmmss (15 bytes incl. NUL) and YYMM (5 bytes). */
void now_datetime14(char out[15]);
void now_yymm(char out[5]);

/* Structured one-line log: "ts level component key=value ..." to stderr. */
void logf_(const char *level, const char *component, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
#define LOG_INFO(c, ...) logf_("INFO", c, __VA_ARGS__)
#define LOG_WARN(c, ...) logf_("WARN", c, __VA_ARGS__)
#define LOG_ERR(c, ...) logf_("ERROR", c, __VA_ARGS__)

/* Hex string -> bytes. Returns byte count, or -1 on bad input. */
int hex_decode(const char *hex, uint8_t *out, size_t cap);

const char *env_or(const char *name, const char *fallback);
int env_int(const char *name, int fallback);

/* write()/read() the whole buffer, retrying on EINTR and short transfers. */
int write_all(int fd, const void *buf, size_t len);

/*
 * Token bucket: `rate` tokens per second, at most `burst` saved up. Not thread safe;
 * callers hold their own lock.
 */
typedef struct {
    double tokens;
    double rate;
    double burst;
    long long last_ms;
} token_bucket;

void tb_init(token_bucket *tb, double rate, double burst, long long now);
int tb_take(token_bucket *tb, long long now);

#endif
