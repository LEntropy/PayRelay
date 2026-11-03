#include "util.h"

#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

void now_datetime14(char out[15]) {
    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(out, 15, "%Y%m%d%H%M%S", &tm);
}

void now_yymm(char out[5]) {
    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(out, 5, "%y%m", &tm);
}

static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;

void logf_(const char *level, const char *component, const char *fmt, ...) {
    char ts[32];
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    struct tm tm;
    localtime_r(&now.tv_sec, &tm);
    size_t n = strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", &tm);
    snprintf(ts + n, sizeof(ts) - n, ".%03ld", now.tv_nsec / 1000000);

    char msg[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    pthread_mutex_lock(&log_lock);
    fprintf(stderr, "%s %-5s %-8s %s\n", ts, level, component, msg);
    pthread_mutex_unlock(&log_lock);
}

int hex_decode(const char *hex, uint8_t *out, size_t cap) {
    size_t n = strlen(hex);
    if (n % 2 != 0 || n / 2 > cap) return -1;
    for (size_t i = 0; i < n / 2; i++) {
        int hi = isdigit((unsigned char)hex[2 * i]) ? hex[2 * i] - '0' : (tolower((unsigned char)hex[2 * i]) - 'a' + 10);
        int lo = isdigit((unsigned char)hex[2 * i + 1]) ? hex[2 * i + 1] - '0' : (tolower((unsigned char)hex[2 * i + 1]) - 'a' + 10);
        if (hi < 0 || hi > 15 || lo < 0 || lo > 15) return -1;
        out[i] = (uint8_t)(hi << 4 | lo);
    }
    return (int)(n / 2);
}

const char *env_or(const char *name, const char *fallback) {
    const char *v = getenv(name);
    return v && *v ? v : fallback;
}

int env_int(const char *name, int fallback) {
    const char *v = getenv(name);
    return v && *v ? atoi(v) : fallback;
}

int write_all(int fd, const void *buf, size_t len) {
    const char *p = buf;
    while (len > 0) {
        ssize_t w = write(fd, p, len);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += w;
        len -= (size_t)w;
    }
    return 0;
}

void tb_init(token_bucket *tb, double rate, double burst, long long now) {
    tb->rate = rate;
    tb->burst = burst;
    tb->tokens = burst;
    tb->last_ms = now;
}

int tb_take(token_bucket *tb, long long now) {
    double elapsed = (double)(now - tb->last_ms) / 1000.0;
    if (elapsed > 0) {
        tb->tokens += elapsed * tb->rate;
        if (tb->tokens > tb->burst) tb->tokens = tb->burst;
        tb->last_ms = now;
    }
    if (tb->tokens >= 1.0) {
        tb->tokens -= 1.0;
        return 1;
    }
    return 0;
}
