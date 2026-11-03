/*
 * Internal control interface used by the admin console. Line protocol over TCP:
 *
 *   AUTH <token>      must be the first line (constant-time compare)
 *   HEALTH | STATS | BANS | UNBAN <ipv4> | RELOAD
 *
 * Each answer is one line of JSON. The port is only reachable on the internal Docker network.
 */
#include "gateway.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/crypto.h>

extern atomic_int MERCHANT_RELOAD;
static const char *token;

static int read_line(int fd, char *buf, size_t cap) {
    size_t n = 0;
    while (n + 1 < cap) {
        char c;
        ssize_t r = read(fd, &c, 1);
        if (r <= 0) return -1;
        if (c == '\n') break;
        if (c != '\r') buf[n++] = c;
    }
    buf[n] = '\0';
    return (int)n;
}

static void answer(int fd, const char *s) {
    write_all(fd, s, strlen(s));
    write_all(fd, "\n", 1);
}

static void stats_json(char *out, size_t cap) {
    long long calls = atomic_load(&STATS.van_calls);
    long long lat = atomic_load(&STATS.van_latency_ms_sum);
    snprintf(out, cap,
             "{\"received\":%lld,\"approved\":%lld,\"declined\":%lld,\"timeouts\":%lld,\"reversals_ok\":%lld,"
             "\"reversals_failed\":%lld,\"canceled\":%lld,\"duplicates\":%lld,\"rate_limited\":%lld,"
             "\"bad_mac\":%lld,\"bad_format\":%lld,\"unknown_merchant\":%lld,\"conn_accepted\":%lld,"
             "\"conn_rejected\":%lld,\"conn_active\":%lld,\"bans\":%lld,\"queue_full\":%lld,\"queue_depth\":%d,"
             "\"van_calls\":%lld,\"van_avg_ms\":%.1f,\"workers\":%d}",
             atomic_load(&STATS.received), atomic_load(&STATS.approved), atomic_load(&STATS.declined),
             atomic_load(&STATS.timeouts), atomic_load(&STATS.reversals_ok), atomic_load(&STATS.reversals_failed),
             atomic_load(&STATS.canceled), atomic_load(&STATS.duplicates), atomic_load(&STATS.rate_limited),
             atomic_load(&STATS.bad_mac), atomic_load(&STATS.bad_format), atomic_load(&STATS.unknown_merchant),
             atomic_load(&STATS.conn_accepted), atomic_load(&STATS.conn_rejected), atomic_load(&STATS.conn_active),
             atomic_load(&STATS.bans), atomic_load(&STATS.queue_full), jobq_depth(), calls,
             calls ? (double)lat / (double)calls : 0.0, CFG.workers);
}

static void *session(void *arg) {
    int fd = (int)(long)arg;
    struct timeval tv = { 10, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    char line[256];
    if (read_line(fd, line, sizeof(line)) < 0 || strncmp(line, "AUTH ", 5) != 0 ||
        strlen(line + 5) != strlen(token) || CRYPTO_memcmp(line + 5, token, strlen(token)) != 0) {
        answer(fd, "{\"error\":\"unauthorized\"}");
        close(fd);
        return NULL;
    }
    answer(fd, "{\"ok\":true}");
    static char big[65536];
    static pthread_mutex_t big_lock = PTHREAD_MUTEX_INITIALIZER;
    while (read_line(fd, line, sizeof(line)) >= 0) {
        if (strcmp(line, "HEALTH") == 0) {
            answer(fd, "{\"ok\":true}");
        } else if (strcmp(line, "STATS") == 0) {
            char s[1024];
            stats_json(s, sizeof(s));
            answer(fd, s);
        } else if (strcmp(line, "BANS") == 0) {
            pthread_mutex_lock(&big_lock);
            guard_list(big, sizeof(big));
            answer(fd, big);
            pthread_mutex_unlock(&big_lock);
        } else if (strncmp(line, "UNBAN ", 6) == 0) {
            int r = guard_unban(line + 6);
            answer(fd, r < 0 ? "{\"error\":\"invalid ip\"}" : r ? "{\"ok\":true,\"found\":true}" : "{\"ok\":true,\"found\":false}");
        } else if (strcmp(line, "RELOAD") == 0) {
            atomic_store(&MERCHANT_RELOAD, 1);
            answer(fd, "{\"ok\":true}");
        } else {
            answer(fd, "{\"error\":\"unknown command\"}");
        }
    }
    close(fd);
    return NULL;
}

void *control_main(void *arg) {
    (void)arg;
    token = env_or("CONTROL_TOKEN", "");
    if (strlen(token) < 16) {
        LOG_ERR("control", "event=disabled reason=\"CONTROL_TOKEN shorter than 16 characters\"");
        return NULL;
    }
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons((uint16_t)CFG.control_port),
                             .sin_addr.s_addr = INADDR_ANY };
    if (bind(ls, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(ls, 16) != 0) {
        LOG_ERR("control", "event=listen_failed port=%d", CFG.control_port);
        return NULL;
    }
    LOG_INFO("control", "event=listening port=%d", CFG.control_port);
    for (;;) {
        int fd = accept(ls, NULL, NULL);
        if (fd < 0) continue;
        pthread_t th;
        if (pthread_create(&th, NULL, session, (void *)(long)fd) == 0) pthread_detach(th);
        else close(fd);
    }
}
