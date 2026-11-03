/*
 * Traffic guard: counts protocol violations per source IP and bans repeat offenders.
 *
 * A ban works on two layers:
 *   1. in-process deny list, checked on accept() (always available)
 *   2. an nftables set (`inet payrelay banned`) with a timeout, so the kernel drops the
 *      attacker's packets before they reach the gateway at all
 * nft is started with posix_spawnp and a fixed argument vector, never through a shell, and
 * only with an address that inet_pton has already validated.
 */
#include "gateway.h"
#include "store.h"

#include <arpa/inet.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>

#define MAX_TRACKED 1024

extern char **environ;

typedef struct {
    char ip[46];
    int count;
    long long window_start;
} offender;

typedef struct {
    char ip[46];
    long long until_ms;
    char reason[32];
    int kernel;   /* nftables element added */
} ban;

static offender offenders[MAX_TRACKED];
static ban bans[MAX_TRACKED];
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

void guard_init(void) {
    memset(offenders, 0, sizeof(offenders));
    memset(bans, 0, sizeof(bans));
}

static int exempt(const char *ip) {
    const char *p = CFG.ban_exempt;
    size_t n = strlen(ip);
    while (p && *p) {
        const char *e = strchr(p, ',');
        size_t len = e ? (size_t)(e - p) : strlen(p);
        if (len == n && strncmp(p, ip, n) == 0) return 1;
        p = e ? e + 1 : NULL;
    }
    return 0;
}

static int valid_ipv4(const char *ip) {
    struct in_addr a;
    return inet_pton(AF_INET, ip, &a) == 1;
}

/* Runs nft with a fixed argv. Returns its exit status, or -1 if it could not start. */
static int run_nft(const char *op, const char *ip) {
    char element[96];
    if (strcmp(op, "add") == 0) snprintf(element, sizeof(element), "{ %s timeout %ds }", ip, CFG.ban_seconds);
    else snprintf(element, sizeof(element), "{ %s }", ip);
    char *argv[] = { "nft", (char *)op, "element", "inet", "payrelay", "banned", element, NULL };
    pid_t pid;
    if (posix_spawnp(&pid, "nft", NULL, NULL, argv, environ) != 0) return -1;
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

int guard_is_banned(const char *ip) {
    long long now = now_ms();
    int banned = 0;
    pthread_mutex_lock(&lock);
    for (int i = 0; i < MAX_TRACKED; i++) {
        if (bans[i].ip[0] && strcmp(bans[i].ip, ip) == 0) {
            if (bans[i].until_ms > now) banned = 1;
            else bans[i].ip[0] = '\0';   /* expired */
            break;
        }
    }
    pthread_mutex_unlock(&lock);
    return banned;
}

static void do_ban(const char *ip, const char *reason) {
    long long now = now_ms();
    int slot = -1;
    for (int i = 0; i < MAX_TRACKED; i++) {
        if (!bans[i].ip[0] || bans[i].until_ms <= now) {
            slot = i;
            break;
        }
    }
    if (slot < 0) slot = 0;
    snprintf(bans[slot].ip, sizeof(bans[slot].ip), "%s", ip);
    bans[slot].until_ms = now + (long long)CFG.ban_seconds * 1000;
    snprintf(bans[slot].reason, sizeof(bans[slot].reason), "%s", reason);
    bans[slot].kernel = 0;
    atomic_fetch_add(&STATS.bans, 1);
}

void guard_violation(const char *ip, const char *reason) {
    sec_event_post(ip, "VIOLATION", NULL, reason);
    if (exempt(ip) || !valid_ipv4(ip)) return;

    long long now = now_ms();
    int ban_now = 0;
    pthread_mutex_lock(&lock);
    offender *o = NULL, *free_slot = NULL, *oldest = &offenders[0];
    for (int i = 0; i < MAX_TRACKED; i++) {
        if (offenders[i].ip[0] && strcmp(offenders[i].ip, ip) == 0) {
            o = &offenders[i];
            break;
        }
        if (!offenders[i].ip[0] && !free_slot) free_slot = &offenders[i];
        if (offenders[i].window_start < oldest->window_start) oldest = &offenders[i];
    }
    if (!o) {
        o = free_slot ? free_slot : oldest;
        snprintf(o->ip, sizeof(o->ip), "%s", ip);
        o->count = 0;
        o->window_start = now;
    }
    if (now - o->window_start > (long long)CFG.ban_window_s * 1000) {
        o->count = 0;
        o->window_start = now;
    }
    o->count++;
    if (o->count >= CFG.ban_threshold) {
        ban_now = 1;
        o->ip[0] = '\0';
        do_ban(ip, reason);
    }
    pthread_mutex_unlock(&lock);

    if (ban_now) {
        int rc = run_nft("add", ip);
        if (rc == 0) {
            pthread_mutex_lock(&lock);
            for (int i = 0; i < MAX_TRACKED; i++) {
                if (strcmp(bans[i].ip, ip) == 0) bans[i].kernel = 1;
            }
            pthread_mutex_unlock(&lock);
        }
        LOG_WARN("guard", "event=banned ip=%s reason=%s seconds=%d nftables=%s", ip, reason, CFG.ban_seconds,
                 rc == 0 ? "added" : "unavailable");
        char detail[96];
        snprintf(detail, sizeof(detail), "last=%s seconds=%d nftables=%s", reason, CFG.ban_seconds,
                 rc == 0 ? "added" : "unavailable");
        sec_event_post(ip, "BANNED", NULL, detail);
        reactor_close_ip(ip);
    }
}

int guard_unban(const char *ip) {
    if (!valid_ipv4(ip)) return -1;
    int found = 0;
    pthread_mutex_lock(&lock);
    for (int i = 0; i < MAX_TRACKED; i++) {
        if (bans[i].ip[0] && strcmp(bans[i].ip, ip) == 0) {
            bans[i].ip[0] = '\0';
            found = 1;
        }
    }
    pthread_mutex_unlock(&lock);
    run_nft("delete", ip);   /* harmless if it already expired */
    if (found) sec_event_post(ip, "UNBANNED", NULL, "by admin");
    return found;
}

int guard_list(char *out, size_t cap) {
    long long now = now_ms();
    size_t n = 0;
    n += (size_t)snprintf(out + n, cap - n, "[");
    int first = 1;
    pthread_mutex_lock(&lock);
    for (int i = 0; i < MAX_TRACKED && n < cap - 128; i++) {
        if (!bans[i].ip[0] || bans[i].until_ms <= now) continue;
        n += (size_t)snprintf(out + n, cap - n, "%s{\"ip\":\"%s\",\"reason\":\"%s\",\"remaining_s\":%lld,\"nftables\":%s}",
                              first ? "" : ",", bans[i].ip, bans[i].reason, (bans[i].until_ms - now) / 1000,
                              bans[i].kernel ? "true" : "false");
        first = 0;
    }
    pthread_mutex_unlock(&lock);
    n += (size_t)snprintf(out + n, cap - n, "]");
    return (int)n;
}
