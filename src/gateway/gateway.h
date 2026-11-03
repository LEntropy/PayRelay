/* PG gateway: shared configuration, queues, counters and module interfaces. */
#ifndef PAYRELAY_GATEWAY_H
#define PAYRELAY_GATEWAY_H

#include "telegram.h"
#include "util.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>

#define MAX_CONNS      4096
#define MAX_MERCHANTS  256
#define JOB_QUEUE_CAP  4096

typedef struct {
    int listen_port;
    int control_port;
    int workers;
    int max_conn_per_ip;
    int frame_timeout_ms;   /* a started frame must complete within this time (slowloris) */
    int idle_timeout_ms;
    int van_timeout_ms;
    int ban_threshold;      /* protocol violations per IP within ban_window_s */
    int ban_window_s;
    int ban_seconds;
    const char *ban_exempt; /* comma-separated IPs that are never banned */
    const char *db_host, *db_user, *db_pass, *db_name;
    int db_port;
    const char *van_host;
    int van_port;
    const char *van_merchant_id;
    uint8_t van_key[64];
    int van_key_len;
    uint8_t token_key[64];  /* card token HMAC key */
    int token_key_len;
    const char *cert, *key, *ca;
} gw_config;

extern gw_config CFG;

/* Counters exposed on the control port. */
typedef struct {
    atomic_llong received, approved, declined, timeouts, reversals_ok, reversals_failed;
    atomic_llong canceled, duplicates, rate_limited, bad_mac, bad_format, unknown_merchant;
    atomic_llong conn_rejected, conn_accepted, conn_active, bans, queue_full;
    atomic_llong van_latency_ms_sum, van_calls;
} gw_stats;

extern gw_stats STATS;

/* ---- reactor <-> workers ------------------------------------------------------------- */

typedef struct {
    uint64_t conn_id;
    char ip[46];
    long long received_ms;
    size_t len;
    char data[TG_MAX_FRAME];
} gw_job;

/* Blocking pop for workers; push returns -1 when full (the reactor answers "busy"). */
int  jobq_push(const gw_job *j);
void jobq_pop(gw_job *j);
int  jobq_depth(void);

/* Worker -> reactor: send `data` on connection conn_id; close it afterwards if close_after. */
void reply_post(uint64_t conn_id, const char *data, size_t len, int close_after);

/* ---- modules ------------------------------------------------------------------------- */

int  reactor_run(void);                 /* conn.c, never returns on success */
void reactor_close_ip(const char *ip);  /* conn.c, thread safe: drops every connection from ip */
int  reactor_conn_count(void);

void *worker_main(void *arg);           /* worker.c */

/* guard.c: per-IP violations, bans (in-process and nftables) */
void guard_init(void);
int  guard_is_banned(const char *ip);
void guard_violation(const char *ip, const char *reason);   /* may ban; thread safe */
int  guard_unban(const char *ip);
int  guard_list(char *out, size_t cap);                     /* JSON array of bans */

void *control_main(void *arg);          /* control.c */

/* Merchant cache (worker.c) */
typedef struct {
    char id[11];
    uint8_t key[64];
    int key_len;
    int active;
    int tps;
    token_bucket tb;
} merchant;

#endif
