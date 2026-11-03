#include "store.h"

#include "gateway.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ---- small prepared-statement helper -------------------------------------------------- */

typedef struct {
    enum { P_STR, P_LL, P_INT, P_NULL } type;
    const char *s;
    long long ll;
    int i;
} param;

#define PS(x) ((param){ .type = P_STR, .s = (x) })
#define PS_OR_NULL(x) ((x) ? PS(x) : (param){ .type = P_NULL })
#define PLL(x) ((param){ .type = P_LL, .ll = (x) })
#define PI(x) ((param){ .type = P_INT, .i = (x) })

static void bind_params(MYSQL_BIND *b, param *p, int n, unsigned long *lens) {
    memset(b, 0, sizeof(MYSQL_BIND) * (size_t)n);
    for (int k = 0; k < n; k++) {
        switch (p[k].type) {
        case P_STR:
            lens[k] = strlen(p[k].s);
            b[k].buffer_type = MYSQL_TYPE_STRING;
            b[k].buffer = (void *)p[k].s;
            b[k].buffer_length = lens[k];
            b[k].length = &lens[k];
            break;
        case P_LL:
            b[k].buffer_type = MYSQL_TYPE_LONGLONG;
            b[k].buffer = &p[k].ll;
            break;
        case P_INT:
            b[k].buffer_type = MYSQL_TYPE_LONG;
            b[k].buffer = &p[k].i;
            break;
        case P_NULL:
            b[k].buffer_type = MYSQL_TYPE_NULL;
            break;
        }
    }
}

/* Executes a statement. Returns affected rows, -1 on error, -2 on duplicate key. */
static long long exec(store *s, const char *sql, param *p, int n) {
    MYSQL_STMT *st = mysql_stmt_init(s->db);
    if (!st) return -1;
    long long rc = -1;
    MYSQL_BIND b[24];
    unsigned long lens[24];
    if (mysql_stmt_prepare(st, sql, strlen(sql)) != 0) goto out;
    bind_params(b, p, n, lens);
    if (n && mysql_stmt_bind_param(st, b) != 0) goto out;
    if (mysql_stmt_execute(st) != 0) {
        if (mysql_stmt_errno(st) == 1062) rc = -2;   /* ER_DUP_ENTRY */
        else LOG_ERR("store", "event=sql_error errno=%u msg=\"%s\"", mysql_stmt_errno(st), mysql_stmt_error(st));
        goto out;
    }
    rc = (long long)mysql_stmt_affected_rows(st);
out:
    mysql_stmt_close(st);
    return rc;
}

int store_open(store *s) {
    s->db = mysql_init(NULL);
    if (!s->db) return -1;
    unsigned int timeout = 5;
    mysql_options(s->db, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
    mysql_options(s->db, MYSQL_SET_CHARSET_NAME, "utf8mb4");
    for (int attempt = 0; attempt < 30; attempt++) {
        if (mysql_real_connect(s->db, CFG.db_host, CFG.db_user, CFG.db_pass, CFG.db_name,
                               (unsigned)CFG.db_port, NULL, 0)) {
            return 0;
        }
        LOG_WARN("store", "event=db_connect_retry attempt=%d msg=\"%s\"", attempt + 1, mysql_error(s->db));
        sleep(2);
    }
    return -1;
}

void store_close(store *s) {
    if (s->db) mysql_close(s->db);
    s->db = NULL;
}

int store_begin(store *s) { return mysql_query(s->db, "START TRANSACTION") == 0 ? 0 : -1; }
int store_commit(store *s) { return mysql_commit(s->db) == 0 ? 0 : -1; }
int store_rollback(store *s) { return mysql_rollback(s->db) == 0 ? 0 : -1; }

int store_load_merchants(store *s, void (*fn)(const char *, const char *, int, int, void *), void *ctx) {
    if (mysql_query(s->db, "SELECT merchant_id, mac_key_hex, status = 'ACTIVE', tps_limit FROM merchants") != 0) {
        LOG_ERR("store", "event=load_merchants_failed msg=\"%s\"", mysql_error(s->db));
        return -1;
    }
    MYSQL_RES *res = mysql_store_result(s->db);
    if (!res) return -1;
    MYSQL_ROW row;
    while ((row = mysql_fetch_row(res))) fn(row[0], row[1], atoi(row[2]), atoi(row[3]), ctx);
    mysql_free_result(res);
    return 0;
}

int store_insert_tx(store *s, const tx_rec *t) {
    param p[] = { PS(t->pg_tx_id), PS(t->merchant_id), PS(t->order_no), PS(t->terminal_id), PS(t->trace_no),
                  PLL(t->amount), PS(t->currency), PI(t->installment), PS(t->card_bin), PS(t->card_last4),
                  PS(t->card_token), PS(t->status), PS_OR_NULL(t->resp_code[0] ? t->resp_code : NULL),
                  PS(t->client_ip) };
    long long rc = exec(s,
        "INSERT INTO transactions (pg_tx_id, merchant_id, order_no, terminal_id, trace_no, amount, currency,"
        " installment, card_bin, card_last4, card_token, status, resp_code, client_ip)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", p, 14);
    if (rc == -2) return 1;
    return rc == 1 ? 0 : -1;
}

int store_get_by_order(store *s, const char *merchant_id, const char *order_no, tx_rec *out, int for_update) {
    const char *sql = for_update
        ? "SELECT pg_tx_id, merchant_id, order_no, amount, card_bin, card_last4, card_token, status,"
          " IFNULL(resp_code,''), IFNULL(approval_no,''), IFNULL(cancel_approval,'')"
          " FROM transactions WHERE merchant_id = ? AND order_no = ? FOR UPDATE"
        : "SELECT pg_tx_id, merchant_id, order_no, amount, card_bin, card_last4, card_token, status,"
          " IFNULL(resp_code,''), IFNULL(approval_no,''), IFNULL(cancel_approval,'')"
          " FROM transactions WHERE merchant_id = ? AND order_no = ?";
    MYSQL_STMT *st = mysql_stmt_init(s->db);
    if (!st) return -1;
    int rc = -1;
    param p[] = { PS(merchant_id), PS(order_no) };
    MYSQL_BIND in[2], res[11];
    unsigned long inlens[2], lens[11];
    memset(out, 0, sizeof(*out));
    if (mysql_stmt_prepare(st, sql, strlen(sql)) != 0) goto done;
    bind_params(in, p, 2, inlens);
    if (mysql_stmt_bind_param(st, in) != 0 || mysql_stmt_execute(st) != 0) goto done;

    memset(res, 0, sizeof(res));
    struct { void *buf; unsigned long cap; } cols[] = {
        { out->pg_tx_id, sizeof(out->pg_tx_id) }, { out->merchant_id, sizeof(out->merchant_id) },
        { out->order_no, sizeof(out->order_no) },  { NULL, 0 },
        { out->card_bin, sizeof(out->card_bin) },  { out->card_last4, sizeof(out->card_last4) },
        { out->card_token, sizeof(out->card_token) }, { out->status, sizeof(out->status) },
        { out->resp_code, sizeof(out->resp_code) }, { out->approval_no, sizeof(out->approval_no) },
        { out->cancel_approval, sizeof(out->cancel_approval) },
    };
    for (int k = 0; k < 11; k++) {
        if (k == 3) {
            res[k].buffer_type = MYSQL_TYPE_LONGLONG;
            res[k].buffer = &out->amount;
        } else {
            res[k].buffer_type = MYSQL_TYPE_STRING;
            res[k].buffer = cols[k].buf;
            res[k].buffer_length = cols[k].cap - 1;   /* keep room for the terminating NUL */
            res[k].length = &lens[k];
        }
    }
    if (mysql_stmt_bind_result(st, res) != 0 || mysql_stmt_store_result(st) != 0) goto done;
    int f = mysql_stmt_fetch(st);
    if (f == MYSQL_NO_DATA) {
        rc = 1;
        goto done;
    }
    if (f != 0 && f != MYSQL_DATA_TRUNCATED) goto done;
    for (int k = 0; k < 11; k++) {
        if (k != 3) ((char *)cols[k].buf)[lens[k] < cols[k].cap ? lens[k] : cols[k].cap - 1] = '\0';
    }
    rc = 0;
done:
    mysql_stmt_close(st);
    return rc;
}

int store_transition(store *s, const char *pg_tx_id, const char *from, const char *to, const char *resp_code,
                     const char *approval_no, int van_latency_ms) {
    /* van_latency_ms < 0 means "not measured": keep the stored value */
    param p[] = { PS(to), PS(resp_code), PS_OR_NULL(approval_no), PI(van_latency_ms), PI(van_latency_ms),
                  PS(pg_tx_id), PS(from) };
    long long rc = exec(s,
        "UPDATE transactions SET status = ?, resp_code = ?, approval_no = IFNULL(?, approval_no),"
        " van_latency_ms = IF(? >= 0, ?, van_latency_ms), responded_at = CURRENT_TIMESTAMP(3)"
        " WHERE pg_tx_id = ? AND status = ?", p, 7);
    return (int)rc;
}

int store_mark_canceled(store *s, const char *pg_tx_id, const char *cancel_approval) {
    param p[] = { PS_OR_NULL(cancel_approval), PS(pg_tx_id) };
    return (int)exec(s,
        "UPDATE transactions SET status = 'CANCELED', cancel_approval = ?, canceled_at = CURRENT_TIMESTAMP(3)"
        " WHERE pg_tx_id = ? AND status = 'APPROVED'", p, 2);
}

int store_event(store *s, const char *pg_tx_id, const char *event, const char *detail) {
    param p[] = { PS(pg_tx_id), PS(event), PS_OR_NULL(detail) };
    return exec(s, "INSERT INTO tx_events (pg_tx_id, event, detail) VALUES (?,?,?)", p, 3) == 1 ? 0 : -1;
}

/* ---- security event writer ------------------------------------------------------------ */

typedef struct sec_ev {
    struct sec_ev *next;
    char ip[46], event[32], merchant[11], detail[128];
} sec_ev;

static sec_ev *sq_head, *sq_tail;
static int sq_len;
static pthread_mutex_t sq_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t sq_cond = PTHREAD_COND_INITIALIZER;

void sec_event_post(const char *ip, const char *event, const char *merchant_id, const char *detail) {
    sec_ev *e = calloc(1, sizeof(*e));
    if (!e) return;
    snprintf(e->ip, sizeof(e->ip), "%s", ip);
    snprintf(e->event, sizeof(e->event), "%s", event);
    snprintf(e->merchant, sizeof(e->merchant), "%s", merchant_id ? merchant_id : "");
    snprintf(e->detail, sizeof(e->detail), "%s", detail ? detail : "");
    pthread_mutex_lock(&sq_lock);
    if (sq_len > 10000) {   /* never let an attack exhaust memory through logging */
        pthread_mutex_unlock(&sq_lock);
        free(e);
        return;
    }
    if (sq_tail) sq_tail->next = e;
    else sq_head = e;
    sq_tail = e;
    sq_len++;
    pthread_cond_signal(&sq_cond);
    pthread_mutex_unlock(&sq_lock);
}

void *sec_writer_main(void *arg) {
    (void)arg;
    mysql_thread_init();
    store s;
    if (store_open(&s) != 0) return NULL;
    for (;;) {
        pthread_mutex_lock(&sq_lock);
        while (!sq_head) pthread_cond_wait(&sq_cond, &sq_lock);
        sec_ev *e = sq_head;
        sq_head = e->next;
        if (!sq_head) sq_tail = NULL;
        sq_len--;
        pthread_mutex_unlock(&sq_lock);

        param p[] = { PS(e->ip), PS(e->event), PS_OR_NULL(e->merchant[0] ? e->merchant : NULL), PS(e->detail) };
        if (exec(&s, "INSERT INTO security_events (client_ip, event, merchant_id, detail) VALUES (?,?,?,?)", p, 4) < 0) {
            mysql_ping(s.db);   /* reconnect if the server dropped us */
        }
        free(e);
    }
}
