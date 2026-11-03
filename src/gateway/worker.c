/*
 * Worker threads: the payment logic.
 *
 * For every complete telegram from a merchant:
 *   parse -> merchant lookup -> MAC check -> per-merchant rate limit -> dispatch
 *
 * Approval (0200)
 *   1. validate card number (Luhn), expiry, amount and currency
 *   2. INSERT a PENDING row. The UNIQUE (merchant_id, order_no) key makes retries
 *      idempotent: a repeated order returns the stored result instead of charging twice
 *   3. forward to the VAN over mutual TLS and wait at most van_timeout_ms
 *   4. answer -> APPROVED / DECLINED. No answer -> TIMEOUT, reply 9001 to the merchant at
 *      once, then send a reversal (0420, 망취소) so the customer is not charged for a payment
 *      the merchant was told failed. Confirmed -> NET_CANCELED, unconfirmed -> REVERSAL_FAILED
 *      (left for reconciliation against the VAN settlement file)
 *
 * Cancel (0400): the row is locked (SELECT ... FOR UPDATE) for the VAN round trip so two
 * cancels of the same payment cannot both go through.
 */
#include "gateway.h"
#include "card.h"
#include "store.h"
#include "tlsio.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

SSL_CTX *VAN_CTX;

/* ---- merchant cache ------------------------------------------------------------------- */

static merchant merchants[MAX_MERCHANTS];
static int merchant_n;
static pthread_rwlock_t merchant_lock = PTHREAD_RWLOCK_INITIALIZER;
static pthread_mutex_t bucket_lock = PTHREAD_MUTEX_INITIALIZER;
static long long merchants_loaded_ms;
atomic_int MERCHANT_RELOAD;

typedef struct {
    merchant list[MAX_MERCHANTS];
    int n;
} merchant_load;

static void on_merchant(const char *id, const char *key_hex, int active, int tps, void *ctx) {
    merchant_load *ml = ctx;
    if (ml->n >= MAX_MERCHANTS) return;
    merchant *m = &ml->list[ml->n];
    snprintf(m->id, sizeof(m->id), "%s", id);
    m->key_len = hex_decode(key_hex, m->key, sizeof(m->key));
    if (m->key_len < 16) return;   /* refuse weak or broken keys */
    m->active = active;
    m->tps = tps > 0 ? tps : 1;
    ml->n++;
}

void reload_merchants(store *s) {
    static merchant_load ml;
    ml.n = 0;
    if (store_load_merchants(s, on_merchant, &ml) != 0) return;
    pthread_rwlock_wrlock(&merchant_lock);
    long long now = now_ms();
    for (int i = 0; i < ml.n; i++) {
        /* keep the bucket state of merchants we already know */
        int kept = 0;
        for (int j = 0; j < merchant_n; j++) {
            if (strcmp(merchants[j].id, ml.list[i].id) == 0 && merchants[j].tps == ml.list[i].tps) {
                ml.list[i].tb = merchants[j].tb;
                kept = 1;
            }
        }
        if (!kept) tb_init(&ml.list[i].tb, ml.list[i].tps, ml.list[i].tps, now);
    }
    memcpy(merchants, ml.list, sizeof(merchant) * (size_t)ml.n);
    merchant_n = ml.n;
    merchants_loaded_ms = now;
    pthread_rwlock_unlock(&merchant_lock);
    LOG_INFO("worker", "event=merchants_loaded count=%d", ml.n);
}

static int find_merchant(const char *id, merchant *out) {
    int found = 0;
    pthread_rwlock_rdlock(&merchant_lock);
    for (int i = 0; i < merchant_n; i++) {
        if (strcmp(merchants[i].id, id) == 0) {
            *out = merchants[i];
            found = 1;
            break;
        }
    }
    pthread_rwlock_unlock(&merchant_lock);
    return found;
}

static int take_token(const char *id) {
    int ok = 1;
    pthread_rwlock_rdlock(&merchant_lock);
    pthread_mutex_lock(&bucket_lock);
    for (int i = 0; i < merchant_n; i++) {
        if (strcmp(merchants[i].id, id) == 0) {
            ok = tb_take(&merchants[i].tb, now_ms());
            break;
        }
    }
    pthread_mutex_unlock(&bucket_lock);
    pthread_rwlock_unlock(&merchant_lock);
    return ok;
}

/* ---- worker state and helpers --------------------------------------------------------- */

typedef struct {
    int id;
    store db;
    SSL *van;
    int van_fd;
} worker;

static atomic_uint tx_seq;

static void new_pg_tx_id(char out[21]) {
    char dt[15];
    now_datetime14(dt);
    unsigned seq = atomic_fetch_add(&tx_seq, 1) % 10000000u;
    snprintf(out, 21, "P%.12s%07u", dt + 2, seq);   /* P + YYMMDDhhmmss + 7 digits = 20 */
}

static void reply(const gw_job *j, tg_msg *m, const merchant *mc, int close_after) {
    char out[TG_MAX_FRAME];
    static const uint8_t no_key[16];
    int n = mc ? tg_encode(m, mc->key, (size_t)mc->key_len, out, sizeof(out))
               : tg_encode(m, no_key, sizeof(no_key), out, sizeof(out));
    if (n < 0) {
        reply_post(j->conn_id, NULL, 0, 1);
        return;
    }
    reply_post(j->conn_id, out, (size_t)n, close_after);
}

static void van_drop(worker *w) {
    if (w->van) {
        SSL_free(w->van);
        close(w->van_fd);
    }
    w->van = NULL;
}

static int van_ensure(worker *w) {
    if (w->van) return 0;
    w->van = tls_connect(VAN_CTX, CFG.van_host, CFG.van_port, CFG.van_timeout_ms, &w->van_fd);
    if (!w->van) {
        LOG_WARN("worker", "event=van_connect_failed worker=%d reason=\"%s\"", w->id, tls_err());
        return -1;
    }
    return 0;
}

typedef enum { VAN_OK, VAN_TIMEOUT, VAN_UNAVAILABLE } van_result;

/*
 * One request/response with the VAN. VAN_UNAVAILABLE means the request certainly did not
 * arrive (connect or send failed); VAN_TIMEOUT means it may have arrived, so the outcome
 * is unknown and must be reversed.
 */
static van_result van_call(worker *w, const tg_msg *req, tg_msg *resp, int *latency_ms) {
    char out[TG_MAX_FRAME], in[TG_MAX_FRAME];
    int n = tg_encode(req, CFG.van_key, (size_t)CFG.van_key_len, out, sizeof(out));
    if (n < 0) return VAN_UNAVAILABLE;

    int sent = 0;
    for (int attempt = 0; attempt < 2 && !sent; attempt++) {
        if (van_ensure(w) != 0) return VAN_UNAVAILABLE;
        if (tls_write_all(w->van, out, (size_t)n) == 0) sent = 1;
        else van_drop(w);   /* stale pooled connection: the write failed, safe to retry once */
    }
    if (!sent) return VAN_UNAVAILABLE;

    long long t0 = now_ms();
    int r = tls_read_frame(w->van, in, sizeof(in));
    *latency_ms = (int)(now_ms() - t0);
    atomic_fetch_add(&STATS.van_calls, 1);
    atomic_fetch_add(&STATS.van_latency_ms_sum, *latency_ms);
    const char *bad = NULL;
    if (r <= 0 || tg_decode(in, (size_t)r, resp, &bad) != TG_OK ||
        tg_verify_mac(in, (size_t)r, CFG.van_key, (size_t)CFG.van_key_len) != TG_OK ||
        strcmp(resp->order_no, req->order_no) != 0) {
        /* A late answer on this connection could be mistaken for the next request's. */
        van_drop(w);
        return VAN_TIMEOUT;
    }
    return VAN_OK;
}

static void upstream_from(const tg_msg *req, const char *type, const char *pg_tx_id, tg_msg *up) {
    memset(up, 0, sizeof(*up));
    memcpy(up->msg_type, type, 4);
    strcpy(up->version, "01");
    snprintf(up->merchant_id, sizeof(up->merchant_id), "%s", CFG.van_merchant_id);
    strcpy(up->terminal_id, "PGGW0001");
    strcpy(up->trace_no, req->trace_no);
    now_datetime14(up->tx_datetime);
    strcpy(up->resp_code, RC_OK);
    snprintf(up->order_no, sizeof(up->order_no), "%s", pg_tx_id);   /* the VAN knows PG ids only */
    snprintf(up->pg_tx_id, sizeof(up->pg_tx_id), "%s", pg_tx_id);
    strcpy(up->card_no, req->card_no);
    strcpy(up->expiry, req->expiry);
    strcpy(up->installment, req->installment[0] ? req->installment : "00");
    strcpy(up->currency, req->currency[0] ? req->currency : "KRW");
    strcpy(up->reason, req->reason[0] ? req->reason : "01");
    up->amount = req->amount;
}

/* ---- reversal (망취소) ----------------------------------------------------------------- */

static void reverse(worker *w, const tg_msg *req, const char *pg_tx_id) {
    tg_msg up, resp;
    upstream_from(req, TG_REVERSE_REQ, pg_tx_id, &up);
    strcpy(up.reason, "99");
    for (int attempt = 1; attempt <= 3; attempt++) {
        van_drop(w);   /* never reuse the connection that timed out */
        int lat = 0;
        if (van_call(w, &up, &resp, &lat) == VAN_OK && strcmp(resp.resp_code, RC_OK) == 0) {
            store_transition(&w->db, pg_tx_id, "TIMEOUT", "NET_CANCELED", RC_VAN_TIMEOUT, NULL, -1);
            char d[64];
            snprintf(d, sizeof(d), "attempt=%d", attempt);
            store_event(&w->db, pg_tx_id, "REVERSED", d);
            atomic_fetch_add(&STATS.reversals_ok, 1);
            LOG_INFO("worker", "event=reversal_ok pg_tx_id=%s attempt=%d", pg_tx_id, attempt);
            return;
        }
        LOG_WARN("worker", "event=reversal_retry pg_tx_id=%s attempt=%d", pg_tx_id, attempt);
        usleep(300 * 1000);
    }
    store_transition(&w->db, pg_tx_id, "TIMEOUT", "REVERSAL_FAILED", RC_VAN_TIMEOUT, NULL, -1);
    store_event(&w->db, pg_tx_id, "REVERSAL_FAILED", "3 attempts, no confirmation: check settlement file");
    atomic_fetch_add(&STATS.reversals_failed, 1);
    LOG_ERR("worker", "event=reversal_failed pg_tx_id=%s", pg_tx_id);
}

/* ---- approval ------------------------------------------------------------------------- */

static void reply_approve(const gw_job *j, const tg_msg *req, const merchant *mc, const char *rc,
                          const char *pg_tx_id, const char *approval_no, const char *masked) {
    tg_msg r;
    tg_make_reply(req, &r, TG_APPROVE_RESP, rc);
    snprintf(r.pg_tx_id, sizeof(r.pg_tx_id), "%s", pg_tx_id ? pg_tx_id : "");
    snprintf(r.approval_no, sizeof(r.approval_no), "%s", approval_no ? approval_no : "");
    snprintf(r.card_masked, sizeof(r.card_masked), "%s", masked ? masked : "");
    reply(j, &r, mc, 0);
}

static const char *final_rc(const tx_rec *t) {
    if (strcmp(t->status, "NET_CANCELED") == 0 || strcmp(t->status, "REVERSAL_FAILED") == 0) return RC_VAN_TIMEOUT;
    return t->resp_code[0] ? t->resp_code : RC_SYSTEM;
}

static void approve(worker *w, const gw_job *j, const tg_msg *req, const merchant *mc) {
    char masked[20], token[65], now_ym[5];
    card_mask(req->card_no, masked);
    now_yymm(now_ym);

    tx_rec t;
    memset(&t, 0, sizeof(t));
    new_pg_tx_id(t.pg_tx_id);
    strcpy(t.merchant_id, req->merchant_id);
    strcpy(t.order_no, req->order_no);
    strcpy(t.terminal_id, req->terminal_id);
    strcpy(t.trace_no, req->trace_no);
    t.amount = req->amount;
    snprintf(t.currency, sizeof(t.currency), "%s", req->currency);
    t.installment = (req->installment[0] - '0') * 10 + (req->installment[1] - '0');
    snprintf(t.card_bin, sizeof(t.card_bin), "%.6s", req->card_no);
    size_t pl = strlen(req->card_no);
    snprintf(t.card_last4, sizeof(t.card_last4), "%s", pl >= 4 ? req->card_no + pl - 4 : "0000");
    card_token(CFG.token_key, (size_t)CFG.token_key_len, req->card_no, token);
    strcpy(t.card_token, token);
    snprintf(t.client_ip, sizeof(t.client_ip), "%s", j->ip);

    /* Checks the gateway can make on its own; declined without bothering the VAN. */
    const char *pre = NULL;
    if (!card_luhn_valid(req->card_no)) pre = RC_BAD_CARD;
    else if (!card_expiry_ok(req->expiry, now_ym)) pre = RC_EXPIRED;
    else if (req->amount <= 0 || strcmp(req->currency, "KRW") != 0 || t.installment > 36) pre = RC_BAD_FORMAT;

    strcpy(t.status, pre ? "DECLINED" : "PENDING");
    if (pre) strcpy(t.resp_code, pre);

    int ins = store_insert_tx(&w->db, &t);
    if (ins == 1) {
        tx_rec old;
        if (store_get_by_order(&w->db, req->merchant_id, req->order_no, &old, 0) != 0) {
            reply_approve(j, req, mc, RC_SYSTEM, NULL, NULL, NULL);
            return;
        }
        atomic_fetch_add(&STATS.duplicates, 1);
        if (old.amount != req->amount || strcmp(old.card_token, token) != 0) {
            /* Same order number, different payment: never replay someone else's result. */
            sec_event_post(j->ip, "ORDER_REUSE", req->merchant_id, req->order_no);
            reply_approve(j, req, mc, RC_BAD_FORMAT, NULL, NULL, NULL);
            return;
        }
        if (strcmp(old.status, "PENDING") == 0 || strcmp(old.status, "TIMEOUT") == 0) {
            reply_approve(j, req, mc, RC_IN_PROGRESS, old.pg_tx_id, NULL, masked);
            return;
        }
        store_event(&w->db, old.pg_tx_id, "DUPLICATE_REPLAY", "same order resent: stored result returned");
        reply_approve(j, req, mc, final_rc(&old), old.pg_tx_id, old.approval_no, masked);
        return;
    }
    if (ins != 0) {
        mysql_ping(w->db.db);
        reply_approve(j, req, mc, RC_SYSTEM, NULL, NULL, NULL);
        return;
    }
    if (pre) {
        atomic_fetch_add(&STATS.declined, 1);
        store_event(&w->db, t.pg_tx_id, "DECLINED_BY_GATEWAY", pre);
        reply_approve(j, req, mc, pre, t.pg_tx_id, NULL, masked);
        return;
    }
    store_event(&w->db, t.pg_tx_id, "REQUESTED", NULL);

    tg_msg up, resp;
    upstream_from(req, TG_APPROVE_REQ, t.pg_tx_id, &up);
    int lat = 0;
    van_result vr = van_call(w, &up, &resp, &lat);

    if (vr == VAN_OK) {
        int ok = strcmp(resp.resp_code, RC_OK) == 0;
        store_transition(&w->db, t.pg_tx_id, "PENDING", ok ? "APPROVED" : "DECLINED", resp.resp_code,
                         ok ? resp.approval_no : NULL, lat);
        store_event(&w->db, t.pg_tx_id, ok ? "APPROVED" : "DECLINED_BY_VAN", resp.resp_code);
        atomic_fetch_add(ok ? &STATS.approved : &STATS.declined, 1);
        reply_approve(j, req, mc, resp.resp_code, t.pg_tx_id, ok ? resp.approval_no : NULL, masked);
        return;
    }
    if (vr == VAN_UNAVAILABLE) {
        store_transition(&w->db, t.pg_tx_id, "PENDING", "DECLINED", RC_VAN_UNAVAILABLE, NULL, -1);
        store_event(&w->db, t.pg_tx_id, "VAN_UNAVAILABLE", "request not delivered");
        atomic_fetch_add(&STATS.declined, 1);
        reply_approve(j, req, mc, RC_VAN_UNAVAILABLE, t.pg_tx_id, NULL, masked);
        return;
    }
    /* Outcome unknown: tell the merchant now, then undo whatever the VAN may have done. */
    store_transition(&w->db, t.pg_tx_id, "PENDING", "TIMEOUT", RC_VAN_TIMEOUT, NULL, lat);
    char d[48];
    snprintf(d, sizeof(d), "no answer within %d ms", CFG.van_timeout_ms);
    store_event(&w->db, t.pg_tx_id, "VAN_TIMEOUT", d);
    atomic_fetch_add(&STATS.timeouts, 1);
    reply_approve(j, req, mc, RC_VAN_TIMEOUT, t.pg_tx_id, NULL, masked);
    reverse(w, req, t.pg_tx_id);
}

/* ---- cancel --------------------------------------------------------------------------- */

static void reply_cancel(const gw_job *j, const tg_msg *req, const merchant *mc, const char *rc, const char *approval) {
    tg_msg r;
    tg_make_reply(req, &r, TG_CANCEL_RESP, rc);
    snprintf(r.approval_no, sizeof(r.approval_no), "%s", approval ? approval : "");
    reply(j, &r, mc, 0);
}

static void cancel(worker *w, const gw_job *j, const tg_msg *req, const merchant *mc) {
    tx_rec t;
    if (store_begin(&w->db) != 0) {
        reply_cancel(j, req, mc, RC_SYSTEM, NULL);
        return;
    }
    int g = store_get_by_order(&w->db, req->merchant_id, req->order_no, &t, 1);
    const char *rc = NULL;
    if (g != 0 || strcmp(t.pg_tx_id, req->pg_tx_id) != 0) rc = g < 0 ? RC_SYSTEM : RC_NO_ORIGINAL;
    else if (strcmp(t.status, "CANCELED") == 0) rc = RC_ALREADY_CANCELED;
    else if (strcmp(t.status, "APPROVED") != 0) rc = RC_NO_ORIGINAL;
    else if (t.amount != req->amount) rc = RC_AMOUNT_MISMATCH;   /* full cancellation only */
    if (rc) {
        store_rollback(&w->db);
        reply_cancel(j, req, mc, rc, strcmp(rc, RC_ALREADY_CANCELED) == 0 ? t.cancel_approval : NULL);
        return;
    }

    tg_msg up, resp;
    upstream_from(req, TG_CANCEL_REQ, t.pg_tx_id, &up);
    int lat = 0;
    van_result vr = van_call(w, &up, &resp, &lat);
    /* 3002 from the VAN means an earlier cancel already went through: same end state. */
    if (vr == VAN_OK && (strcmp(resp.resp_code, RC_OK) == 0 || strcmp(resp.resp_code, RC_ALREADY_CANCELED) == 0)) {
        store_mark_canceled(&w->db, t.pg_tx_id, resp.approval_no);
        store_event(&w->db, t.pg_tx_id, "CANCELED", resp.resp_code);
        store_commit(&w->db);
        atomic_fetch_add(&STATS.canceled, 1);
        reply_cancel(j, req, mc, RC_OK, resp.approval_no);
        return;
    }
    store_rollback(&w->db);
    if (vr == VAN_OK) {
        reply_cancel(j, req, mc, resp.resp_code, NULL);
        return;
    }
    store_event(&w->db, t.pg_tx_id, vr == VAN_TIMEOUT ? "CANCEL_UNCERTAIN" : "CANCEL_NOT_SENT",
                "payment stays APPROVED; merchant may retry the cancel");
    reply_cancel(j, req, mc, vr == VAN_TIMEOUT ? RC_VAN_TIMEOUT : RC_VAN_UNAVAILABLE, NULL);
}

/* ---- dispatch ------------------------------------------------------------------------- */

static void process(worker *w, const gw_job *j) {
    tg_msg req;
    const char *bad = NULL;
    tg_status st = tg_decode(j->data, j->len, &req, &bad);
    if (st != TG_OK) {
        char why[48];
        snprintf(why, sizeof(why), "%s:%s", tg_status_str(st), bad ? bad : "-");
        atomic_fetch_add(&STATS.bad_format, 1);
        guard_violation(j->ip, why);
        reply_post(j->conn_id, NULL, 0, 1);
        return;
    }

    merchant mc;
    if (!find_merchant(req.merchant_id, &mc)) {
        atomic_fetch_add(&STATS.unknown_merchant, 1);
        guard_violation(j->ip, "unknown_merchant");
        tg_msg r;
        tg_make_reply(&req, &r, strcmp(req.msg_type, TG_CANCEL_REQ) == 0 ? TG_CANCEL_RESP : TG_APPROVE_RESP,
                      RC_UNKNOWN_MERCHANT);
        reply(j, &r, NULL, 1);
        return;
    }
    if (tg_verify_mac(j->data, j->len, mc.key, (size_t)mc.key_len) != TG_OK) {
        atomic_fetch_add(&STATS.bad_mac, 1);
        guard_violation(j->ip, "bad_mac");
        sec_event_post(j->ip, "BAD_MAC", req.merchant_id, req.msg_type);
        tg_msg r;
        tg_make_reply(&req, &r, strcmp(req.msg_type, TG_CANCEL_REQ) == 0 ? TG_CANCEL_RESP : TG_APPROVE_RESP,
                      RC_BAD_MAC);
        reply(j, &r, &mc, 1);
        return;
    }
    if (!mc.active) {
        sec_event_post(j->ip, "MERCHANT_SUSPENDED", req.merchant_id, req.msg_type);
        tg_msg r;
        tg_make_reply(&req, &r, strcmp(req.msg_type, TG_CANCEL_REQ) == 0 ? TG_CANCEL_RESP : TG_APPROVE_RESP,
                      RC_UNKNOWN_MERCHANT);
        reply(j, &r, &mc, 0);
        return;
    }
    if (strcmp(req.msg_type, TG_ECHO_REQ) == 0) {
        tg_msg r;
        tg_make_reply(&req, &r, TG_ECHO_RESP, RC_OK);
        reply(j, &r, &mc, 0);
        return;
    }
    if (!take_token(req.merchant_id)) {
        atomic_fetch_add(&STATS.rate_limited, 1);
        sec_event_post(j->ip, "RATE_LIMITED", req.merchant_id, req.msg_type);
        tg_msg r;
        tg_make_reply(&req, &r, strcmp(req.msg_type, TG_CANCEL_REQ) == 0 ? TG_CANCEL_RESP : TG_APPROVE_RESP,
                      RC_RATE_LIMITED);
        reply(j, &r, &mc, 0);
        return;
    }
    if (strcmp(req.msg_type, TG_APPROVE_REQ) == 0) {
        approve(w, j, &req, &mc);
    } else if (strcmp(req.msg_type, TG_CANCEL_REQ) == 0) {
        cancel(w, j, &req, &mc);
    } else {
        /* Response types or reversals are not something a merchant may send. */
        atomic_fetch_add(&STATS.bad_format, 1);
        guard_violation(j->ip, "unexpected_type");
        reply_post(j->conn_id, NULL, 0, 1);
    }
}

void *worker_main(void *arg) {
    worker w = { .id = (int)(long)arg };
    mysql_thread_init();
    if (store_open(&w.db) != 0) {
        LOG_ERR("worker", "event=db_unavailable worker=%d", w.id);
        return NULL;
    }
    LOG_INFO("worker", "event=ready worker=%d", w.id);

    gw_job *j = malloc(sizeof(gw_job));
    for (;;) {
        jobq_pop(j);
        if (w.id == 0 && (atomic_exchange(&MERCHANT_RELOAD, 0) || now_ms() - merchants_loaded_ms > 30000)) {
            reload_merchants(&w.db);
        }
        process(&w, j);
    }
}
