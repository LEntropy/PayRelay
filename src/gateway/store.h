/*
 * MySQL access. Every statement is a prepared statement with bound parameters: request
 * fields never become part of SQL text. One `store` (connection) per worker thread.
 */
#ifndef PAYRELAY_STORE_H
#define PAYRELAY_STORE_H

#include <mysql.h>

typedef struct {
    MYSQL *db;
} store;

typedef struct {
    char pg_tx_id[21];
    char merchant_id[11];
    char order_no[21];
    char terminal_id[9];
    char trace_no[7];
    long long amount;
    char currency[4];
    int installment;
    char card_bin[7];
    char card_last4[5];
    char card_token[65];
    char status[16];
    char resp_code[5];
    char approval_no[9];
    char cancel_approval[9];
    char client_ip[46];
} tx_rec;

int  store_open(store *s);
void store_close(store *s);

/* Calls fn(id, key_hex, active, tps, ctx) for every merchant. */
int store_load_merchants(store *s, void (*fn)(const char *, const char *, int, int, void *), void *ctx);

/* 0 inserted, 1 duplicate (merchant_id, order_no), -1 error. */
int store_insert_tx(store *s, const tx_rec *t);

/* 0 found, 1 not found, -1 error. for_update locks the row (call inside store_begin). */
int store_get_by_order(store *s, const char *merchant_id, const char *order_no, tx_rec *out, int for_update);

/*
 * Moves a transaction from one status to another only if it is still in `from`
 * (a compare-and-set, so two threads cannot both finish the same transaction).
 * Returns affected rows (1 or 0), -1 on error. approval_no may be NULL.
 */
int store_transition(store *s, const char *pg_tx_id, const char *from, const char *to, const char *resp_code,
                     const char *approval_no, int van_latency_ms);
int store_mark_canceled(store *s, const char *pg_tx_id, const char *cancel_approval);

int store_begin(store *s);
int store_commit(store *s);
int store_rollback(store *s);

int store_event(store *s, const char *pg_tx_id, const char *event, const char *detail);

/* Security events are queued and written by a background thread (safe from any thread). */
void sec_event_post(const char *ip, const char *event, const char *merchant_id, const char *detail);
void *sec_writer_main(void *arg);

#endif
