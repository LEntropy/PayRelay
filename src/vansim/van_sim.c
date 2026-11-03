/*
 * VAN / card issuer simulator.
 *
 * Plays the other side of the PG gateway's upstream link: accepts mutual-TLS connections,
 * answers approval, cancel, reversal and echo telegrams, keeps its own ledger, and appends
 * every booked transaction to a daily settlement file that the PG reconciles against.
 *
 * Behaviour is chosen by test card numbers and amounts so every scenario is repeatable:
 *   4000000000000002  -> 2001 insufficient funds       4000000000000069 -> 2003 expired card
 *   4000000000000119  -> 2004 lost/stolen card          amount > 1,000,000 -> 2001 over limit
 *   amount ending 777 -> approve, but only after VAN_DELAY_MS (PG times out and reverses)
 *   amount ending 888 -> like 777, and the reversal is "lost" (never answered), so the
 *                        PG cannot confirm it: reconciliation must catch this one
 */
#include "telegram.h"
#include "tlsio.h"
#include "util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_TX 65536

typedef enum { ST_APPROVED = 1, ST_CANCELED, ST_REVERSED } van_state;

typedef struct {
    char pg_tx_id[21];
    long long amount;
    char approval_no[9];
    van_state state;
} van_tx;

static van_tx ledger[MAX_TX];
static int ledger_n;
static pthread_mutex_t ledger_lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned long approval_seq = 10000000;

static SSL_CTX *ctx;
static uint8_t mac_key[64];
static int mac_key_len;
static int delay_ms;
static const char *settle_dir;

static van_tx *find_tx(const char *pg_tx_id) {
    for (int i = 0; i < ledger_n; i++) {
        if (strcmp(ledger[i].pg_tx_id, pg_tx_id) == 0) return &ledger[i];
    }
    return NULL;
}

/* One line per booking: TYPE|PG_TX_ID|AMOUNT|APPROVAL_NO|YYYYMMDDhhmmss */
static void settle(char type, const van_tx *t) {
    char now[15], path[512];
    now_datetime14(now);
    snprintf(path, sizeof(path), "%s/VAN_%.8s.txt", settle_dir, now);
    FILE *f = fopen(path, "a");
    if (!f) {
        LOG_ERR("van", "event=settle_write_failed path=%s errno=%d", path, errno);
        return;
    }
    fprintf(f, "%c|%s|%lld|%s|%s\n", type, t->pg_tx_id, t->amount, t->approval_no, now);
    fclose(f);
}

static void next_approval(char out[9]) {
    snprintf(out, 9, "%08lu", approval_seq++ % 100000000UL);
}

/* Returns 0 to send `resp`, 1 to send nothing (simulated lost message). */
static int handle(const tg_msg *req, tg_msg *resp) {
    if (strcmp(req->msg_type, TG_ECHO_REQ) == 0) {
        tg_make_reply(req, resp, TG_ECHO_RESP, RC_OK);
        return 0;
    }

    if (strcmp(req->msg_type, TG_APPROVE_REQ) == 0) {
        const char *rc = RC_OK;
        if (strcmp(req->card_no, "4000000000000002") == 0 || req->amount > 1000000) rc = RC_INSUFFICIENT;
        else if (strcmp(req->card_no, "4000000000000069") == 0) rc = RC_EXPIRED;
        else if (strcmp(req->card_no, "4000000000000119") == 0) rc = RC_LOST_CARD;

        if (req->amount % 1000 == 777 || req->amount % 1000 == 888) {
            LOG_INFO("van", "event=slow_issuer pg_tx_id=%s delay_ms=%d", req->order_no, delay_ms);
            usleep((useconds_t)delay_ms * 1000);
        }
        tg_make_reply(req, resp, TG_APPROVE_RESP, rc);
        /* upstream order_no carries the PG transaction id */
        strcpy(resp->pg_tx_id, req->order_no);
        if (strcmp(rc, RC_OK) == 0) {
            pthread_mutex_lock(&ledger_lock);
            van_tx *t = find_tx(req->order_no);
            if (t && t->state == ST_REVERSED) {
                /* The reversal overtook this (late) original: never book it. */
                memcpy(resp->resp_code, RC_ALREADY_CANCELED, 4);
                pthread_mutex_unlock(&ledger_lock);
                LOG_WARN("van", "event=late_original_after_reversal pg_tx_id=%s booked=no", req->order_no);
                return 0;
            }
            if (!t && ledger_n < MAX_TX) {
                t = &ledger[ledger_n++];
                strcpy(t->pg_tx_id, req->order_no);
                t->amount = req->amount;
                next_approval(t->approval_no);
                t->state = ST_APPROVED;
                settle('A', t);
            }
            if (t) strcpy(resp->approval_no, t->approval_no);
            pthread_mutex_unlock(&ledger_lock);
        }
        LOG_INFO("van", "event=approve pg_tx_id=%s amount=%lld rc=%s", req->order_no, req->amount, rc);
        return 0;
    }

    if (strcmp(req->msg_type, TG_CANCEL_REQ) == 0 || strcmp(req->msg_type, TG_REVERSE_REQ) == 0) {
        int reversal = strcmp(req->msg_type, TG_REVERSE_REQ) == 0;
        const char *rc = RC_OK;
        pthread_mutex_lock(&ledger_lock);
        van_tx *t = find_tx(req->pg_tx_id);
        if (reversal && req->amount % 1000 == 888) {
            pthread_mutex_unlock(&ledger_lock);
            LOG_WARN("van", "event=reversal_lost pg_tx_id=%s (simulated)", req->pg_tx_id);
            return 1;
        }
        if (!t && reversal) {
            /*
             * Reversal before (or instead of) the original: remember it, so that an original
             * still in flight is refused when it arrives. Answering OK is safe either way.
             */
            if (ledger_n < MAX_TX) {
                t = &ledger[ledger_n++];
                strcpy(t->pg_tx_id, req->pg_tx_id);
                t->amount = req->amount;
                strcpy(t->approval_no, "00000000");
                t->state = ST_REVERSED;
            }
            rc = RC_OK;
        } else if (!t) {
            rc = RC_NO_ORIGINAL;
        } else if (t->state != ST_APPROVED) {
            rc = reversal ? RC_OK : RC_ALREADY_CANCELED;
        } else if (t->amount != req->amount) {
            rc = RC_AMOUNT_MISMATCH;
        } else {
            t->state = reversal ? ST_REVERSED : ST_CANCELED;
            settle(reversal ? 'R' : 'C', t);
        }
        tg_make_reply(req, resp, reversal ? TG_REVERSE_RESP : TG_CANCEL_RESP, rc);
        if (t) strcpy(resp->approval_no, t->approval_no);
        pthread_mutex_unlock(&ledger_lock);
        LOG_INFO("van", "event=%s pg_tx_id=%s rc=%s", reversal ? "reverse" : "cancel", req->pg_tx_id, rc);
        return 0;
    }

    tg_make_reply(req, resp, TG_ECHO_RESP, RC_BAD_FORMAT);
    return 0;
}

static void *serve(void *arg) {
    int fd = (int)(long)arg;
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    if (SSL_accept(ssl) != 1) {
        LOG_WARN("van", "event=tls_rejected reason=\"%s\"", tls_err());
        goto done;
    }
    X509 *peer = SSL_get_peer_certificate(ssl);
    char cn[128] = "?";
    if (peer) {
        X509_NAME_get_text_by_NID(X509_get_subject_name(peer), NID_commonName, cn, sizeof(cn));
        X509_free(peer);
    }
    LOG_INFO("van", "event=connected peer_cn=%s", cn);

    char buf[TG_MAX_FRAME], out[TG_MAX_FRAME];
    for (;;) {
        int n = tls_read_frame(ssl, buf, sizeof(buf));
        if (n <= 0) break;
        tg_msg req, resp;
        const char *bad = NULL;
        if (tg_decode(buf, (size_t)n, &req, &bad) != TG_OK ||
            tg_verify_mac(buf, (size_t)n, mac_key, (size_t)mac_key_len) != TG_OK) {
            LOG_WARN("van", "event=bad_telegram field=%s", bad ? bad : "mac");
            break;
        }
        if (handle(&req, &resp) != 0) continue;
        int len = tg_encode(&resp, mac_key, (size_t)mac_key_len, out, sizeof(out));
        if (len < 0 || tls_write_all(ssl, out, (size_t)len) != 0) break;
    }
done:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(fd);
    return NULL;
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    int port = env_int("VAN_PORT", 9200);
    delay_ms = env_int("VAN_DELAY_MS", 5000);
    settle_dir = env_or("VAN_SETTLE_DIR", "/data/settle");
    mkdir(settle_dir, 0755);
    mac_key_len = hex_decode(env_or("VAN_MAC_KEY", ""), mac_key, sizeof(mac_key));
    if (mac_key_len < 16) {
        LOG_ERR("van", "event=config_error reason=\"VAN_MAC_KEY must be at least 16 bytes of hex\"");
        return 1;
    }
    ctx = tls_server_ctx(env_or("VAN_CERT", "/certs/van.crt"), env_or("VAN_KEY", "/certs/van.key"),
                         env_or("TLS_CA", "/certs/ca.crt"));
    if (!ctx) {
        LOG_ERR("van", "event=tls_setup_failed reason=\"%s\"", tls_err());
        return 1;
    }

    int ls = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons((uint16_t)port), .sin_addr.s_addr = INADDR_ANY };
    if (bind(ls, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(ls, 128) != 0) {
        LOG_ERR("van", "event=listen_failed port=%d errno=%d", port, errno);
        return 1;
    }
    LOG_INFO("van", "event=listening port=%d delay_ms=%d settle_dir=%s", port, delay_ms, settle_dir);

    for (;;) {
        int fd = accept(ls, NULL, NULL);
        if (fd < 0) continue;
        pthread_t th;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&th, &attr, serve, (void *)(long)fd) != 0) close(fd);
        pthread_attr_destroy(&attr);
    }
}
