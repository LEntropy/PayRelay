/*
 * PayRelay PG gateway.
 *
 *   merchant POS --TCP telegram--> [reactor (epoll)] --jobs--> [worker pool] --mTLS--> VAN
 *                                        ^                         |  MySQL
 *                                        +------- replies ---------+
 */
#include "gateway.h"
#include "store.h"
#include "tlsio.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ssl.h>

gw_config CFG;
gw_stats STATS;
extern SSL_CTX *VAN_CTX;
void reload_merchants(store *s);

static int load_key(const char *env, uint8_t *out, int *len) {
    *len = hex_decode(env_or(env, ""), out, 64);
    if (*len < 16) {
        LOG_ERR("main", "event=config_error reason=\"%s must be at least 16 bytes of hex\"", env);
        return -1;
    }
    return 0;
}

static int load_config(void) {
    CFG.listen_port = env_int("GW_PORT", 9100);
    CFG.control_port = env_int("GW_CONTROL_PORT", 9190);
    CFG.workers = env_int("GW_WORKERS", 8);
    CFG.max_conn_per_ip = env_int("GW_MAX_CONN_PER_IP", 50);
    CFG.frame_timeout_ms = env_int("GW_FRAME_TIMEOUT_MS", 5000);
    CFG.idle_timeout_ms = env_int("GW_IDLE_TIMEOUT_MS", 60000);
    CFG.van_timeout_ms = env_int("GW_VAN_TIMEOUT_MS", 3000);
    CFG.ban_threshold = env_int("GW_BAN_THRESHOLD", 5);
    CFG.ban_window_s = env_int("GW_BAN_WINDOW_S", 60);
    CFG.ban_seconds = env_int("GW_BAN_SECONDS", 600);
    CFG.ban_exempt = env_or("GW_BAN_EXEMPT", "127.0.0.1");
    CFG.db_host = env_or("DB_HOST", "mysql");
    CFG.db_port = env_int("DB_PORT", 3306);
    CFG.db_user = env_or("DB_USER", "gateway");
    CFG.db_pass = env_or("DB_PASSWORD", "");
    CFG.db_name = env_or("DB_NAME", "payrelay");
    CFG.van_host = env_or("VAN_HOST", "van");
    CFG.van_port = env_int("VAN_PORT", 9200);
    CFG.van_merchant_id = env_or("VAN_MERCHANT_ID", "PAYRELAY01");
    CFG.cert = env_or("GW_CERT", "/certs/gateway.crt");
    CFG.key = env_or("GW_KEY", "/certs/gateway.key");
    CFG.ca = env_or("TLS_CA", "/certs/ca.crt");
    if (CFG.workers < 1 || CFG.workers > 64) CFG.workers = 8;
    if (load_key("VAN_MAC_KEY", CFG.van_key, &CFG.van_key_len) != 0) return -1;
    if (load_key("CARD_TOKEN_KEY", CFG.token_key, &CFG.token_key_len) != 0) return -1;
    return 0;
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    if (load_config() != 0) return 1;
    if (mysql_library_init(0, NULL, NULL) != 0) return 1;

    VAN_CTX = tls_client_ctx(CFG.cert, CFG.key, CFG.ca);
    if (!VAN_CTX) {
        LOG_ERR("main", "event=tls_setup_failed reason=\"%s\"", tls_err());
        return 1;
    }

    /* Load merchants before accepting anything, so no request sees an empty cache. */
    store boot;
    if (store_open(&boot) != 0) {
        LOG_ERR("main", "event=db_unavailable");
        return 1;
    }
    reload_merchants(&boot);
    store_close(&boot);

    guard_init();
    pthread_t th;
    pthread_create(&th, NULL, sec_writer_main, NULL);
    for (int i = 0; i < CFG.workers; i++) pthread_create(&th, NULL, worker_main, (void *)(long)i);
    pthread_create(&th, NULL, control_main, NULL);

    LOG_INFO("main", "event=starting workers=%d van=%s:%d van_timeout_ms=%d ban_threshold=%d", CFG.workers,
             CFG.van_host, CFG.van_port, CFG.van_timeout_ms, CFG.ban_threshold);
    return reactor_run() == 0 ? 0 : 1;
}
