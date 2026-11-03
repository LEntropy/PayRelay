#include "telegram.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

typedef enum { F_TEXT, F_DIGITS, F_ALNUM } field_kind;

typedef struct {
    const char *name;
    size_t offset;   /* offset of the char[] member in tg_msg, or (size_t)-1 for amount */
    int width;
    field_kind kind;
} field_def;

#define FLD(member, w, k) { #member, offsetof(tg_msg, member), (w), (k) }
#define AMOUNT_FLD(w) { "amount", (size_t)-1, (w), F_DIGITS }

static const field_def HEADER[] = {
    FLD(msg_type, 4, F_DIGITS),     FLD(version, 2, F_DIGITS),
    FLD(merchant_id, 10, F_ALNUM),  FLD(terminal_id, 8, F_ALNUM),
    FLD(trace_no, 6, F_DIGITS),     FLD(tx_datetime, 14, F_DIGITS),
    FLD(resp_code, 4, F_DIGITS),
};

static const field_def APPROVE_REQ[] = {
    FLD(order_no, 20, F_ALNUM), FLD(card_no, 19, F_DIGITS), FLD(expiry, 4, F_DIGITS),
    AMOUNT_FLD(12),             FLD(installment, 2, F_DIGITS), FLD(currency, 3, F_ALNUM),
};
static const field_def APPROVE_RESP[] = {
    FLD(order_no, 20, F_ALNUM), FLD(pg_tx_id, 20, F_ALNUM), FLD(approval_no, 8, F_ALNUM),
    AMOUNT_FLD(12),             FLD(card_masked, 19, F_TEXT),
};
static const field_def CANCEL_REQ[] = {
    FLD(order_no, 20, F_ALNUM), FLD(pg_tx_id, 20, F_ALNUM), AMOUNT_FLD(12), FLD(reason, 2, F_DIGITS),
};
static const field_def CANCEL_RESP[] = {
    FLD(order_no, 20, F_ALNUM), FLD(pg_tx_id, 20, F_ALNUM), AMOUNT_FLD(12), FLD(approval_no, 8, F_ALNUM),
};

typedef struct {
    const char *type;
    const field_def *fields;
    size_t count;
} body_def;

#define BODY(t, arr) { t, arr, sizeof(arr) / sizeof(arr[0]) }

static const body_def BODIES[] = {
    BODY(TG_APPROVE_REQ, APPROVE_REQ), BODY(TG_APPROVE_RESP, APPROVE_RESP),
    BODY(TG_CANCEL_REQ, CANCEL_REQ),   BODY(TG_CANCEL_RESP, CANCEL_RESP),
    BODY(TG_REVERSE_REQ, CANCEL_REQ),  BODY(TG_REVERSE_RESP, CANCEL_RESP),
    { TG_ECHO_REQ, NULL, 0 },          { TG_ECHO_RESP, NULL, 0 },
};

const char *tg_status_str(tg_status s) {
    switch (s) {
    case TG_OK: return "ok";
    case TG_E_INCOMPLETE: return "incomplete";
    case TG_E_LENGTH: return "bad_length";
    case TG_E_TYPE: return "unknown_type";
    case TG_E_FIELD: return "bad_field";
    case TG_E_MAC: return "bad_mac";
    case TG_E_SPACE: return "no_space";
    }
    return "unknown";
}

static const body_def *find_body(const char *type) {
    for (size_t i = 0; i < sizeof(BODIES) / sizeof(BODIES[0]); i++) {
        if (memcmp(BODIES[i].type, type, 4) == 0) return &BODIES[i];
    }
    return NULL;
}

static int fields_width(const field_def *f, size_t n) {
    int w = 0;
    for (size_t i = 0; i < n; i++) w += f[i].width;
    return w;
}

int tg_body_len(const char *msg_type) {
    const body_def *b = find_body(msg_type);
    return b ? fields_width(b->fields, b->count) : -1;
}

tg_status tg_frame_length(const char *buf, size_t avail, size_t *frame_len) {
    if (avail < TG_LEN_DIGITS) return TG_E_INCOMPLETE;
    size_t n = 0;
    for (int i = 0; i < TG_LEN_DIGITS; i++) {
        if (!isdigit((unsigned char)buf[i])) return TG_E_LENGTH;
        n = n * 10 + (size_t)(buf[i] - '0');
    }
    if (n < TG_HEADER_LEN + TG_MAC_LEN || n + TG_LEN_DIGITS > TG_MAX_FRAME) return TG_E_LENGTH;
    *frame_len = n + TG_LEN_DIGITS;
    return TG_OK;
}

static int valid_char(char c, field_kind k) {
    unsigned char u = (unsigned char)c;
    switch (k) {
    case F_DIGITS: return isdigit(u) || c == ' ';
    case F_ALNUM: return isalnum(u) || c == ' ' || c == '-' || c == '_';
    case F_TEXT: return u >= 0x20 && u < 0x7f;
    }
    return 0;
}

/* Copies a fixed-width field into a NUL-terminated member, dropping trailing padding. */
static tg_status read_fields(const char *p, const field_def *f, size_t n, tg_msg *m, const char **bad) {
    for (size_t i = 0; i < n; i++) {
        int w = f[i].width;
        for (int j = 0; j < w; j++) {
            if (!valid_char(p[j], f[i].kind)) {
                if (bad) *bad = f[i].name;
                return TG_E_FIELD;
            }
        }
        if (f[i].offset == (size_t)-1) {
            long long v = 0;
            for (int j = 0; j < w; j++) {
                if (!isdigit((unsigned char)p[j])) {
                    if (bad) *bad = f[i].name;
                    return TG_E_FIELD;
                }
                v = v * 10 + (p[j] - '0');
            }
            m->amount = v;
        } else {
            char *dst = (char *)m + f[i].offset;
            int len = w;
            while (len > 0 && p[len - 1] == ' ') len--;
            memcpy(dst, p, (size_t)len);
            dst[len] = '\0';
        }
        p += w;
    }
    return TG_OK;
}

static int write_fields(char *p, const field_def *f, size_t n, const tg_msg *m) {
    for (size_t i = 0; i < n; i++) {
        int w = f[i].width;
        if (f[i].offset == (size_t)-1) {
            if (m->amount < 0) return -1;
            char tmp[32];
            int len = snprintf(tmp, sizeof(tmp), "%0*lld", w, m->amount);
            if (len != w) return -1;   /* does not fit */
            memcpy(p, tmp, (size_t)w);
        } else {
            const char *src = (const char *)m + f[i].offset;
            size_t len = strlen(src);
            if (len > (size_t)w) return -1;
            /* numeric fields are zero padded on the left, text fields space padded on the right */
            if (f[i].kind == F_DIGITS && strcmp(f[i].name, "card_no") != 0) {
                memset(p, '0', (size_t)w);
                memcpy(p + (w - (int)len), src, len);
            } else {
                memset(p, ' ', (size_t)w);
                memcpy(p, src, len);
            }
        }
        p += w;
    }
    return 0;
}

static void compute_mac(const char *data, size_t len, const uint8_t *key, size_t key_len, char out[TG_MAC_LEN + 1]) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;
    HMAC(EVP_sha256(), key, (int)key_len, (const unsigned char *)data, len, digest, &dlen);
    static const char hex[] = "0123456789ABCDEF";
    for (int i = 0; i < TG_MAC_LEN / 2; i++) {
        out[i * 2] = hex[digest[i] >> 4];
        out[i * 2 + 1] = hex[digest[i] & 0x0f];
    }
    out[TG_MAC_LEN] = '\0';
}

tg_status tg_decode(const char *frame, size_t len, tg_msg *out, const char **bad_field) {
    size_t expected;
    tg_status st = tg_frame_length(frame, len, &expected);
    if (st != TG_OK) return st == TG_E_INCOMPLETE ? TG_E_LENGTH : st;
    if (expected != len) return TG_E_LENGTH;

    memset(out, 0, sizeof(*out));
    const char *p = frame + TG_LEN_DIGITS;
    st = read_fields(p, HEADER, sizeof(HEADER) / sizeof(HEADER[0]), out, bad_field);
    if (st != TG_OK) return st;

    const body_def *b = find_body(out->msg_type);
    if (!b) return TG_E_TYPE;
    int body_len = fields_width(b->fields, b->count);
    if (len != (size_t)(TG_LEN_DIGITS + TG_HEADER_LEN + body_len + TG_MAC_LEN)) return TG_E_LENGTH;

    st = read_fields(p + TG_HEADER_LEN, b->fields, b->count, out, bad_field);
    if (st != TG_OK) return st;

    const char *mac = p + TG_HEADER_LEN + body_len;
    for (int i = 0; i < TG_MAC_LEN; i++) {
        if (!isxdigit((unsigned char)mac[i])) {
            if (bad_field) *bad_field = "mac";
            return TG_E_FIELD;
        }
    }
    memcpy(out->mac, mac, TG_MAC_LEN);
    out->mac[TG_MAC_LEN] = '\0';
    return TG_OK;
}

tg_status tg_verify_mac(const char *frame, size_t len, const uint8_t *key, size_t key_len) {
    if (len < TG_LEN_DIGITS + TG_HEADER_LEN + TG_MAC_LEN) return TG_E_LENGTH;
    char expected[TG_MAC_LEN + 1];
    size_t signed_len = len - TG_LEN_DIGITS - TG_MAC_LEN;
    compute_mac(frame + TG_LEN_DIGITS, signed_len, key, key_len, expected);
    /* CRYPTO_memcmp: no early exit, so timing does not reveal how many bytes matched */
    return CRYPTO_memcmp(expected, frame + len - TG_MAC_LEN, TG_MAC_LEN) == 0 ? TG_OK : TG_E_MAC;
}

int tg_encode(const tg_msg *m, const uint8_t *key, size_t key_len, char *out, size_t cap) {
    const body_def *b = find_body(m->msg_type);
    if (!b) return -1;
    int body_len = fields_width(b->fields, b->count);
    int total = TG_LEN_DIGITS + TG_HEADER_LEN + body_len + TG_MAC_LEN;
    if ((size_t)total > cap || total > TG_MAX_FRAME) return -1;

    char lenbuf[16];
    snprintf(lenbuf, sizeof(lenbuf), "%04d", total - TG_LEN_DIGITS);
    memcpy(out, lenbuf, TG_LEN_DIGITS);
    if (write_fields(out + TG_LEN_DIGITS, HEADER, sizeof(HEADER) / sizeof(HEADER[0]), m) != 0) return -1;
    if (write_fields(out + TG_LEN_DIGITS + TG_HEADER_LEN, b->fields, b->count, m) != 0) return -1;

    char mac[TG_MAC_LEN + 1];
    compute_mac(out + TG_LEN_DIGITS, (size_t)(TG_HEADER_LEN + body_len), key, key_len, mac);
    memcpy(out + total - TG_MAC_LEN, mac, TG_MAC_LEN);
    return total;
}

void tg_make_reply(const tg_msg *req, tg_msg *resp, const char *resp_type, const char *resp_code) {
    memset(resp, 0, sizeof(*resp));
    memcpy(resp->msg_type, resp_type, 4);
    memcpy(resp->version, req->version[0] ? req->version : "01", 2);
    strcpy(resp->merchant_id, req->merchant_id);
    strcpy(resp->terminal_id, req->terminal_id);
    strcpy(resp->trace_no, req->trace_no);
    strcpy(resp->tx_datetime, req->tx_datetime);
    memcpy(resp->resp_code, resp_code, 4);
    strcpy(resp->order_no, req->order_no);
    strcpy(resp->pg_tx_id, req->pg_tx_id);
    resp->amount = req->amount;
}
