/*
 * Fixed-length payment telegram (전문) codec.
 *
 * Frame on the wire (all ASCII):
 *
 *   LEN(4) | HEADER(48) | BODY(depends on msg_type) | MAC(32)
 *
 *   LEN     decimal byte count of everything after LEN, zero padded ("0172")
 *   HEADER  msg_type(4) version(2) merchant_id(10) terminal_id(8) trace_no(6)
 *           tx_datetime(14, YYYYMMDDhhmmss) resp_code(4)
 *   MAC     first 16 bytes of HMAC-SHA256(key, HEADER || BODY), upper-case hex
 *
 * Text fields are left-justified and space padded, numeric fields are right-justified
 * and zero padded, the same conventions Korean VAN/PG telegrams use.
 */
#ifndef PAYRELAY_TELEGRAM_H
#define PAYRELAY_TELEGRAM_H

#include <stddef.h>
#include <stdint.h>

#define TG_LEN_DIGITS   4
#define TG_HEADER_LEN   48
#define TG_MAC_LEN      32
#define TG_MAX_FRAME    512

/* Message types */
#define TG_APPROVE_REQ  "0200"
#define TG_APPROVE_RESP "0210"
#define TG_CANCEL_REQ   "0400"
#define TG_CANCEL_RESP  "0410"
#define TG_REVERSE_REQ  "0420"   /* 망취소: undo a transaction whose result is unknown */
#define TG_REVERSE_RESP "0430"
#define TG_ECHO_REQ     "0800"   /* 망관리: link check */
#define TG_ECHO_RESP    "0810"

/* Response codes (header resp_code) */
#define RC_OK               "0000"
#define RC_BAD_MAC          "1001"
#define RC_BAD_FORMAT       "1002"
#define RC_UNKNOWN_MERCHANT "1003"
#define RC_IN_PROGRESS      "1004"
#define RC_INSUFFICIENT     "2001"
#define RC_BAD_CARD         "2002"
#define RC_EXPIRED          "2003"
#define RC_LOST_CARD        "2004"
#define RC_NO_ORIGINAL      "3001"
#define RC_ALREADY_CANCELED "3002"
#define RC_AMOUNT_MISMATCH  "3003"
#define RC_VAN_TIMEOUT      "9001"
#define RC_VAN_UNAVAILABLE  "9002"
#define RC_RATE_LIMITED     "9003"
#define RC_SYSTEM           "9999"

typedef struct {
    /* header */
    char msg_type[5];
    char version[3];
    char merchant_id[11];
    char terminal_id[9];
    char trace_no[7];
    char tx_datetime[15];
    char resp_code[5];
    /* body (which fields are used depends on msg_type) */
    char order_no[21];
    char card_no[20];
    char expiry[5];       /* YYMM */
    char installment[3];
    char currency[4];
    char pg_tx_id[21];
    char approval_no[9];
    char card_masked[20];
    char reason[3];
    long long amount;
    /* trailer */
    char mac[TG_MAC_LEN + 1];
} tg_msg;

typedef enum {
    TG_OK = 0,
    TG_E_INCOMPLETE,   /* need more bytes */
    TG_E_LENGTH,       /* LEN not digits, too small/large, or wrong for the type */
    TG_E_TYPE,         /* unknown msg_type */
    TG_E_FIELD,        /* a field has characters it may not contain */
    TG_E_MAC,          /* MAC mismatch */
    TG_E_SPACE         /* output buffer too small */
} tg_status;

const char *tg_status_str(tg_status s);

/* Body length for a message type, or -1 if the type is unknown. */
int tg_body_len(const char *msg_type);

/*
 * Inspects the start of a receive buffer. Returns TG_OK and sets *frame_len to the full
 * frame size (LEN prefix included) once LEN is readable and plausible, TG_E_INCOMPLETE
 * if fewer than 4 bytes are buffered, TG_E_LENGTH for a malformed or oversized LEN.
 */
tg_status tg_frame_length(const char *buf, size_t avail, size_t *frame_len);

/* Parses a complete frame. Does not check the MAC (the key depends on merchant_id). */
tg_status tg_decode(const char *frame, size_t len, tg_msg *out, const char **bad_field);

/* Recomputes the MAC of a complete frame and compares it in constant time. */
tg_status tg_verify_mac(const char *frame, size_t len, const uint8_t *key, size_t key_len);

/* Builds a frame (LEN prefix included) and fills in the MAC. Returns its length or -1. */
int tg_encode(const tg_msg *m, const uint8_t *key, size_t key_len, char *out, size_t cap);

/* Fills header fields of a response from its request (same merchant, terminal, trace). */
void tg_make_reply(const tg_msg *req, tg_msg *resp, const char *resp_type, const char *resp_code);

#endif
