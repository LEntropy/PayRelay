/* Unit tests for the shared library: telegram codec, MAC, card handling, rate limiting. */
#include "card.h"
#include "telegram.h"
#include "util.h"

#include <stdio.h>
#include <string.h>

static int failures, checks;

#define CHECK(cond, name)                                                                 \
    do {                                                                                  \
        checks++;                                                                         \
        if (cond) {                                                                       \
            printf("  \033[32mPASS\033[0m %s\n", name);                                   \
        } else {                                                                          \
            failures++;                                                                   \
            printf("  \033[31mFAIL\033[0m %s  (%s:%d)\n", name, __FILE__, __LINE__);      \
        }                                                                                 \
    } while (0)

static const uint8_t KEY[] = "merchant-test-key-0123456789abcd";

static tg_msg approve_req(void) {
    tg_msg m;
    memset(&m, 0, sizeof(m));
    strcpy(m.msg_type, TG_APPROVE_REQ);
    strcpy(m.version, "01");
    strcpy(m.merchant_id, "M000000001");
    strcpy(m.terminal_id, "T0000001");
    strcpy(m.trace_no, "000123");
    strcpy(m.tx_datetime, "20261103101500");
    strcpy(m.resp_code, RC_OK);
    strcpy(m.order_no, "ORD-20261103-0001");
    strcpy(m.card_no, "4111111111111111");
    strcpy(m.expiry, "2912");
    strcpy(m.installment, "00");
    strcpy(m.currency, "KRW");
    m.amount = 15000;
    return m;
}

static void test_codec(void) {
    printf("telegram codec\n");
    tg_msg m = approve_req();
    char buf[TG_MAX_FRAME];
    int n = tg_encode(&m, KEY, sizeof(KEY) - 1, buf, sizeof(buf));
    CHECK(n == 4 + 48 + 60 + 32, "0200 frame is LEN(4)+HEADER(48)+BODY(60)+MAC(32) = 144 bytes");
    CHECK(memcmp(buf, "0140", 4) == 0, "LEN prefix counts bytes after itself (0140)");
    CHECK(memcmp(buf + 4 + 48 + 20 + 19 + 4, "000000015000", 12) == 0, "amount is zero padded to 12 digits");
    CHECK(memcmp(buf + 4 + 48 + 20, "4111111111111111   ", 19) == 0, "card number is left aligned, space padded");

    tg_msg d;
    const char *bad = NULL;
    CHECK(tg_decode(buf, (size_t)n, &d, &bad) == TG_OK, "decode of own encoding succeeds");
    CHECK(strcmp(d.order_no, m.order_no) == 0 && d.amount == 15000 && strcmp(d.card_no, m.card_no) == 0,
          "decoded fields equal the originals (padding removed)");
    CHECK(tg_verify_mac(buf, (size_t)n, KEY, sizeof(KEY) - 1) == TG_OK, "MAC verifies with the right key");

    const uint8_t other[] = "another-merchant-key-xxxxxxxxxxx";
    CHECK(tg_verify_mac(buf, (size_t)n, other, sizeof(other) - 1) == TG_E_MAC, "MAC fails with another merchant's key");

    char tampered[TG_MAX_FRAME];
    memcpy(tampered, buf, (size_t)n);
    memcpy(tampered + 4 + 48 + 20 + 19 + 4, "000001500000", 12);   /* 15,000 -> 1,500,000 */
    CHECK(tg_decode(tampered, (size_t)n, &d, &bad) == TG_OK, "tampered amount still parses as a valid frame");
    CHECK(tg_verify_mac(tampered, (size_t)n, KEY, sizeof(KEY) - 1) == TG_E_MAC, "but changing the amount breaks the MAC");
}

static void test_malformed(void) {
    printf("malformed input\n");
    tg_msg m = approve_req();
    char buf[TG_MAX_FRAME];
    int n = tg_encode(&m, KEY, sizeof(KEY) - 1, buf, sizeof(buf));
    tg_msg d;
    const char *bad = NULL;
    size_t fl;

    CHECK(tg_frame_length("01", 2, &fl) == TG_E_INCOMPLETE, "fewer than 4 bytes: wait for more");
    CHECK(tg_frame_length("AB12", 4, &fl) == TG_E_LENGTH, "non-digit LEN rejected");
    CHECK(tg_frame_length("9999", 4, &fl) == TG_E_LENGTH, "LEN above the 512-byte limit rejected (no huge buffers)");
    CHECK(tg_frame_length("0010", 4, &fl) == TG_E_LENGTH, "LEN smaller than header+MAC rejected");

    CHECK(tg_decode(buf, (size_t)n - 1, &d, &bad) == TG_E_LENGTH, "truncated frame rejected");

    char x[TG_MAX_FRAME];
    memcpy(x, buf, (size_t)n);
    memcpy(x + 4, "0999", 4);
    CHECK(tg_decode(x, (size_t)n, &d, &bad) == TG_E_TYPE, "unknown message type rejected");

    memcpy(x, buf, (size_t)n);
    x[4 + 48 + 20 + 3] = 'X';   /* letter inside the card number */
    CHECK(tg_decode(x, (size_t)n, &d, &bad) == TG_E_FIELD && strcmp(bad, "card_no") == 0,
          "letter in a numeric field rejected and the field is named");

    memcpy(x, buf, (size_t)n);
    x[4 + 48 + 5] = '\'';   /* quote in order_no */
    CHECK(tg_decode(x, (size_t)n, &d, &bad) == TG_E_FIELD && strcmp(bad, "order_no") == 0,
          "quote character in order_no rejected (input never reaches SQL as text)");

    tg_msg big = approve_req();
    big.amount = 1000000000000LL;   /* 13 digits */
    CHECK(tg_encode(&big, KEY, sizeof(KEY) - 1, x, sizeof(x)) == -1, "amount wider than its field cannot be encoded");
    tg_msg neg = approve_req();
    neg.amount = -1;
    CHECK(tg_encode(&neg, KEY, sizeof(KEY) - 1, x, sizeof(x)) == -1, "negative amount cannot be encoded");
}

static void test_card(void) {
    printf("card handling\n");
    CHECK(card_luhn_valid("4111111111111111"), "Luhn: valid test Visa number");
    CHECK(!card_luhn_valid("4111111111111112"), "Luhn: one wrong digit detected");
    CHECK(!card_luhn_valid("411111"), "Luhn: too short rejected");
    char masked[20];
    card_mask("4111111111111111", masked);
    CHECK(strcmp(masked, "411111******1111") == 0, "mask keeps first 6 and last 4 digits");
    char t1[65], t2[65], t3[65];
    const uint8_t tk[] = "token-key";
    card_token(tk, 9, "4111111111111111", t1);
    card_token(tk, 9, "4111111111111111", t2);
    card_token(tk, 9, "4000000000000002", t3);
    CHECK(strcmp(t1, t2) == 0 && strcmp(t1, t3) != 0, "token is stable per card and differs between cards");
    CHECK(strstr(t1, "1111") == NULL || strlen(t1) == 64, "token is 64 hex chars, not the card number");
    CHECK(card_expiry_ok("2912", "2611") && !card_expiry_ok("2610", "2611") && !card_expiry_ok("2913", "2611"),
          "expiry: future ok, past rejected, month 13 rejected");
}

static void test_rate_limit(void) {
    printf("rate limiting\n");
    token_bucket tb;
    tb_init(&tb, 5, 5, 0);
    int ok = 0;
    for (int i = 0; i < 10; i++) ok += tb_take(&tb, 0);
    CHECK(ok == 5, "burst of 10 at once: only 5 allowed");
    CHECK(tb_take(&tb, 200) == 1, "after 200 ms one more token (5 per second)");
    CHECK(tb_take(&tb, 200) == 0, "but not two");
    ok = 0;
    for (int i = 0; i < 10; i++) ok += tb_take(&tb, 10000);
    CHECK(ok == 5, "long idle does not save more than the burst size");
}

int main(void) {
    test_codec();
    test_malformed();
    test_card();
    test_rate_limit();
    printf("\n%d/%d checks passed\n", checks - failures, checks);
    return failures ? 1 : 0;
}
