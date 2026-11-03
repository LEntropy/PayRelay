/* Card number handling: validation, masking and a non-reversible token for storage. */
#ifndef PAYRELAY_CARD_H
#define PAYRELAY_CARD_H

#include <stddef.h>
#include <stdint.h>

/* Luhn (mod 10) check digit validation of a 13-19 digit card number. */
int card_luhn_valid(const char *pan);

/* "4111111111111111" -> "411111******1111" (first 6 / last 4 kept, as PCI DSS allows). */
void card_mask(const char *pan, char out[20]);

/*
 * HMAC-SHA256 of the card number under a dedicated key, as 64 hex chars. Lets the gateway
 * recognise the same card again (fraud checks, refunds) without storing the number.
 */
void card_token(const uint8_t *key, size_t key_len, const char *pan, char out[65]);

/* YYMM expiry not before the given YYMM (both 4 digits). */
int card_expiry_ok(const char *yymm, const char *now_yymm);

#endif
