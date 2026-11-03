#include "card.h"

#include <ctype.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>

int card_luhn_valid(const char *pan) {
    size_t n = strlen(pan);
    if (n < 13 || n > 19) return 0;
    int sum = 0;
    int dbl = 0;
    for (size_t i = n; i-- > 0;) {
        if (!isdigit((unsigned char)pan[i])) return 0;
        int d = pan[i] - '0';
        if (dbl) {
            d *= 2;
            if (d > 9) d -= 9;
        }
        sum += d;
        dbl = !dbl;
    }
    return sum % 10 == 0;
}

void card_mask(const char *pan, char out[20]) {
    size_t n = strlen(pan);
    if (n < 10 || n > 19) {
        strcpy(out, "****");
        return;
    }
    memcpy(out, pan, 6);
    memset(out + 6, '*', n - 10);
    memcpy(out + n - 4, pan + n - 4, 4);
    out[n] = '\0';
}

void card_token(const uint8_t *key, size_t key_len, const char *pan, char out[65]) {
    unsigned char d[EVP_MAX_MD_SIZE];
    unsigned int dl = 0;
    HMAC(EVP_sha256(), key, (int)key_len, (const unsigned char *)pan, strlen(pan), d, &dl);
    static const char hex[] = "0123456789abcdef";
    for (unsigned i = 0; i < 32; i++) {
        out[i * 2] = hex[d[i] >> 4];
        out[i * 2 + 1] = hex[d[i] & 0x0f];
    }
    out[64] = '\0';
}

int card_expiry_ok(const char *yymm, const char *now_yymm) {
    if (strlen(yymm) != 4 || strlen(now_yymm) != 4) return 0;
    int mm = (yymm[2] - '0') * 10 + (yymm[3] - '0');
    if (mm < 1 || mm > 12) return 0;
    return strncmp(yymm, now_yymm, 4) >= 0;
}
