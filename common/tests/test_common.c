#include "endian.h"
#include "ntt.h"
#include "random.h"
#include "sha3.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int hex_equal(const uint8_t *buf, size_t len, const char *expected) {
    static const char hex[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < len; ++i) {
        if (hex[buf[i] >> 4] != expected[2 * i] ||
            hex[buf[i] & 0x0f] != expected[2 * i + 1]) {
            return 0;
        }
    }
    return 1;
}

static int test_sha3(void) {
    uint8_t out[64];
    crypto_sha3_ctx ctx;

    crypto_sha3_256(out, (const uint8_t *)"abc", 3);
    if (!hex_equal(out, 32,
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")) {
        return -1;
    }

    crypto_sha3_512(out, (const uint8_t *)"abc", 3);
    if (!hex_equal(out, 64,
        "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
        "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0")) {
        return -1;
    }

    crypto_shake128(out, 32, (const uint8_t *)"abc", 3);
    if (!hex_equal(out, 32,
        "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8")) {
        return -1;
    }

    crypto_shake256_init(&ctx);
    crypto_sha3_update(&ctx, (const uint8_t *)"a", 1);
    crypto_sha3_update(&ctx, (const uint8_t *)"bc", 2);
    crypto_sha3_finalize(&ctx);
    crypto_sha3_squeeze(&ctx, out, 32);
    crypto_sha3_squeeze(&ctx, out + 32, 32);
    crypto_sha3_clear(&ctx);
    if (!hex_equal(out, 64,
        "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"
        "d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4")) {
        return -1;
    }

    return 0;
}

static int test_endian(void) {
    uint8_t b[8];
    const uint64_t v = UINT64_C(0x0123456789abcdef);

    crypto_store64_be(b, v);
    if (crypto_load64_be(b) != v) return -1;
    crypto_store64_le(b, v);
    if (crypto_load64_le(b) != v) return -1;
    return 0;
}

static int test_ntt(void) {
    crypto_ntt_plan plan;
    uint32_t a[8] = {1,2,3,4,5,6,7,8};
    uint32_t original[8];
    size_t i;

    memcpy(original, a, sizeof(a));
    if (crypto_ntt_plan_init(&plan, 8, 17, 3) != 0) return -1;
    if (crypto_ntt_forward(&plan, a) != 0) return -1;
    if (crypto_ntt_inverse(&plan, a) != 0) return -1;
    for (i = 0; i < 8; ++i) {
        if (a[i] != original[i]) return -1;
    }
    return 0;
}

static int test_random(void) {
    uint8_t a[32], b[32];
    if (crypto_random_bytes(a, sizeof(a)) != 0) return -1;
    if (crypto_random_bytes(b, sizeof(b)) != 0) return -1;
    if (memcmp(a, b, sizeof(a)) == 0) return -1;
    return 0;
}

int main(void) {
    if (test_sha3() != 0) { fprintf(stderr, "SHA3/SHAKE test failed\n"); return 1; }
    if (test_endian() != 0) { fprintf(stderr, "endian test failed\n"); return 1; }
    if (test_ntt() != 0) { fprintf(stderr, "NTT test failed\n"); return 1; }
    if (test_random() != 0) { fprintf(stderr, "random test failed\n"); return 1; }
    puts("common crypto tests: OK");
    return 0;
}
