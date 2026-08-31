/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <stdio.h>
#include <string.h>

#include "Util/ECC/ecc_internal.h"
#include "Reference.h"

static uint32_t prng_step(uint32_t *state) {
    uint32_t x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

static int points_equal(const CryptoEcCurve *curve,
                        const CryptoEcAffinePoint *a,
                        const CryptoEcAffinePoint *b) {
    uint8_t ea[1u + 2u * 66u];
    uint8_t eb[1u + 2u * 66u];
    size_t la = sizeof(ea);
    size_t lb = sizeof(eb);

    if (crypto_ec_point_encode(curve, a, 0, ea, &la) != LIBERAC_SUCCESS ||
        crypto_ec_point_encode(curve, b, 0, eb, &lb) != LIBERAC_SUCCESS) {
        return 0;
    }
    return la == lb && memcmp(ea, eb, la) == 0;
}

static int test_curve(CryptoEcCurveId id, uint32_t seed) {
    const CryptoEcCurve *curve = crypto_ec_curve_get(id);
    CryptoEcAffinePoint generator;
    CryptoEcAffinePoint reference;
    CryptoEcAffinePoint vartime;
    CryptoEcAffinePoint secret;
    uint8_t scalar[66];
    size_t iteration;

    if (!curve) {
        return 0;
    }
    crypto_ec_affine_generator(curve, &generator);

    for (iteration = 0u; iteration < 96u; ++iteration) {
        uint32_t value = prng_step(&seed);
        memset(scalar, 0, sizeof(scalar));

        /* Small non-zero scalars keep the textbook reference path affordable
         * while still varying bit patterns and exercising all implementations. */
        value = (value % 0x00ffffffu) + 1u;
        scalar[curve->scalar_bytes - 1u] = (uint8_t)value;
        scalar[curve->scalar_bytes - 2u] = (uint8_t)(value >> 8);
        scalar[curve->scalar_bytes - 3u] = (uint8_t)(value >> 16);

        if (!crypto_ec_scalar_is_valid_ct(curve, scalar, curve->scalar_bytes) ||
            crypto_ec_scalar_multiply_reference(curve, &reference, &generator,
                                                scalar, curve->scalar_bytes) !=
                LIBERAC_SUCCESS ||
            crypto_ec_scalar_multiply_vartime(curve, &vartime, &generator,
                                              scalar, curve->scalar_bytes) !=
                LIBERAC_SUCCESS ||
            crypto_ec_scalar_multiply_ct(curve, &secret, &generator, scalar,
                                         curve->scalar_bytes) != LIBERAC_SUCCESS ||
            !points_equal(curve, &reference, &vartime) ||
            !points_equal(curve, &reference, &secret) ||
            !crypto_ec_affine_is_on_curve(curve, &secret)) {
            fprintf(stderr, "ECC differential mismatch: curve=%d iteration=%lu\n",
                    (int)id, (unsigned long)iteration);
            return 0;
        }
    }
    return 1;
}

int main(void) {
    if (!test_curve(CRYPTO_EC_CURVE_P256, UINT32_C(0x12345678)) ||
        !test_curve(CRYPTO_EC_CURVE_P384, UINT32_C(0x9e3779b9)) ||
        !test_curve(CRYPTO_EC_CURVE_P521, UINT32_C(0xa5a5a5a5))) {
        return 1;
    }
    puts("ECC differential test passed");
    return 0;
}
