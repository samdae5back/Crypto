/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <stdio.h>
#include <string.h>

#include "Util/ECC/ecc_internal.h"

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

static int test_curve(CryptoEcCurveId id) {
    const CryptoEcCurve *curve = crypto_ec_curve_get(id);
    CryptoEcAffinePoint generator;
    CryptoEcAffinePoint decoded;
    CryptoEcAffinePoint reference;
    CryptoEcAffinePoint vartime;
    CryptoEcAffinePoint secret;
    uint8_t scalar[66] = {0};
    uint8_t encoded[1u + 2u * 66u];
    size_t encoded_length;

    if (!curve) {
        return 0;
    }

    crypto_ec_affine_generator(curve, &generator);
    if (!crypto_ec_affine_is_on_curve(curve, &generator) ||
        crypto_ec_affine_is_infinity(&generator)) {
        return 0;
    }

    encoded_length = sizeof(encoded);
    if (crypto_ec_point_encode(curve, &generator, 0, encoded,
                               &encoded_length) != LIBERAC_SUCCESS ||
        crypto_ec_point_decode(curve, &decoded, encoded, encoded_length, 0) !=
            LIBERAC_SUCCESS ||
        !points_equal(curve, &generator, &decoded)) {
        return 0;
    }

    encoded_length = sizeof(encoded);
    if (crypto_ec_point_encode(curve, &generator, 1, encoded,
                               &encoded_length) != LIBERAC_SUCCESS ||
        crypto_ec_point_decode(curve, &decoded, encoded, encoded_length, 0) !=
            LIBERAC_SUCCESS ||
        !points_equal(curve, &generator, &decoded)) {
        return 0;
    }

    scalar[curve->scalar_bytes - 1u] = 1u;
    if (!crypto_ec_scalar_is_valid_ct(curve, scalar, curve->scalar_bytes) ||
        crypto_ec_scalar_multiply_reference(curve, &reference, &generator,
                                            scalar, curve->scalar_bytes) !=
            LIBERAC_SUCCESS ||
        crypto_ec_scalar_multiply_vartime(curve, &vartime, &generator, scalar,
                                          curve->scalar_bytes) !=
            LIBERAC_SUCCESS ||
        crypto_ec_scalar_multiply_ct(curve, &secret, &generator, scalar,
                                     curve->scalar_bytes) != LIBERAC_SUCCESS ||
        !points_equal(curve, &generator, &reference) ||
        !points_equal(curve, &reference, &vartime) ||
        !points_equal(curve, &reference, &secret)) {
        return 0;
    }

    scalar[curve->scalar_bytes - 1u] = 2u;
    if (crypto_ec_scalar_multiply_reference(curve, &reference, &generator,
                                            scalar, curve->scalar_bytes) !=
            LIBERAC_SUCCESS ||
        crypto_ec_scalar_multiply_vartime(curve, &vartime, &generator, scalar,
                                          curve->scalar_bytes) !=
            LIBERAC_SUCCESS ||
        crypto_ec_scalar_multiply_ct(curve, &secret, &generator, scalar,
                                     curve->scalar_bytes) != LIBERAC_SUCCESS ||
        !points_equal(curve, &reference, &vartime) ||
        !points_equal(curve, &reference, &secret) ||
        !crypto_ec_affine_is_on_curve(curve, &secret)) {
        return 0;
    }

    memset(scalar, 0, sizeof(scalar));
    if (crypto_ec_scalar_is_valid_ct(curve, scalar, curve->scalar_bytes)) {
        return 0;
    }

    return 1;
}

int main(void) {
    if (!test_curve(CRYPTO_EC_CURVE_P256) ||
        !test_curve(CRYPTO_EC_CURVE_P384) ||
        !test_curve(CRYPTO_EC_CURVE_P521)) {
        fprintf(stderr, "ECC unit test failed\n");
        return 1;
    }
    puts("ECC unit test passed");
    return 0;
}
