/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <stdio.h>
#include <string.h>

#include "Util/ECC/ecc_internal.h"

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int decode_hex(const char *hex, uint8_t *out, size_t length) {
    size_t index;
    for (index = 0u; index < length; ++index) {
        const int high = hex_nibble(hex[2u * index]);
        const int low = hex_nibble(hex[2u * index + 1u]);
        if (high < 0 || low < 0) return 0;
        out[index] = (uint8_t)((unsigned)high * 16u + (unsigned)low);
    }
    return hex[2u * length] == '\0';
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

static void scalar_from_order(const CryptoEcCurve *curve, uint8_t *scalar,
                              uint32_t subtract) {
    uint64_t borrow = subtract;
    size_t limb;
    memset(scalar, 0, curve->scalar_bytes);
    for (limb = 0u; limb < curve->limbs; ++limb) {
        const uint64_t right = borrow & UINT32_MAX;
        const uint64_t left = curve->order[limb];
        const uint32_t value = (uint32_t)(left - right);
        size_t byte;
        borrow = left < right;
        for (byte = 0u; byte < 4u; ++byte) {
            const size_t absolute = 4u * limb + byte;
            if (absolute < curve->scalar_bytes) {
                scalar[curve->scalar_bytes - 1u - absolute] =
                    (uint8_t)(value >> (8u * byte));
            }
        }
    }
}

static const char *two_g_x(CryptoEcCurveId id) {
    switch (id) {
        case CRYPTO_EC_CURVE_P256:
            return "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978";
        case CRYPTO_EC_CURVE_P384:
            return "08d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df61";
        case CRYPTO_EC_CURVE_P521:
            return "00433c219024277e7e682fcb288148c282747403279b1ccc06352c6e5505d769be97b3b204da6ef55507aa104a3a35c5af41cf2fa364d60fd967f43e3933ba6d783d";
        default:
            return NULL;
    }
}

static const char *two_g_y(CryptoEcCurveId id) {
    switch (id) {
        case CRYPTO_EC_CURVE_P256:
            return "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1";
        case CRYPTO_EC_CURVE_P384:
            return "8e80f1fa5b1b3cedb7bfe8dffd6dba74b275d875bc6cc43e904e505f256ab4255ffd43e94d39e22d61501e700a940e80";
        case CRYPTO_EC_CURVE_P521:
            return "00f4bb8cc7f86db26700a7f3eceeeed3f0b5c6b5107c4da97740ab21a29906c42dbbb3e377de9f251f6b93937fa99a3248f4eafcbe95edc0f4f71be356d661f41b02";
        default:
            return NULL;
    }
}

static int test_curve(CryptoEcCurveId id) {
    const CryptoEcCurve *curve = crypto_ec_curve_get(id);
    CryptoEcAffinePoint generator;
    CryptoEcAffinePoint decoded;
    CryptoEcAffinePoint reference;
    CryptoEcAffinePoint vartime;
    CryptoEcAffinePoint secret;
    CryptoEcAffinePoint expected_two_g;
    uint8_t scalar[66] = {0};
    uint8_t coordinate[66];
    uint8_t encoded[1u + 2u * 66u];
    size_t encoded_length;

    if (!curve) return 0;

    crypto_ec_affine_generator(curve, &generator);
    if (!crypto_ec_affine_is_on_curve(curve, &generator) ||
        crypto_ec_affine_is_infinity(&generator)) return 0;

    encoded_length = sizeof(encoded);
    if (crypto_ec_point_encode(curve, &generator, 0, encoded, &encoded_length) !=
            LIBERAC_SUCCESS ||
        crypto_ec_point_decode(curve, &decoded, encoded, encoded_length, 0) !=
            LIBERAC_SUCCESS ||
        !points_equal(curve, &generator, &decoded)) return 0;

    encoded_length = sizeof(encoded);
    if (crypto_ec_point_encode(curve, &generator, 1, encoded, &encoded_length) !=
            LIBERAC_SUCCESS ||
        crypto_ec_point_decode(curve, &decoded, encoded, encoded_length, 0) !=
            LIBERAC_SUCCESS ||
        !points_equal(curve, &generator, &decoded)) return 0;

    scalar[curve->scalar_bytes - 1u] = 1u;
    if (!crypto_ec_scalar_is_valid_ct(curve, scalar, curve->scalar_bytes) ||
        crypto_ec_scalar_multiply_reference(curve, &reference, &generator,
                                            scalar, curve->scalar_bytes) !=
            LIBERAC_SUCCESS ||
        crypto_ec_scalar_multiply_vartime(curve, &vartime, &generator, scalar,
                                          curve->scalar_bytes) != LIBERAC_SUCCESS ||
        crypto_ec_scalar_multiply_ct(curve, &secret, &generator, scalar,
                                     curve->scalar_bytes) != LIBERAC_SUCCESS ||
        !points_equal(curve, &generator, &reference) ||
        !points_equal(curve, &reference, &vartime) ||
        !points_equal(curve, &reference, &secret)) return 0;

    memset(scalar, 0, sizeof(scalar));
    scalar[curve->scalar_bytes - 1u] = 2u;
    if (crypto_ec_scalar_multiply_reference(curve, &reference, &generator,
                                            scalar, curve->scalar_bytes) !=
            LIBERAC_SUCCESS ||
        crypto_ec_scalar_multiply_vartime(curve, &vartime, &generator, scalar,
                                          curve->scalar_bytes) != LIBERAC_SUCCESS ||
        crypto_ec_scalar_multiply_ct(curve, &secret, &generator, scalar,
                                     curve->scalar_bytes) != LIBERAC_SUCCESS ||
        !points_equal(curve, &reference, &vartime) ||
        !points_equal(curve, &reference, &secret)) return 0;

    if (!decode_hex(two_g_x(id), coordinate, curve->field_bytes) ||
        crypto_ec_field_from_bytes(curve, &expected_two_g.x, coordinate,
                                   curve->field_bytes) != LIBERAC_SUCCESS ||
        !decode_hex(two_g_y(id), coordinate, curve->field_bytes) ||
        crypto_ec_field_from_bytes(curve, &expected_two_g.y, coordinate,
                                   curve->field_bytes) != LIBERAC_SUCCESS) return 0;
    expected_two_g.infinity = 0u;
    if (!points_equal(curve, &reference, &expected_two_g) ||
        !crypto_ec_affine_is_on_curve(curve, &expected_two_g)) return 0;

    memset(scalar, 0, sizeof(scalar));
    if (crypto_ec_scalar_is_valid_ct(curve, scalar, curve->scalar_bytes)) return 0;
    scalar_from_order(curve, scalar, 1u);
    if (!crypto_ec_scalar_is_valid_ct(curve, scalar, curve->scalar_bytes)) return 0;
    scalar_from_order(curve, scalar, 0u);
    if (crypto_ec_scalar_is_valid_ct(curve, scalar, curve->scalar_bytes)) return 0;

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
