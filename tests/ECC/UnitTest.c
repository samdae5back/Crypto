/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "Util/ECC/ecc_internal.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct EcVector {
    CryptoEcCurveId id;
    const char *generator_x;
    const char *generator_y;
    const char *double_x;
    const char *double_y;
    uint32_t non_residue_x;
} EcVector;

static const EcVector crypto_ec_vectors[] = {
    {
        CRYPTO_EC_CURVE_P256,
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
        "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1",
        1u
    },
    {
        CRYPTO_EC_CURVE_P384,
        "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
        "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
        "08d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df61",
        "8e80f1fa5b1b3cedb7bfe8dffd6dba74b275d875bc6cc43e904e505f256ab4255ffd43e94d39e22d61501e700a940e80",
        1u
    },
    {
        CRYPTO_EC_CURVE_P521,
        "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
        "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650",
        "00433c219024277e7e682fcb288148c282747403279b1ccc06352c6e5505d769be97b3b204da6ef55507aa104a3a35c5af41cf2fa364d60fd967f43e3933ba6d783d",
        "00f4bb8cc7f86db26700a7f3eceeeed3f0b5c6b5107c4da97740ab21a29906c42dbbb3e377de9f251f6b93937fa99a3248f4eafcbe95edc0f4f71be356d661f41b02",
        3u
    }
};

static int crypto_test_hex_digit(char value) {
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return value - 'a' + 10;
    }
    if (value >= 'A' && value <= 'F') {
        return value - 'A' + 10;
    }
    return -1;
}

static int crypto_test_hex_decode(const char *hex, uint8_t *out,
                                  size_t out_length) {
    size_t i;

    if (hex == NULL || out == NULL ||
        strlen(hex) != out_length * 2u) {
        return 0;
    }
    for (i = 0u; i < out_length; ++i) {
        int high = crypto_test_hex_digit(hex[2u * i]);
        int low = crypto_test_hex_digit(hex[2u * i + 1u]);
        if (high < 0 || low < 0) {
            return 0;
        }
        out[i] = (uint8_t)((high << 4) | low);
    }
    return 1;
}

static void crypto_test_scalar_u32(const CryptoEcCurve *curve,
                                   uint8_t *scalar, uint32_t value) {
    size_t i;

    memset(scalar, 0, curve->scalar_bytes);
    for (i = 0u; i < 4u && i < curve->scalar_bytes; ++i) {
        scalar[curve->scalar_bytes - 1u - i] =
            (uint8_t)(value >> (8u * i));
    }
}

static void crypto_test_order_bytes(const CryptoEcCurve *curve,
                                    uint8_t *out) {
    size_t i;

    for (i = 0u; i < curve->scalar_bytes; ++i) {
        out[curve->scalar_bytes - 1u - i] =
            (uint8_t)(curve->order[i / 4u] >> ((i % 4u) * 8u));
    }
}

static void crypto_test_subtract_one(uint8_t *value, size_t length) {
    size_t i;

    for (i = length; i > 0u; --i) {
        value[i - 1u] = (uint8_t)(value[i - 1u] - 1u);
        if (value[i - 1u] != UINT8_MAX) {
            return;
        }
    }
}

static int crypto_test_affine_equal(const CryptoEcCurve *curve,
                                    const CryptoEcAffinePoint *a,
                                    const CryptoEcAffinePoint *b) {
    if ((a->infinity != 0u) != (b->infinity != 0u)) {
        return 0;
    }
    if (a->infinity != 0u) {
        return 1;
    }
    return crypto_ec_field_equal_mask(curve, &a->x, &b->x) ==
               UINT32_MAX &&
           crypto_ec_field_equal_mask(curve, &a->y, &b->y) ==
               UINT32_MAX;
}

static int crypto_test_expected_point(const CryptoEcCurve *curve,
                                      const CryptoEcAffinePoint *point,
                                      const char *x_hex,
                                      const char *y_hex) {
    uint8_t encoded[1u + 2u * 66u];
    uint8_t expected[1u + 2u * 66u];
    size_t encoded_length = sizeof(encoded);

    expected[0] = 0x04u;
    if (!crypto_test_hex_decode(x_hex, expected + 1u,
                                curve->field_bytes) ||
        !crypto_test_hex_decode(y_hex,
                                expected + 1u + curve->field_bytes,
                                curve->field_bytes)) {
        return 0;
    }
    if (crypto_ec_point_encode(curve, point, 0, encoded,
                               &encoded_length) != LIBERAC_SUCCESS) {
        return 0;
    }
    return encoded_length == 1u + 2u * curve->field_bytes &&
           memcmp(encoded, expected, encoded_length) == 0;
}

static int crypto_test_known_double(const EcVector *vector) {
    const CryptoEcCurve *curve = crypto_ec_curve_get(vector->id);
    CryptoEcAffinePoint generator;
    CryptoEcAffinePoint reference;
    CryptoEcAffinePoint vartime;
    CryptoEcAffinePoint fixed;
    uint8_t scalar[66u];

    if (curve == NULL) {
        return 0;
    }
    crypto_ec_affine_generator(curve, &generator);
    crypto_test_scalar_u32(curve, scalar, 2u);

    if (!crypto_ec_affine_is_on_curve(curve, &generator) ||
        crypto_ec_scalar_multiply_reference(
            curve, &reference, &generator, scalar,
            curve->scalar_bytes) != LIBERAC_SUCCESS ||
        crypto_ec_scalar_multiply_vartime(
            curve, &vartime, &generator, scalar,
            curve->scalar_bytes) != LIBERAC_SUCCESS ||
        crypto_ec_scalar_multiply_ct(
            curve, &fixed, &generator, scalar,
            curve->scalar_bytes) != LIBERAC_SUCCESS) {
        return 0;
    }

    return crypto_test_expected_point(
               curve, &generator, vector->generator_x,
               vector->generator_y) &&
           crypto_test_expected_point(
               curve, &reference, vector->double_x,
               vector->double_y) &&
           crypto_test_affine_equal(curve, &reference, &vartime) &&
           crypto_test_affine_equal(curve, &reference, &fixed);
}

static int crypto_test_differential(const EcVector *vector) {
    static const uint32_t scalars[] = {
        1u, 2u, 3u, 5u, 17u, 257u, 65535u
    };
    const CryptoEcCurve *curve = crypto_ec_curve_get(vector->id);
    CryptoEcAffinePoint generator;
    size_t i;

    crypto_ec_affine_generator(curve, &generator);
    for (i = 0u; i < sizeof(scalars) / sizeof(scalars[0]); ++i) {
        CryptoEcAffinePoint reference;
        CryptoEcAffinePoint vartime;
        CryptoEcAffinePoint fixed;
        uint8_t scalar[66u];

        crypto_test_scalar_u32(curve, scalar, scalars[i]);
        if (crypto_ec_scalar_multiply_reference(
                curve, &reference, &generator, scalar,
                curve->scalar_bytes) != LIBERAC_SUCCESS ||
            crypto_ec_scalar_multiply_vartime(
                curve, &vartime, &generator, scalar,
                curve->scalar_bytes) != LIBERAC_SUCCESS ||
            crypto_ec_scalar_multiply_ct(
                curve, &fixed, &generator, scalar,
                curve->scalar_bytes) != LIBERAC_SUCCESS ||
            !crypto_test_affine_equal(curve, &reference, &vartime) ||
            !crypto_test_affine_equal(curve, &reference, &fixed) ||
            !crypto_ec_affine_is_on_curve(curve, &reference)) {
            return 0;
        }
    }
    return 1;
}

static int crypto_test_projective_edges(const EcVector *vector) {
    const CryptoEcCurve *curve = crypto_ec_curve_get(vector->id);
    CryptoEcAffinePoint generator;
    CryptoEcAffinePoint negative;
    CryptoEcAffinePoint affine_result;
    CryptoEcJacobianPoint g;
    CryptoEcJacobianPoint neg_g;
    CryptoEcJacobianPoint infinity;
    CryptoEcJacobianPoint result;

    crypto_ec_affine_generator(curve, &generator);
    negative = generator;
    crypto_ec_field_negate(curve, &negative.y, &negative.y);
    crypto_ec_affine_to_jacobian(curve, &g, &generator);
    crypto_ec_affine_to_jacobian(curve, &neg_g, &negative);
    crypto_ec_jacobian_set_infinity(curve, &infinity);

    crypto_ec_jacobian_add_complete(curve, &result, &g, &infinity);
    crypto_ec_jacobian_to_affine(curve, &affine_result, &result);
    if (!crypto_test_affine_equal(curve, &affine_result, &generator)) {
        return 0;
    }

    crypto_ec_jacobian_add_complete(curve, &result, &infinity, &g);
    crypto_ec_jacobian_to_affine(curve, &affine_result, &result);
    if (!crypto_test_affine_equal(curve, &affine_result, &generator)) {
        return 0;
    }

    crypto_ec_jacobian_add_complete(curve, &result, &g, &neg_g);
    if (!crypto_ec_jacobian_is_infinity(curve, &result)) {
        return 0;
    }

    crypto_ec_jacobian_double(curve, &result, &infinity);
    if (!crypto_ec_jacobian_is_infinity(curve, &result)) {
        return 0;
    }

    crypto_ec_jacobian_add_complete(curve, &result, &g, &g);
    crypto_ec_jacobian_to_affine(curve, &affine_result, &result);
    return crypto_test_expected_point(
        curve, &affine_result, vector->double_x, vector->double_y);
}

static int crypto_test_scalar_boundaries(const EcVector *vector) {
    const CryptoEcCurve *curve = crypto_ec_curve_get(vector->id);
    CryptoEcAffinePoint generator;
    CryptoEcAffinePoint result;
    CryptoEcAffinePoint negative_generator;
    uint8_t scalar[66u];

    memset(scalar, 0, sizeof(scalar));
    if (crypto_ec_scalar_is_valid_ct(
            curve, scalar, curve->scalar_bytes)) {
        return 0;
    }
    scalar[curve->scalar_bytes - 1u] = 1u;
    if (!crypto_ec_scalar_is_valid_ct(
            curve, scalar, curve->scalar_bytes)) {
        return 0;
    }

    crypto_test_order_bytes(curve, scalar);
    if (crypto_ec_scalar_is_valid_ct(
            curve, scalar, curve->scalar_bytes)) {
        return 0;
    }

    crypto_ec_affine_generator(curve, &generator);
    if (crypto_ec_scalar_multiply_vartime(
            curve, &result, &generator, scalar,
            curve->scalar_bytes) != LIBERAC_SUCCESS ||
        !crypto_ec_affine_is_infinity(&result)) {
        return 0;
    }

    crypto_test_subtract_one(scalar, curve->scalar_bytes);
    if (!crypto_ec_scalar_is_valid_ct(
            curve, scalar, curve->scalar_bytes) ||
        crypto_ec_scalar_multiply_vartime(
            curve, &result, &generator, scalar,
            curve->scalar_bytes) != LIBERAC_SUCCESS) {
        return 0;
    }
    negative_generator = generator;
    crypto_ec_field_negate(curve, &negative_generator.y,
                           &negative_generator.y);
    if (!crypto_test_affine_equal(curve, &result,
                                  &negative_generator)) {
        return 0;
    }

    if (crypto_ec_scalar_multiply_ct(
            curve, &result, &generator, scalar,
            curve->scalar_bytes) != LIBERAC_SUCCESS ||
        !crypto_test_affine_equal(curve, &result,
                                  &negative_generator)) {
        return 0;
    }

    return 1;
}

static int crypto_test_encoding(const EcVector *vector) {
    const CryptoEcCurve *curve = crypto_ec_curve_get(vector->id);
    CryptoEcAffinePoint generator;
    CryptoEcAffinePoint decoded;
    CryptoEcAffinePoint infinity;
    uint8_t uncompressed[1u + 2u * 66u];
    uint8_t compressed[1u + 66u];
    uint8_t invalid[1u + 2u * 66u];
    size_t uncompressed_length = sizeof(uncompressed);
    size_t compressed_length = sizeof(compressed);
    size_t query_length = 0u;
    size_t i;

    crypto_ec_affine_generator(curve, &generator);
    if (crypto_ec_point_encode(
            curve, &generator, 0, uncompressed,
            &uncompressed_length) != LIBERAC_SUCCESS ||
        crypto_ec_point_encode(
            curve, &generator, 1, compressed,
            &compressed_length) != LIBERAC_SUCCESS ||
        crypto_ec_point_decode(
            curve, &decoded, uncompressed,
            uncompressed_length, 0) != LIBERAC_SUCCESS ||
        !crypto_test_affine_equal(curve, &generator, &decoded) ||
        crypto_ec_point_decode(
            curve, &decoded, compressed,
            compressed_length, 0) != LIBERAC_SUCCESS ||
        !crypto_test_affine_equal(curve, &generator, &decoded)) {
        return 0;
    }

    if (crypto_ec_point_encode(
            curve, &generator, 1, NULL,
            &query_length) != LIBERAC_ERROR_BUFFER_TOO_SMALL ||
        query_length != 1u + curve->field_bytes) {
        return 0;
    }

    crypto_ec_affine_set_infinity(&infinity);
    query_length = sizeof(invalid);
    if (crypto_ec_point_encode(
            curve, &infinity, 0, invalid,
            &query_length) != LIBERAC_SUCCESS ||
        query_length != 1u || invalid[0] != 0u ||
        crypto_ec_point_decode(
            curve, &decoded, invalid, 1u,
            1) != LIBERAC_SUCCESS ||
        !crypto_ec_affine_is_infinity(&decoded) ||
        crypto_ec_point_decode(
            curve, &decoded, invalid, 1u,
            0) != LIBERAC_ERROR_INVALID_KEY) {
        return 0;
    }

    memcpy(invalid, compressed, compressed_length);
    invalid[0] = 0x05u;
    if (crypto_ec_point_decode(
            curve, &decoded, invalid,
            compressed_length, 0) != LIBERAC_ERROR_INVALID_KEY ||
        crypto_ec_point_decode(
            curve, &decoded, compressed,
            compressed_length - 1u,
            0) != LIBERAC_ERROR_INVALID_KEY) {
        return 0;
    }

    invalid[0] = 0x02u;
    memset(invalid + 1u, 0, curve->field_bytes);
    for (i = 0u; i < curve->field_bytes; ++i) {
        invalid[curve->field_bytes - i] =
            (uint8_t)(curve->p[i / 4u] >> ((i % 4u) * 8u));
    }
    if (crypto_ec_point_decode(
            curve, &decoded, invalid,
            1u + curve->field_bytes,
            0) != LIBERAC_ERROR_INVALID_KEY) {
        return 0;
    }

    invalid[0] = 0x02u;
    memset(invalid + 1u, 0, curve->field_bytes);
    invalid[curve->field_bytes] =
        (uint8_t)vector->non_residue_x;
    if (crypto_ec_point_decode(
            curve, &decoded, invalid,
            1u + curve->field_bytes,
            0) != LIBERAC_ERROR_INVALID_KEY) {
        return 0;
    }

    memcpy(invalid, uncompressed, uncompressed_length);
    invalid[uncompressed_length - 1u] ^= 1u;
    if (crypto_ec_point_decode(
            curve, &decoded, invalid,
            uncompressed_length,
            0) != LIBERAC_ERROR_INVALID_KEY) {
        return 0;
    }

    return 1;
}

static int crypto_test_aliasing(const EcVector *vector) {
    const CryptoEcCurve *curve = crypto_ec_curve_get(vector->id);
    CryptoEcAffinePoint point;
    uint8_t scalar[66u];

    crypto_test_scalar_u32(curve, scalar, 2u);

    crypto_ec_affine_generator(curve, &point);
    if (crypto_ec_scalar_multiply_reference(
            curve, &point, &point, scalar,
            curve->scalar_bytes) != LIBERAC_SUCCESS ||
        !crypto_test_expected_point(
            curve, &point, vector->double_x,
            vector->double_y)) {
        return 0;
    }

    crypto_ec_affine_generator(curve, &point);
    if (crypto_ec_scalar_multiply_vartime(
            curve, &point, &point, scalar,
            curve->scalar_bytes) != LIBERAC_SUCCESS ||
        !crypto_test_expected_point(
            curve, &point, vector->double_x,
            vector->double_y)) {
        return 0;
    }

    crypto_ec_affine_generator(curve, &point);
    if (crypto_ec_scalar_multiply_ct(
            curve, &point, &point, scalar,
            curve->scalar_bytes) != LIBERAC_SUCCESS ||
        !crypto_test_expected_point(
            curve, &point, vector->double_x,
            vector->double_y)) {
        return 0;
    }

    return 1;
}

static int crypto_test_invalid_arguments(void) {
    const CryptoEcCurve *curve =
        crypto_ec_curve_get(CRYPTO_EC_CURVE_P256);
    CryptoEcAffinePoint point;
    uint8_t scalar[32u] = {0u};
    size_t length = 0u;

    crypto_ec_affine_generator(curve, &point);
    return crypto_ec_curve_get((CryptoEcCurveId)0) == NULL &&
           crypto_ec_scalar_multiply_reference(
               NULL, &point, &point, scalar,
               sizeof(scalar)) == LIBERAC_ERROR_INVALID_ARGUMENT &&
           crypto_ec_scalar_multiply_vartime(
               curve, &point, &point, scalar,
               sizeof(scalar) - 1u) == LIBERAC_ERROR_INVALID_ARGUMENT &&
           crypto_ec_scalar_multiply_ct(
               curve, &point, &point, NULL,
               sizeof(scalar)) == LIBERAC_ERROR_INVALID_ARGUMENT &&
           crypto_ec_point_encode(
               curve, &point, 0, NULL,
               NULL) == LIBERAC_ERROR_INVALID_ARGUMENT &&
           crypto_ec_point_decode(
               curve, &point, NULL, length,
               0) == LIBERAC_ERROR_INVALID_ARGUMENT;
}

int main(void) {
    size_t i;

    for (i = 0u;
         i < sizeof(crypto_ec_vectors) / sizeof(crypto_ec_vectors[0]);
         ++i) {
        const EcVector *vector = &crypto_ec_vectors[i];

        if (!crypto_test_known_double(vector) ||
            !crypto_test_differential(vector) ||
            !crypto_test_projective_edges(vector) ||
            !crypto_test_scalar_boundaries(vector) ||
            !crypto_test_encoding(vector) ||
            !crypto_test_aliasing(vector)) {
            fprintf(stderr, "ECC unit test failed for curve id %d\n",
                    (int)vector->id);
            return 1;
        }
    }

    if (!crypto_test_invalid_arguments()) {
        fprintf(stderr, "ECC invalid-argument test failed\n");
        return 1;
    }

    puts("ECC internal unit tests passed");
    return 0;
}
