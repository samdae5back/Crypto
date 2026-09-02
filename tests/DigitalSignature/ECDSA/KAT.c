/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <stdio.h>
#include <string.h>

#include "DigitalSignature.h"
#include "HashFunction.h"

#define ECDSA_MAX_PRIVATE_BYTES 66u
#define ECDSA_MAX_PUBLIC_BYTES 133u
#define ECDSA_MAX_SIGNATURE_BYTES 132u

typedef struct {
    const char *name;
    LiberaCAlgID algorithm;
    LiberaCAlgID hash_algorithm;
    size_t scalar_bytes;
    const char *private_key;
    const char *public_x;
    const char *public_y;
    const char *signature_r;
    const char *signature_s;
} EcdsaKat;

/* RFC 6979 Appendix A.2.5 through A.2.7, message = "sample". */
static const EcdsaKat KATS[] = {
    {
        "P-256/SHA-256",
        LIBERAC_ALG_ECDSA_P256,
        LIBERAC_ALG_HASH_SHA2_256,
        32u,
        "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
        "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
        "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299",
        "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
        "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"
    },
    {
        "P-384/SHA-384",
        LIBERAC_ALG_ECDSA_P384,
        LIBERAC_ALG_HASH_SHA2_384,
        48u,
        "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D8"
        "96D5724E4C70A825F872C9EA60D2EDF5",
        "EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64"
        "DEF8F0EA9055866064A254515480BC13",
        "8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1"
        "288B231C3AE0D4FE7344FD2533264720",
        "94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C"
        "81A648152E44ACF96E36DD1E80FABE46",
        "99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94F"
        "A329C145786E679E7B82C71A38628AC8"
    },
    {
        "P-521/SHA-512",
        LIBERAC_ALG_ECDSA_P521,
        LIBERAC_ALG_HASH_SHA2_512,
        66u,
        "0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75C"
        "AA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83"
        "538",
        "1894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD3"
        "71123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F502"
        "3A4",
        "0493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A2"
        "8A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDF"
        "CF5",
        "0C328FAFCBD79DD77850370C46325D987CB525569FB63C5D3BC53950E6D4C5F1"
        "74E25A1EE9017B5D450606ADD152B534931D7D4E8455CC91F9B15BF05EC36E37"
        "7FA",
        "0617CCE7CF5064806C467F678D3B4080D6F1CC50AF26CA209417308281B68AF2"
        "82623EAA63E5B5C0723D8B8C37FF0777B1A20F8CCB1DCCC43997F1EE0E44DA4A"
        "67A"
    }
};

static int hex_nibble(char character) {
    if (character >= '0' && character <= '9') {
        return character - '0';
    }
    if (character >= 'a' && character <= 'f') {
        return character - 'a' + 10;
    }
    if (character >= 'A' && character <= 'F') {
        return character - 'A' + 10;
    }
    return -1;
}

static int decode_hex_left_padded(
    const char *hex, uint8_t *output, size_t output_length) {
    size_t hex_index = strlen(hex);
    size_t output_index = output_length;

    if (hex_index > 2u * output_length) {
        return 0;
    }
    memset(output, 0, output_length);
    while (hex_index != 0u) {
        int high = 0;
        const int low = hex_nibble(hex[--hex_index]);
        if (low < 0) {
            return 0;
        }
        if (hex_index != 0u) {
            high = hex_nibble(hex[--hex_index]);
            if (high < 0) {
                return 0;
            }
        }
        output[--output_index] =
            (uint8_t)((unsigned)high * 16u + (unsigned)low);
    }
    return 1;
}

static int fail(const EcdsaKat *kat, const char *stage) {
    fprintf(stderr, "ECDSA KAT failure: %s stage=%s\n", kat->name, stage);
    return 0;
}

static int run_kat(const EcdsaKat *kat) {
    static const uint8_t message[] = {'s', 'a', 'm', 'p', 'l', 'e'};
    uint8_t private_key[ECDSA_MAX_PRIVATE_BYTES];
    uint8_t expected_public[ECDSA_MAX_PUBLIC_BYTES];
    uint8_t public_key[ECDSA_MAX_PUBLIC_BYTES];
    uint8_t compressed_public[1u + ECDSA_MAX_PRIVATE_BYTES];
    uint8_t expected_signature[ECDSA_MAX_SIGNATURE_BYTES];
    uint8_t signature[ECDSA_MAX_SIGNATURE_BYTES];
    const size_t public_length = 1u + 2u * kat->scalar_bytes;
    const size_t signature_length = 2u * kat->scalar_bytes;

    memset(private_key, 0, sizeof(private_key));
    memset(expected_public, 0, sizeof(expected_public));
    memset(public_key, 0, sizeof(public_key));
    memset(compressed_public, 0, sizeof(compressed_public));
    memset(expected_signature, 0, sizeof(expected_signature));
    memset(signature, 0, sizeof(signature));

    if (!decode_hex_left_padded(
            kat->private_key, private_key, kat->scalar_bytes) ||
        !decode_hex_left_padded(
            kat->public_x, expected_public + 1u, kat->scalar_bytes) ||
        !decode_hex_left_padded(
            kat->public_y, expected_public + 1u + kat->scalar_bytes,
            kat->scalar_bytes) ||
        !decode_hex_left_padded(
            kat->signature_r, expected_signature, kat->scalar_bytes) ||
        !decode_hex_left_padded(
            kat->signature_s, expected_signature + kat->scalar_bytes,
            kat->scalar_bytes)) {
        return fail(kat, "vector decode");
    }
    expected_public[0] = UINT8_C(0x04);

    if (LIBERAC_ECDSA_PRIVATE_KEY_SIZE(kat->algorithm) != kat->scalar_bytes ||
        LIBERAC_ECDSA_PUBLIC_KEY_SIZE(kat->algorithm) != public_length ||
        LIBERAC_ECDSA_SIGNATURE_SIZE(kat->algorithm) != signature_length) {
        return fail(kat, "size query");
    }
    if (LIBERAC_ECDSA_PUBLIC_FROM_PRIVATE(
            public_key, public_length, private_key, kat->scalar_bytes,
            kat->algorithm) != LIBERAC_SUCCESS ||
        memcmp(public_key, expected_public, public_length) != 0) {
        return fail(kat, "public key");
    }
    if (LIBERAC_ECDSA_SIGN(
            private_key, kat->scalar_bytes, message, sizeof(message),
            signature, signature_length, kat->hash_algorithm,
            kat->algorithm) != LIBERAC_SUCCESS ||
        memcmp(signature, expected_signature, signature_length) != 0) {
        return fail(kat, "deterministic signature");
    }
    if (LIBERAC_ECDSA_VERIFY(
            public_key, public_length, message, sizeof(message),
            signature, signature_length, kat->hash_algorithm,
            kat->algorithm) != LIBERAC_SUCCESS) {
        return fail(kat, "uncompressed verification");
    }

    compressed_public[0] = (uint8_t)(
        UINT8_C(0x02) |
        (expected_public[public_length - 1u] & UINT8_C(0x01)));
    memcpy(compressed_public + 1u,
           expected_public + 1u, kat->scalar_bytes);
    if (LIBERAC_ECDSA_VERIFY(
            compressed_public, 1u + kat->scalar_bytes,
            message, sizeof(message), signature, signature_length,
            kat->hash_algorithm, kat->algorithm) != LIBERAC_SUCCESS) {
        return fail(kat, "compressed verification");
    }

    return 1;
}

int main(void) {
    size_t index;

    for (index = 0u; index < sizeof(KATS) / sizeof(KATS[0]); ++index) {
        if (!run_kat(&KATS[index])) {
            return 1;
        }
    }
    puts("ECDSA RFC 6979 KAT passed");
    return 0;
}
