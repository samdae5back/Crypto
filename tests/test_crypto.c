#include "Crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int test_hash(void) {
    static const uint8_t expected[32] = {
        0x3a,0x98,0x5d,0xa7,0x4f,0xe2,0x25,0xb2,
        0x04,0x5c,0x17,0x2d,0x6b,0xd3,0x90,0xbd,
        0x85,0x5f,0x08,0x6e,0x3e,0x9d,0x52,0x5b,
        0x46,0xbf,0xe2,0x45,0x11,0x43,0x15,0x32
    };
    static const uint8_t input[] = {'a', 'b', 'c'};
    uint8_t output[32];

    if (CRYPTO_HASH(output, sizeof(output), input, sizeof(input),
                    ALG_HASH_SHA3_256) != CRYPTO_SUCCESS)
        return 1;
    if (memcmp(output, expected, sizeof(output)) != 0) return 1;
    return CRYPTO_HASH(output, sizeof(output), input, sizeof(input),
                       (AlgID)0x7fffffff) != CRYPTO_ERROR_INVALID_ALG_ID;
}

static int test_block_cipher(void) {
    static const uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    static const uint8_t iv[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    static const uint8_t ctr[16] = {
        0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,
        0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff
    };
    static const uint8_t plaintext[16] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
        0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
    };
    static const uint8_t expected_cbc[16] = {
        0x76,0x49,0xab,0xac,0x81,0x19,0xb2,0x46,
        0xce,0xe9,0x8e,0x9b,0x12,0xe9,0x19,0x7d
    };
    static const uint8_t expected_ctr[16] = {
        0x87,0x4d,0x61,0x91,0xb6,0x20,0xe3,0x26,
        0x1b,0xef,0x68,0x64,0x99,0x0d,0xb6,0xce
    };
    uint8_t ciphertext[16], decoded[16];

    if (CRYPTO_BLOCK_CIPHER_KEY_SIZE(ALG_AES_128_CBC) != sizeof(key) ||
        CRYPTO_BLOCK_CIPHER_KEY_SIZE(ALG_AES_192_GCM) != 24u ||
        CRYPTO_BLOCK_CIPHER_KEY_SIZE(ALG_AES_256_CCM) != 32u ||
        CRYPTO_BLOCK_CIPHER_KEY_SIZE(ALG_RSA_RAW) != 0u)
        return 1;

    if (CRYPTO_BLOCK_CIPHER_ENCRYPT(
            ciphertext, sizeof(ciphertext), NULL, 0u,
            plaintext, sizeof(plaintext), key, sizeof(key),
            iv, sizeof(iv), NULL, 0u, ALG_AES_128_CBC) != CRYPTO_SUCCESS)
        return 1;
    if (memcmp(ciphertext, expected_cbc, sizeof(ciphertext)) != 0) return 1;
    if (CRYPTO_BLOCK_CIPHER_DECRYPT(
            decoded, sizeof(decoded), NULL, 0u,
            ciphertext, sizeof(ciphertext), key, sizeof(key),
            iv, sizeof(iv), NULL, 0u, ALG_AES_128_CBC) != CRYPTO_SUCCESS)
        return 1;
    if (memcmp(decoded, plaintext, sizeof(decoded)) != 0) return 1;

    if (CRYPTO_BLOCK_CIPHER_ENCRYPT(
            ciphertext, sizeof(ciphertext), NULL, 0u,
            plaintext, sizeof(plaintext), key, sizeof(key),
            ctr, sizeof(ctr), NULL, 0u, ALG_AES_128_CTR) != CRYPTO_SUCCESS)
        return 1;
    if (memcmp(ciphertext, expected_ctr, sizeof(ciphertext)) != 0) return 1;
    if (CRYPTO_BLOCK_CIPHER_DECRYPT(
            decoded, sizeof(decoded), NULL, 0u,
            ciphertext, sizeof(ciphertext), key, sizeof(key),
            ctr, sizeof(ctr), NULL, 0u, ALG_AES_128_CTR) != CRYPTO_SUCCESS)
        return 1;
    if (memcmp(decoded, plaintext, sizeof(decoded)) != 0) return 1;

    return CRYPTO_BLOCK_CIPHER_ENCRYPT(
               ciphertext, sizeof(ciphertext), NULL, 0u,
               plaintext, sizeof(plaintext), key, sizeof(key) - 1u,
               NULL, 0u, NULL, 0u,
               ALG_AES_128_ECB) != CRYPTO_ERROR_INVALID_KEY;
}

static int test_aead(void) {
    static const uint8_t gcm_key[16] = {0};
    static const uint8_t gcm_iv[12] = {0};
    static const uint8_t gcm_plaintext[16] = {0};
    static const uint8_t gcm_ciphertext[16] = {
        0x03,0x88,0xda,0xce,0x60,0xb6,0xa3,0x92,
        0xf3,0x28,0xc2,0xb9,0x71,0xb2,0xfe,0x78
    };
    static const uint8_t gcm_tag[16] = {
        0xab,0x6e,0x47,0xd4,0x2c,0xec,0x13,0xbd,
        0xf5,0x3a,0x67,0xb2,0x12,0x57,0xbd,0xdf
    };
    static const uint8_t ccm_key[16] = {
        0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7,
        0xc8,0xc9,0xca,0xcb,0xcc,0xcd,0xce,0xcf
    };
    static const uint8_t ccm_nonce[13] = {
        0x00,0x00,0x00,0x03,0x02,0x01,0x00,
        0xa0,0xa1,0xa2,0xa3,0xa4,0xa5
    };
    static const uint8_t ccm_aad[8] = {0,1,2,3,4,5,6,7};
    static const uint8_t ccm_plaintext[23] = {
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e
    };
    uint8_t output[32], decoded[32], tag[16], bad_tag[16];

    if (CRYPTO_BLOCK_CIPHER_ENCRYPT(
            output, sizeof(output), tag, sizeof(tag),
            gcm_plaintext, sizeof(gcm_plaintext), gcm_key, sizeof(gcm_key),
            gcm_iv, sizeof(gcm_iv), NULL, 0u, ALG_AES_128_GCM) != CRYPTO_SUCCESS)
        return 1;
    if (memcmp(output, gcm_ciphertext, sizeof(gcm_ciphertext)) != 0 ||
        memcmp(tag, gcm_tag, sizeof(gcm_tag)) != 0)
        return 1;
    if (CRYPTO_BLOCK_CIPHER_DECRYPT(
            decoded, sizeof(decoded), tag, sizeof(tag),
            output, sizeof(gcm_plaintext), gcm_key, sizeof(gcm_key),
            gcm_iv, sizeof(gcm_iv), NULL, 0u, ALG_AES_128_GCM) != CRYPTO_SUCCESS)
        return 1;
    if (memcmp(decoded, gcm_plaintext, sizeof(gcm_plaintext)) != 0) return 1;

    memcpy(bad_tag, tag, sizeof(tag));
    bad_tag[0] ^= 1u;
    memset(decoded, 0xa5, sizeof(gcm_plaintext));
    if (CRYPTO_BLOCK_CIPHER_DECRYPT(
            decoded, sizeof(decoded), bad_tag, sizeof(bad_tag),
            output, sizeof(gcm_plaintext), gcm_key, sizeof(gcm_key),
            gcm_iv, sizeof(gcm_iv), NULL, 0u,
            ALG_AES_128_GCM) != CRYPTO_ERROR_AUTHENTICATION_FAILED)
        return 1;

    if (CRYPTO_BLOCK_CIPHER_ENCRYPT(
            output, sizeof(output), tag, 8u,
            ccm_plaintext, sizeof(ccm_plaintext), ccm_key, sizeof(ccm_key),
            ccm_nonce, sizeof(ccm_nonce), ccm_aad, sizeof(ccm_aad),
            ALG_AES_128_CCM) != CRYPTO_SUCCESS)
        return 1;
    if (CRYPTO_BLOCK_CIPHER_DECRYPT(
            decoded, sizeof(decoded), tag, 8u,
            output, sizeof(ccm_plaintext), ccm_key, sizeof(ccm_key),
            ccm_nonce, sizeof(ccm_nonce), ccm_aad, sizeof(ccm_aad),
            ALG_AES_128_CCM) != CRYPTO_SUCCESS)
        return 1;
    return memcmp(decoded, ccm_plaintext, sizeof(ccm_plaintext)) != 0;
}

static int test_bignum(void) {
    static const uint8_t input[] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
    };
    uint8_t output[sizeof(input)];
    CRYPTO_BIGNUM value;
    int failed;

    CRYPTO_BIGNUM_INIT(&value);
    failed = CRYPTO_BIGNUM_FROM_BYTES_BE(&value, input, sizeof(input)) != CRYPTO_SUCCESS ||
             CRYPTO_BIGNUM_TO_BYTES_BE(&value, output, sizeof(output)) != CRYPTO_SUCCESS ||
             memcmp(input, output, sizeof(input)) != 0;
    CRYPTO_BIGNUM_FREE(&value);
    return failed;
}

static int test_rsa(void) {
    static const uint8_t encoded[] = {42u};
    uint8_t decoded[sizeof(encoded)];
    CRYPTO_RSA_PUBLIC_KEY public_key;
    CRYPTO_RSA_PRIVATE_KEY private_key;
    CRYPTO_BIGNUM message, ciphertext, recovered;
    int failed = 1;

    CRYPTO_RSA_PUBLIC_KEY_INIT(&public_key);
    CRYPTO_RSA_PRIVATE_KEY_INIT(&private_key);
    CRYPTO_BIGNUM_INIT(&message);
    CRYPTO_BIGNUM_INIT(&ciphertext);
    CRYPTO_BIGNUM_INIT(&recovered);
    if (CRYPTO_RSA_KEYGEN(&public_key, &private_key, 256u, 12u,
                          ALG_RSA_RAW) != CRYPTO_SUCCESS)
        goto done;
    if (CRYPTO_BIGNUM_FROM_BYTES_BE(&message, encoded, sizeof(encoded)) != CRYPTO_SUCCESS)
        goto done;
    if (CRYPTO_RSA_ENCRYPT(&ciphertext, &message, &public_key,
                           ALG_RSA_RAW) != CRYPTO_SUCCESS)
        goto done;
    if (CRYPTO_RSA_DECRYPT(&recovered, &ciphertext, &private_key,
                           ALG_RSA_RAW) != CRYPTO_SUCCESS)
        goto done;
    if (CRYPTO_BIGNUM_TO_BYTES_BE(&recovered, decoded, sizeof(decoded)) != CRYPTO_SUCCESS ||
        memcmp(encoded, decoded, sizeof(encoded)) != 0)
        goto done;
    failed = 0;

done:
    CRYPTO_BIGNUM_FREE(&message);
    CRYPTO_BIGNUM_FREE(&ciphertext);
    CRYPTO_BIGNUM_FREE(&recovered);
    CRYPTO_RSA_PUBLIC_KEY_FREE(&public_key);
    CRYPTO_RSA_PRIVATE_KEY_FREE(&private_key);
    return failed;
}

static int test_ml_kem(AlgID alg) {
    size_t public_key_length = CRYPTO_ML_KEM_PUBLIC_KEY_SIZE(alg);
    size_t private_key_length = CRYPTO_ML_KEM_PRIVATE_KEY_SIZE(alg);
    size_t ciphertext_length = CRYPTO_ML_KEM_CIPHERTEXT_SIZE(alg);
    uint8_t *public_key = NULL, *private_key = NULL, *ciphertext = NULL;
    uint8_t shared_a[CRYPTO_ML_KEM_SHARED_SECRET_BYTES];
    uint8_t shared_b[CRYPTO_ML_KEM_SHARED_SECRET_BYTES];
    uint8_t rejected[CRYPTO_ML_KEM_SHARED_SECRET_BYTES];
    uint8_t rejection_expected[CRYPTO_ML_KEM_SHARED_SECRET_BYTES];
    uint8_t rejection_input[CRYPTO_ML_KEM_1024_CIPHERTEXT_BYTES + 32u];
    int failed = 1;

    public_key = (uint8_t *)malloc(public_key_length);
    private_key = (uint8_t *)malloc(private_key_length);
    ciphertext = (uint8_t *)malloc(ciphertext_length);
    if (!public_key || !private_key || !ciphertext) goto done;
    if (CRYPTO_ML_KEM_KEYGEN(public_key, public_key_length,
                             private_key, private_key_length, alg) != CRYPTO_SUCCESS)
        goto done;
    if (CRYPTO_ML_KEM_ENCAPS(public_key, public_key_length, shared_a,
                             ciphertext, ciphertext_length, alg) != CRYPTO_SUCCESS)
        goto done;
    if (CRYPTO_ML_KEM_DECAPS(private_key, private_key_length,
                             ciphertext, ciphertext_length, shared_b,
                             alg) != CRYPTO_SUCCESS)
        goto done;
    if (memcmp(shared_a, shared_b, sizeof(shared_a)) != 0)
        goto done;

    ciphertext[0] ^= 1u;
    memcpy(rejection_input, private_key + private_key_length - 32u, 32u);
    memcpy(rejection_input + 32u, ciphertext, ciphertext_length);
    if (CRYPTO_HASH(rejection_expected, sizeof(rejection_expected),
                    rejection_input, ciphertext_length + 32u,
                    ALG_HASH_SHAKE256) != CRYPTO_SUCCESS)
        goto done;
    if (CRYPTO_ML_KEM_DECAPS(private_key, private_key_length,
                             ciphertext, ciphertext_length, rejected,
                             alg) != CRYPTO_SUCCESS)
        goto done;
    if (memcmp(rejected, rejection_expected, sizeof(rejected)) != 0)
        goto done;

    failed = 0;

done:
    free(public_key);
    free(private_key);
    free(ciphertext);
    return failed;
}

int main(void) {
    static const AlgID ml_kem_algorithms[] = {
        ALG_ML_KEM_512, ALG_ML_KEM_768, ALG_ML_KEM_1024
    };
    size_t i;

    if (test_hash()) { fputs("hash unit test failed\n", stderr); return 1; }
    if (test_block_cipher()) { fputs("block cipher unit test failed\n", stderr); return 1; }
    if (test_aead()) { fputs("AEAD unit test failed\n", stderr); return 1; }
    if (test_bignum()) { fputs("bignum unit test failed\n", stderr); return 1; }
    if (test_rsa()) { fputs("RSA unit test failed\n", stderr); return 1; }
    for (i = 0u; i < sizeof(ml_kem_algorithms) / sizeof(ml_kem_algorithms[0]); ++i) {
        if (test_ml_kem(ml_kem_algorithms[i])) {
            fprintf(stderr, "ML-KEM algorithm %d unit test failed\n",
                    (int)ml_kem_algorithms[i]);
            return 1;
        }
    }
    puts("all public API unit tests passed");
    return 0;
}
