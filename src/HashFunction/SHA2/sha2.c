/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "sha2_internal.h"

#include "Util/Bit/bit_internal.h"
#include "Util/Core/secure_zero.h"
#include "Util/Endian/endian_internal.h"

#include <string.h>

#define SHA256_BLOCK_BYTES 64u
#define SHA512_BLOCK_BYTES 128u

static const uint32_t sha256_round_constants[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static const uint64_t sha512_round_constants[80] = {
    UINT64_C(0x428a2f98d728ae22), UINT64_C(0x7137449123ef65cd),
    UINT64_C(0xb5c0fbcfec4d3b2f), UINT64_C(0xe9b5dba58189dbbc),
    UINT64_C(0x3956c25bf348b538), UINT64_C(0x59f111f1b605d019),
    UINT64_C(0x923f82a4af194f9b), UINT64_C(0xab1c5ed5da6d8118),
    UINT64_C(0xd807aa98a3030242), UINT64_C(0x12835b0145706fbe),
    UINT64_C(0x243185be4ee4b28c), UINT64_C(0x550c7dc3d5ffb4e2),
    UINT64_C(0x72be5d74f27b896f), UINT64_C(0x80deb1fe3b1696b1),
    UINT64_C(0x9bdc06a725c71235), UINT64_C(0xc19bf174cf692694),
    UINT64_C(0xe49b69c19ef14ad2), UINT64_C(0xefbe4786384f25e3),
    UINT64_C(0x0fc19dc68b8cd5b5), UINT64_C(0x240ca1cc77ac9c65),
    UINT64_C(0x2de92c6f592b0275), UINT64_C(0x4a7484aa6ea6e483),
    UINT64_C(0x5cb0a9dcbd41fbd4), UINT64_C(0x76f988da831153b5),
    UINT64_C(0x983e5152ee66dfab), UINT64_C(0xa831c66d2db43210),
    UINT64_C(0xb00327c898fb213f), UINT64_C(0xbf597fc7beef0ee4),
    UINT64_C(0xc6e00bf33da88fc2), UINT64_C(0xd5a79147930aa725),
    UINT64_C(0x06ca6351e003826f), UINT64_C(0x142929670a0e6e70),
    UINT64_C(0x27b70a8546d22ffc), UINT64_C(0x2e1b21385c26c926),
    UINT64_C(0x4d2c6dfc5ac42aed), UINT64_C(0x53380d139d95b3df),
    UINT64_C(0x650a73548baf63de), UINT64_C(0x766a0abb3c77b2a8),
    UINT64_C(0x81c2c92e47edaee6), UINT64_C(0x92722c851482353b),
    UINT64_C(0xa2bfe8a14cf10364), UINT64_C(0xa81a664bbc423001),
    UINT64_C(0xc24b8b70d0f89791), UINT64_C(0xc76c51a30654be30),
    UINT64_C(0xd192e819d6ef5218), UINT64_C(0xd69906245565a910),
    UINT64_C(0xf40e35855771202a), UINT64_C(0x106aa07032bbd1b8),
    UINT64_C(0x19a4c116b8d2d0c8), UINT64_C(0x1e376c085141ab53),
    UINT64_C(0x2748774cdf8eeb99), UINT64_C(0x34b0bcb5e19b48a8),
    UINT64_C(0x391c0cb3c5c95a63), UINT64_C(0x4ed8aa4ae3418acb),
    UINT64_C(0x5b9cca4f7763e373), UINT64_C(0x682e6ff3d6b2b8a3),
    UINT64_C(0x748f82ee5defb2fc), UINT64_C(0x78a5636f43172f60),
    UINT64_C(0x84c87814a1f0ab72), UINT64_C(0x8cc702081a6439ec),
    UINT64_C(0x90befffa23631e28), UINT64_C(0xa4506cebde82bde9),
    UINT64_C(0xbef9a3f7b2c67915), UINT64_C(0xc67178f2e372532b),
    UINT64_C(0xca273eceea26619c), UINT64_C(0xd186b8c721c0c207),
    UINT64_C(0xeada7dd6cde0eb1e), UINT64_C(0xf57d4f7fee6ed178),
    UINT64_C(0x06f067aa72176fba), UINT64_C(0x0a637dc5a2c898a6),
    UINT64_C(0x113f9804bef90dae), UINT64_C(0x1b710b35131c471b),
    UINT64_C(0x28db77f523047d84), UINT64_C(0x32caab7b40c72493),
    UINT64_C(0x3c9ebe0a15c9bebc), UINT64_C(0x431d67c49c100d4c),
    UINT64_C(0x4cc5d4becb3e42b6), UINT64_C(0x597f299cfc657e2a),
    UINT64_C(0x5fcb6fab3ad6faec), UINT64_C(0x6c44198c4a475817)
};

static void sha256_compress(uint32_t state[8], const uint8_t block[SHA256_BLOCK_BYTES]) {
    uint32_t schedule[64];
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t choice, majority, sigma0, sigma1, temporary1, temporary2;
    size_t round;

    for (round = 0; round < 16u; ++round) {
        schedule[round] = crypto_load32_be(block + (round * 4u));
    }
    for (; round < 64u; ++round) {
        const uint32_t s0 = crypto_rotr32(schedule[round - 15u], 7u) ^
                            crypto_rotr32(schedule[round - 15u], 18u) ^
                            (schedule[round - 15u] >> 3);
        const uint32_t s1 = crypto_rotr32(schedule[round - 2u], 17u) ^
                            crypto_rotr32(schedule[round - 2u], 19u) ^
                            (schedule[round - 2u] >> 10);
        schedule[round] = schedule[round - 16u] + s0 +
                          schedule[round - 7u] + s1;
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    for (round = 0; round < 64u; ++round) {
        sigma1 = crypto_rotr32(e, 6u) ^ crypto_rotr32(e, 11u) ^
                 crypto_rotr32(e, 25u);
        choice = (e & f) ^ ((~e) & g);
        temporary1 = h + sigma1 + choice + sha256_round_constants[round] + schedule[round];
        sigma0 = crypto_rotr32(a, 2u) ^ crypto_rotr32(a, 13u) ^
                 crypto_rotr32(a, 22u);
        majority = (a & b) ^ (a & c) ^ (b & c);
        temporary2 = sigma0 + majority;

        h = g; g = f; f = e; e = d + temporary1;
        d = c; c = b; b = a; a = temporary1 + temporary2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
    crypto_zeroize(schedule, sizeof(schedule));
}

static void sha512_compress(uint64_t state[8], const uint8_t block[SHA512_BLOCK_BYTES]) {
    uint64_t schedule[80];
    uint64_t a, b, c, d, e, f, g, h;
    uint64_t choice, majority, sigma0, sigma1, temporary1, temporary2;
    size_t round;

    for (round = 0; round < 16u; ++round) {
        schedule[round] = crypto_load64_be(block + (round * 8u));
    }
    for (; round < 80u; ++round) {
        const uint64_t s0 = crypto_rotr64(schedule[round - 15u], 1u) ^
                            crypto_rotr64(schedule[round - 15u], 8u) ^
                            (schedule[round - 15u] >> 7);
        const uint64_t s1 = crypto_rotr64(schedule[round - 2u], 19u) ^
                            crypto_rotr64(schedule[round - 2u], 61u) ^
                            (schedule[round - 2u] >> 6);
        schedule[round] = schedule[round - 16u] + s0 +
                          schedule[round - 7u] + s1;
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    for (round = 0; round < 80u; ++round) {
        sigma1 = crypto_rotr64(e, 14u) ^ crypto_rotr64(e, 18u) ^
                 crypto_rotr64(e, 41u);
        choice = (e & f) ^ ((~e) & g);
        temporary1 = h + sigma1 + choice + sha512_round_constants[round] + schedule[round];
        sigma0 = crypto_rotr64(a, 28u) ^ crypto_rotr64(a, 34u) ^
                 crypto_rotr64(a, 39u);
        majority = (a & b) ^ (a & c) ^ (b & c);
        temporary2 = sigma0 + majority;

        h = g; g = f; f = e; e = d + temporary1;
        d = c; c = b; b = a; a = temporary1 + temporary2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
    crypto_zeroize(schedule, sizeof(schedule));
}

static CryptoError sha256_family(
    uint8_t *output, const uint8_t *input, size_t input_length,
    const uint32_t initial_state[8], size_t digest_length) {
    uint32_t state[8];
    uint8_t block[SHA256_BLOCK_BYTES];
    uint8_t digest[32];
    const size_t original_length = input_length;
    size_t index;

    if (((uint64_t)input_length >> 61) != 0u) {
        return CRYPTO_ERROR_MESSAGE_TOO_LARGE;
    }

    memcpy(state, initial_state, sizeof(state));
    while (input_length >= SHA256_BLOCK_BYTES) {
        sha256_compress(state, input);
        input += SHA256_BLOCK_BYTES;
        input_length -= SHA256_BLOCK_BYTES;
    }

    memset(block, 0, sizeof(block));
    if (input_length != 0u) {
        memcpy(block, input, input_length);
    }
    block[input_length] = 0x80u;
    if (input_length >= 56u) {
        sha256_compress(state, block);
        memset(block, 0, sizeof(block));
    }
    crypto_store64_be(block + 56u, (uint64_t)original_length << 3);
    sha256_compress(state, block);

    for (index = 0; index < 8u; ++index) {
        crypto_store32_be(digest + (index * 4u), state[index]);
    }
    memcpy(output, digest, digest_length);
    crypto_zeroize(digest, sizeof(digest));
    crypto_zeroize(block, sizeof(block));
    crypto_zeroize(state, sizeof(state));
    return CRYPTO_SUCCESS;
}

static CryptoError sha512_family(
    uint8_t *output, const uint8_t *input, size_t input_length,
    const uint64_t initial_state[8], size_t digest_length) {
    uint64_t state[8];
    uint8_t block[SHA512_BLOCK_BYTES];
    uint8_t digest[64];
    const uint64_t original_length = (uint64_t)input_length;
    size_t index;

    memcpy(state, initial_state, sizeof(state));
    while (input_length >= SHA512_BLOCK_BYTES) {
        sha512_compress(state, input);
        input += SHA512_BLOCK_BYTES;
        input_length -= SHA512_BLOCK_BYTES;
    }

    memset(block, 0, sizeof(block));
    if (input_length != 0u) {
        memcpy(block, input, input_length);
    }
    block[input_length] = 0x80u;
    if (input_length >= 112u) {
        sha512_compress(state, block);
        memset(block, 0, sizeof(block));
    }
    crypto_store64_be(block + 112u, original_length >> 61);
    crypto_store64_be(block + 120u, original_length << 3);
    sha512_compress(state, block);

    for (index = 0; index < 8u; ++index) {
        crypto_store64_be(digest + (index * 8u), state[index]);
    }
    memcpy(output, digest, digest_length);
    crypto_zeroize(digest, sizeof(digest));
    crypto_zeroize(block, sizeof(block));
    crypto_zeroize(state, sizeof(state));
    return CRYPTO_SUCCESS;
}

CryptoError crypto_sha2_hash(
    uint8_t *OUTPUT, size_t OUTPUT_LENGTH,
    const uint8_t *INPUT, size_t INPUT_LENGTH,
    AlgID ALG) {
    static const uint32_t iv224[8] = {
        0xc1059ed8u, 0x367cd507u, 0x3070dd17u, 0xf70e5939u,
        0xffc00b31u, 0x68581511u, 0x64f98fa7u, 0xbefa4fa4u
    };
    static const uint32_t iv256[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
    };
    static const uint64_t iv384[8] = {
        UINT64_C(0xcbbb9d5dc1059ed8), UINT64_C(0x629a292a367cd507),
        UINT64_C(0x9159015a3070dd17), UINT64_C(0x152fecd8f70e5939),
        UINT64_C(0x67332667ffc00b31), UINT64_C(0x8eb44a8768581511),
        UINT64_C(0xdb0c2e0d64f98fa7), UINT64_C(0x47b5481dbefa4fa4)
    };
    static const uint64_t iv512[8] = {
        UINT64_C(0x6a09e667f3bcc908), UINT64_C(0xbb67ae8584caa73b),
        UINT64_C(0x3c6ef372fe94f82b), UINT64_C(0xa54ff53a5f1d36f1),
        UINT64_C(0x510e527fade682d1), UINT64_C(0x9b05688c2b3e6c1f),
        UINT64_C(0x1f83d9abfb41bd6b), UINT64_C(0x5be0cd19137e2179)
    };
    static const uint64_t iv512_224[8] = {
        UINT64_C(0x8c3d37c819544da2), UINT64_C(0x73e1996689dcd4d6),
        UINT64_C(0x1dfab7ae32ff9c82), UINT64_C(0x679dd514582f9fcf),
        UINT64_C(0x0f6d2b697bd44da8), UINT64_C(0x77e36f7304c48942),
        UINT64_C(0x3f9d85a86a1d36c8), UINT64_C(0x1112e6ad91d692a1)
    };
    static const uint64_t iv512_256[8] = {
        UINT64_C(0x22312194fc2bf72c), UINT64_C(0x9f555fa3c84c64c2),
        UINT64_C(0x2393b86b6f53b151), UINT64_C(0x963877195940eabd),
        UINT64_C(0x96283ee2a88effe3), UINT64_C(0xbe5e1e2553863992),
        UINT64_C(0x2b0199fc2c85b8aa), UINT64_C(0x0eb72ddc81c52ca2)
    };

    (void)OUTPUT_LENGTH;
    switch (ALG) {
        case ALG_HASH_SHA2_224:
            return sha256_family(OUTPUT, INPUT, INPUT_LENGTH, iv224, 28u);
        case ALG_HASH_SHA2_256:
            return sha256_family(OUTPUT, INPUT, INPUT_LENGTH, iv256, 32u);
        case ALG_HASH_SHA2_384:
            return sha512_family(OUTPUT, INPUT, INPUT_LENGTH, iv384, 48u);
        case ALG_HASH_SHA2_512:
            return sha512_family(OUTPUT, INPUT, INPUT_LENGTH, iv512, 64u);
        case ALG_HASH_SHA2_512_224:
            return sha512_family(OUTPUT, INPUT, INPUT_LENGTH, iv512_224, 28u);
        case ALG_HASH_SHA2_512_256:
            return sha512_family(OUTPUT, INPUT, INPUT_LENGTH, iv512_256, 32u);
        default:
            return CRYPTO_ERROR_INVALID_ALG_ID;
    }
}
