/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#include "BlockCipher/TripleDES/triple_des_internal.h"
#include "Util/Core/secure_zero.h"

#include <string.h>

static const uint8_t PC1[56] = {57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4};
static const uint8_t PC2[48] = {14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32};
static const uint8_t ROT[16] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};

/*
 * The four output bits of each DES S-box after permutation P. TRUTH_TABLE
 * packs the corresponding 32 one-bit Boolean functions for each possible
 * six-bit input. Both tables are derived mechanically from FIPS 46-3 S/P.
 * They are accessed only at public, fixed indices; secret selection is done
 * by the Boolean multiplexer tree in des_round_function().
 */
static const uint32_t SBOX_OUTPUT_MASKS[8] = {
    UINT32_C(0x00808202), UINT32_C(0x40084010),
    UINT32_C(0x04010104), UINT32_C(0x80401040),
    UINT32_C(0x21040080), UINT32_C(0x10202008),
    UINT32_C(0x02100401), UINT32_C(0x08020820)
};

static const uint32_t TRUTH_TABLE[64] = {
    UINT32_C(0xd8d8dbbc), UINT32_C(0xd73559c1),
    UINT32_C(0x8306f441), UINT32_C(0x3dabeafe),
    UINT32_C(0x1cec9542), UINT32_C(0x8a408efb),
    UINT32_C(0xf079253f), UINT32_C(0xcf34d510),
    UINT32_C(0x721726b5), UINT32_C(0x4cfef21c),
    UINT32_C(0x4deadaa6), UINT32_C(0xf2471ac9),
    UINT32_C(0xeda34bcf), UINT32_C(0x338fa826),
    UINT32_C(0x16d508d1), UINT32_C(0xe048253f),
    UINT32_C(0x8f0a4602), UINT32_C(0x28bc163d),
    UINT32_C(0x7cd56b19), UINT32_C(0x8240bf20),
    UINT32_C(0x6223abc1), UINT32_C(0x37d7e0a8),
    UINT32_C(0xaf9fd4bc), UINT32_C(0x59bb1bcf),
    UINT32_C(0xb77c897e), UINT32_C(0xe0810592),
    UINT32_C(0x00a1344b), UINT32_C(0x3f7ae567),
    UINT32_C(0x091474bc), UINT32_C(0x4d697b47),
    UINT32_C(0xf36abb62), UINT32_C(0x949644d0),
    UINT32_C(0x1647a960), UINT32_C(0xa5dac69a),
    UINT32_C(0x587b189e), UINT32_C(0x83e8bd45),
    UINT32_C(0xf2a1e679), UINT32_C(0x4fbf0121),
    UINT32_C(0x67986989), UINT32_C(0x30465aa9),
    UINT32_C(0x49b899c3), UINT32_C(0x7241e064),
    UINT32_C(0xbf458774), UINT32_C(0xcd9e619a),
    UINT32_C(0xbe5e56bc), UINT32_C(0x982035db),
    UINT32_C(0x81b27643), UINT32_C(0x7f358e66),
    UINT32_C(0xa5e4f7df), UINT32_C(0xda2fe8e3),
    UINT32_C(0xa79a8421), UINT32_C(0x7fb513be),
    UINT32_C(0x89de041e), UINT32_C(0xc8017b16),
    UINT32_C(0x78659b73), UINT32_C(0xa7f8a65d),
    UINT32_C(0x8c0f7aa2), UINT32_C(0x05b21fcd),
    UINT32_C(0x72d26b8c), UINT32_C(0x84455c30),
    UINT32_C(0x5221a967), UINT32_C(0x724e8634),
    UINT32_C(0x4d2d549c), UINT32_C(0x38dbf9cb)
};

typedef struct des_round_workspace {
    uint32_t PLANES[6];
    uint32_t NODES[32];
} des_round_workspace;

static uint64_t load64_be(const uint8_t *input) {
    uint64_t value = 0u;
    size_t index;

    for (index = 0u; index < 8u; ++index) {
        value = (value << 8) | input[index];
    }
    return value;
}

static void store64_be(uint8_t *output, uint64_t value) {
    size_t index;

    for (index = 0u; index < 8u; ++index) {
        output[7u - index] = (uint8_t)(value >> (8u * index));
    }
}

static uint64_t permute_bits(
    uint64_t input, unsigned int input_bits,
    const uint8_t *table, size_t output_bits) {
    uint64_t output = 0u;
    size_t index;

    for (index = 0u; index < output_bits; ++index) {
        output = (output << 1) |
                 ((input >> (input_bits - table[index])) & UINT64_C(1));
    }
    return output;
}

/* Richard Outerbridge's public-domain IP network, expressed with uint32_t. */
static uint64_t initial_permutation(uint64_t input) {
    uint32_t left = (uint32_t)(input >> 32);
    uint32_t right = (uint32_t)input;
    uint32_t temporary;

    temporary = ((left >> 4) ^ right) & UINT32_C(0x0f0f0f0f);
    right ^= temporary;
    left ^= temporary << 4;
    temporary = ((left >> 16) ^ right) & UINT32_C(0x0000ffff);
    right ^= temporary;
    left ^= temporary << 16;
    temporary = ((right >> 2) ^ left) & UINT32_C(0x33333333);
    left ^= temporary;
    right ^= temporary << 2;
    temporary = ((right >> 8) ^ left) & UINT32_C(0x00ff00ff);
    left ^= temporary;
    right ^= temporary << 8;
    temporary = ((left >> 1) ^ right) & UINT32_C(0x55555555);
    right ^= temporary;
    left ^= temporary << 1;
    return ((uint64_t)left << 32) | right;
}

static uint64_t final_permutation(uint64_t input) {
    uint32_t left = (uint32_t)(input >> 32);
    uint32_t right = (uint32_t)input;
    uint32_t temporary;

    temporary = ((left >> 1) ^ right) & UINT32_C(0x55555555);
    right ^= temporary;
    left ^= temporary << 1;
    temporary = ((right >> 8) ^ left) & UINT32_C(0x00ff00ff);
    left ^= temporary;
    right ^= temporary << 8;
    temporary = ((right >> 2) ^ left) & UINT32_C(0x33333333);
    left ^= temporary;
    right ^= temporary << 2;
    temporary = ((left >> 16) ^ right) & UINT32_C(0x0000ffff);
    right ^= temporary;
    left ^= temporary << 16;
    temporary = ((left >> 4) ^ right) & UINT32_C(0x0f0f0f0f);
    right ^= temporary;
    left ^= temporary << 4;
    return ((uint64_t)left << 32) | right;
}

static uint32_t des_round_function(
    uint32_t right, uint64_t round_key,
    des_round_workspace *workspace) {
    uint64_t expanded;
    unsigned int box;
    unsigned int bit;
    unsigned int index;
    unsigned int node_count;

    memset(workspace->PLANES, 0, sizeof(workspace->PLANES));

    /* Spell out E rather than walking its table on every block. */
    expanded = (uint64_t)(((right & 1u) << 5) | (right >> 27)) << 42;
    expanded |= (uint64_t)((right >> 23) & 63u) << 36;
    expanded |= (uint64_t)((right >> 19) & 63u) << 30;
    expanded |= (uint64_t)((right >> 15) & 63u) << 24;
    expanded |= (uint64_t)((right >> 11) & 63u) << 18;
    expanded |= (uint64_t)((right >> 7) & 63u) << 12;
    expanded |= (uint64_t)((right >> 3) & 63u) << 6;
    expanded |= (uint64_t)(((right & 31u) << 1) | (right >> 31));
    expanded ^= round_key;

    for (box = 0u; box < 8u; ++box) {
        const uint32_t input =
            (uint32_t)(expanded >> (42u - 6u * box)) & 63u;
        for (bit = 0u; bit < 6u; ++bit) {
            const uint32_t mask = 0u - ((input >> bit) & 1u);
            workspace->PLANES[bit] |= mask & SBOX_OUTPUT_MASKS[box];
        }
    }

    /* First Shannon-expansion level reads the fixed truth table directly. */
    for (index = 0u; index < 32u; ++index) {
        const uint32_t left = TRUTH_TABLE[2u * index];
        workspace->NODES[index] = left ^
            (workspace->PLANES[0] &
             (left ^ TRUTH_TABLE[2u * index + 1u]));
    }
    node_count = 32u;
    for (bit = 1u; bit < 6u; ++bit) {
        node_count >>= 1;
        for (index = 0u; index < node_count; ++index) {
            const uint32_t left = workspace->NODES[2u * index];
            workspace->NODES[index] = left ^
                (workspace->PLANES[bit] &
                 (left ^ workspace->NODES[2u * index + 1u]));
        }
    }
    return workspace->NODES[0];
}

static void des_key_schedule(const uint8_t key[8], uint64_t round_keys[16]) {
    const uint64_t permuted = permute_bits(load64_be(key), 64u, PC1, 56u);
    uint32_t left = (uint32_t)(permuted >> 28);
    uint32_t right = (uint32_t)(permuted & UINT32_C(0x0fffffff));
    unsigned int index;

    for (index = 0u; index < 16u; ++index) {
        left = ((left << ROT[index]) | (left >> (28u - ROT[index]))) &
               UINT32_C(0x0fffffff);
        right = ((right << ROT[index]) | (right >> (28u - ROT[index]))) &
                UINT32_C(0x0fffffff);
        round_keys[index] = permute_bits(
            ((uint64_t)left << 28) | right, 56u, PC2, 48u);
    }
}

/* Input and output remain in the IP domain so adjacent EDE stages cancel. */
static uint64_t des_rounds(
    uint64_t input, const uint64_t round_keys[16], int encrypt,
    des_round_workspace *workspace) {
    uint32_t left = (uint32_t)(input >> 32);
    uint32_t right = (uint32_t)input;
    uint32_t temporary;
    unsigned int round;

    for (round = 0u; round < 16u; ++round) {
        temporary = right;
        right = left ^ des_round_function(
            right, round_keys[encrypt != 0 ? round : 15u - round],
            workspace);
        left = temporary;
    }
    return ((uint64_t)right << 32) | left;
}

static uint64_t triple_des_block(
    uint64_t block, uint64_t round_keys[3][16], int encrypt,
    des_round_workspace *workspace) {
    uint64_t state = initial_permutation(block);

    if (encrypt != 0) {
        state = des_rounds(state, round_keys[0], 1, workspace);
        state = des_rounds(state, round_keys[1], 0, workspace);
        state = des_rounds(state, round_keys[2], 1, workspace);
    } else {
        state = des_rounds(state, round_keys[2], 0, workspace);
        state = des_rounds(state, round_keys[1], 1, workspace);
        state = des_rounds(state, round_keys[0], 0, workspace);
    }
    return final_permutation(state);
}

LiberaCError crypto_tdes_ede3_context_init(
    CryptoTdesEde3Context *context,
    const uint8_t *key, size_t key_length) {
    if (context == NULL || key == NULL) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    crypto_zeroize(context, sizeof(*context));
    if (key_length != LIBERAC_TDES_EDE3_KEY_BYTES) {
        return LIBERAC_ERROR_INVALID_KEY;
    }

    des_key_schedule(key, context->ROUND_KEYS[0]);
    des_key_schedule(key + 8u, context->ROUND_KEYS[1]);
    des_key_schedule(key + 16u, context->ROUND_KEYS[2]);
    return LIBERAC_SUCCESS;
}

LiberaCError crypto_tdes_ede3_encrypt_block(
    CryptoTdesEde3Context *context,
    const uint8_t input[LIBERAC_TDES_BLOCK_BYTES],
    uint8_t output[LIBERAC_TDES_BLOCK_BYTES]) {
    des_round_workspace workspace;
    uint64_t block;

    if (context == NULL || input == NULL || output == NULL) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    block = triple_des_block(
        load64_be(input), context->ROUND_KEYS, 1, &workspace);
    store64_be(output, block);
    crypto_zeroize(&workspace, sizeof(workspace));
    crypto_zeroize(&block, sizeof(block));
    return LIBERAC_SUCCESS;
}

void crypto_tdes_ede3_context_clear(CryptoTdesEde3Context *context) {
    if (context != NULL) {
        crypto_zeroize(context, sizeof(*context));
    }
}

LiberaCError crypto_tdes_ede3_crypt(
    uint8_t *output, size_t output_capacity,
    const uint8_t *input, size_t input_length,
    const uint8_t *key, size_t key_length,
    const uint8_t *iv, size_t iv_length,
    CryptoTdesMode mode, int encrypt) {
    uint64_t round_keys[3][16];
    uint64_t chain = 0u;
    uint64_t block = 0u;
    uint64_t result = 0u;
    des_round_workspace workspace;
    size_t offset;

    if (key == NULL ||
        ((input == NULL || output == NULL) && input_length != 0u)) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    if (key_length != LIBERAC_TDES_EDE3_KEY_BYTES) {
        return LIBERAC_ERROR_INVALID_KEY;
    }
    if ((input_length % LIBERAC_TDES_BLOCK_BYTES) != 0u) {
        return LIBERAC_ERROR_INVALID_ARGUMENT;
    }
    if (mode == CRYPTO_TDES_MODE_ECB) {
        if (iv_length != 0u) {
            return LIBERAC_ERROR_INVALID_ARGUMENT;
        }
    } else if (mode == CRYPTO_TDES_MODE_CBC) {
        if (iv == NULL || iv_length != LIBERAC_TDES_BLOCK_BYTES) {
            return LIBERAC_ERROR_INVALID_ARGUMENT;
        }
        chain = load64_be(iv);
    } else {
        return LIBERAC_ERROR_INVALID_ALG_ID;
    }
    if (output_capacity < input_length) {
        return LIBERAC_ERROR_BUFFER_TOO_SMALL;
    }
    if (input_length == 0u) {
        return LIBERAC_SUCCESS;
    }

    des_key_schedule(key, round_keys[0]);
    des_key_schedule(key + 8u, round_keys[1]);
    des_key_schedule(key + 16u, round_keys[2]);

    for (offset = 0u; offset < input_length;
         offset += LIBERAC_TDES_BLOCK_BYTES) {
        block = load64_be(input + offset);
        if (encrypt != 0 && mode == CRYPTO_TDES_MODE_CBC) {
            block ^= chain;
        }
        result = triple_des_block(block, round_keys, encrypt, &workspace);
        if (encrypt == 0 && mode == CRYPTO_TDES_MODE_CBC) {
            result ^= chain;
            chain = block;
        } else if (mode == CRYPTO_TDES_MODE_CBC) {
            chain = result;
        }
        store64_be(output + offset, result);
    }

    crypto_zeroize(round_keys, sizeof(round_keys));
    crypto_zeroize(&workspace, sizeof(workspace));
    chain = 0u;
    block = 0u;
    result = 0u;
    return LIBERAC_SUCCESS;
}
