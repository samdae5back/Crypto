#include "HashFunction.h"

#include "HashFunction/LSH/lsh_internal.h"
#include "HashFunction/SHA2/sha2_internal.h"
#include "HashFunction/SHA3/sha3_internal.h"

static size_t fixed_digest_length(AlgID algorithm) {
    switch (algorithm) {
        case ALG_HASH_SHA2_224:
        case ALG_HASH_SHA2_512_224:
        case ALG_HASH_LSH_256_224:
        case ALG_HASH_LSH_512_224:
        case ALG_HASH_SHA3_224:
            return 28u;
        case ALG_HASH_SHA2_256:
        case ALG_HASH_SHA2_512_256:
        case ALG_HASH_LSH_256_256:
        case ALG_HASH_LSH_512_256:
        case ALG_HASH_SHA3_256:
            return 32u;
        case ALG_HASH_SHA2_384:
        case ALG_HASH_LSH_512_384:
        case ALG_HASH_SHA3_384:
            return 48u;
        case ALG_HASH_SHA2_512:
        case ALG_HASH_LSH_512_512:
        case ALG_HASH_SHA3_512:
            return 64u;
        default:
            return 0u;
    }
}

CryptoError CRYPTO_HASH(
    uint8_t *OUTPUT, size_t OUTPUT_LENGTH,
    const uint8_t *INPUT, size_t INPUT_LENGTH,
    AlgID ALG) {
    const size_t digest_length = fixed_digest_length(ALG);

    if ((INPUT == NULL && INPUT_LENGTH != 0u) ||
        (OUTPUT == NULL && OUTPUT_LENGTH != 0u)) {
        return CRYPTO_ERROR_INVALID_ARGUMENT;
    }

    if (ALG == ALG_HASH_SHAKE128 || ALG == ALG_HASH_SHAKE256) {
        return crypto_sha3_hash(
            OUTPUT, OUTPUT_LENGTH, INPUT, INPUT_LENGTH, ALG);
    }
    if (digest_length == 0u) {
        return CRYPTO_ERROR_INVALID_ALG_ID;
    }
    if (OUTPUT == NULL || OUTPUT_LENGTH < digest_length) {
        return CRYPTO_ERROR_BUFFER_TOO_SMALL;
    }

    switch (ALG) {
        case ALG_HASH_SHA2_224:
        case ALG_HASH_SHA2_256:
        case ALG_HASH_SHA2_384:
        case ALG_HASH_SHA2_512:
        case ALG_HASH_SHA2_512_224:
        case ALG_HASH_SHA2_512_256:
            return crypto_sha2_hash(
                OUTPUT, OUTPUT_LENGTH, INPUT, INPUT_LENGTH, ALG);

        case ALG_HASH_LSH_256_224:
        case ALG_HASH_LSH_256_256:
        case ALG_HASH_LSH_512_224:
        case ALG_HASH_LSH_512_256:
        case ALG_HASH_LSH_512_384:
        case ALG_HASH_LSH_512_512:
            return crypto_lsh_hash(
                OUTPUT, OUTPUT_LENGTH, INPUT, INPUT_LENGTH, ALG);

        default:
            return crypto_sha3_hash(
                OUTPUT, OUTPUT_LENGTH, INPUT, INPUT_LENGTH, ALG);
    }
}
