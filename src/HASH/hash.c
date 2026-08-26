#include "HASH.h"
#include "SHA3.h"

size_t CRYPTO_HASH_OUTPUT_SIZE(AlgID alg) {
    switch (alg) {
        case ALG_HASH_SHA3_256: return SHA3_256_DIGEST_SIZE;
        case ALG_HASH_SHA3_512: return SHA3_512_DIGEST_SIZE;
        case ALG_HASH_SHAKE128:
        case ALG_HASH_SHAKE256:
            return 0;
        default:
            return 0;
    }
}

CryptoError CRYPTO_HASH(AlgID alg, const uint8_t *input, size_t input_len, uint8_t *output, size_t output_len) {
    if ((!input && input_len) || (!output && output_len)) return CRYPTO_ERROR_INVALID_ARGUMENT;
    switch (alg) {
        case ALG_HASH_SHA3_256:
            if (!output || output_len < SHA3_256_DIGEST_SIZE) return CRYPTO_ERROR_BUFFER_TOO_SMALL;
            CRYPTO_SHA3_256(output, input, input_len);
            return CRYPTO_SUCCESS;
        case ALG_HASH_SHA3_512:
            if (!output || output_len < SHA3_512_DIGEST_SIZE) return CRYPTO_ERROR_BUFFER_TOO_SMALL;
            CRYPTO_SHA3_512(output, input, input_len);
            return CRYPTO_SUCCESS;
        case ALG_HASH_SHAKE128:
            if (!output && output_len) return CRYPTO_ERROR_INVALID_ARGUMENT;
            CRYPTO_SHAKE128(output, output_len, input, input_len);
            return CRYPTO_SUCCESS;
        case ALG_HASH_SHAKE256:
            if (!output && output_len) return CRYPTO_ERROR_INVALID_ARGUMENT;
            CRYPTO_SHAKE256(output, output_len, input, input_len);
            return CRYPTO_SUCCESS;
        default:
            return CRYPTO_ERROR_INVALID_ALG_ID;
    }
}
