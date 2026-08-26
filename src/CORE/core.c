#include "ALGID.h"
#include "ERROR.h"

const char *ALGID_NAME(AlgID alg) {
    switch (alg) {
        case ALG_HASH_SHA3_256: return "SHA3-256";
        case ALG_HASH_SHA3_512: return "SHA3-512";
        case ALG_HASH_SHAKE128: return "SHAKE128";
        case ALG_HASH_SHAKE256: return "SHAKE256";
        case ALG_ML_KEM_512: return "ML-KEM-512";
        case ALG_ML_KEM_768: return "ML-KEM-768";
        case ALG_ML_KEM_1024: return "ML-KEM-1024";
        case ALG_RSA_RAW: return "RSA-RAW";
        case ALG_ELGAMAL_SAFE_PRIME: return "ELGAMAL-SAFE-PRIME";
        case ALG_NTT_GENERIC: return "NTT-GENERIC";
        case ALG_AES_128: return "AES-128";
        case ALG_AES_192: return "AES-192";
        case ALG_AES_256: return "AES-256";
        case ALG_NONE: return "NONE";
        default: return "UNKNOWN";
    }
}

const char *CRYPTO_ERROR_STRING(CryptoError error) {
    switch (error) {
        case CRYPTO_SUCCESS: return "success";
        case CRYPTO_ERROR_INVALID_ARGUMENT: return "invalid argument";
        case CRYPTO_ERROR_INVALID_ALG_ID: return "invalid algorithm identifier";
        case CRYPTO_ERROR_UNSUPPORTED_ALGORITHM: return "unsupported algorithm";
        case CRYPTO_ERROR_BUFFER_TOO_SMALL: return "buffer too small";
        case CRYPTO_ERROR_ALLOCATION_FAILED: return "memory allocation failed";
        case CRYPTO_ERROR_RANDOM_FAILED: return "operating-system random source failed";
        case CRYPTO_ERROR_INVALID_KEY: return "invalid key";
        case CRYPTO_ERROR_MESSAGE_TOO_LARGE: return "message is too large for the selected key";
        case CRYPTO_ERROR_PRIME_GENERATION_FAILED: return "prime generation failed";
        case CRYPTO_ERROR_ARITHMETIC: return "arithmetic operation failed";
        case CRYPTO_ERROR_INTERNAL: return "internal error";
        default: return "unknown error";
    }
}
