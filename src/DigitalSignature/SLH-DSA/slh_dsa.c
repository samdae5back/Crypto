#include "SLH_DSA.h"
#include "RANDOM.h"
#include "Util/Core/secure_zero.h"
/* Use an explicit path: Windows treats this like the public SLH_DSA.h name. */
#include "../../../third_party/slhdsa-c/slh_dsa.h"

static const slh_param_t *slh_dsa_parameters(AlgID alg) {
    switch (alg) {
        case ALG_SLH_DSA_SHA2_128S: return &slh_dsa_sha2_128s;
        case ALG_SLH_DSA_SHA2_128F: return &slh_dsa_sha2_128f;
        case ALG_SLH_DSA_SHA2_192S: return &slh_dsa_sha2_192s;
        case ALG_SLH_DSA_SHA2_192F: return &slh_dsa_sha2_192f;
        case ALG_SLH_DSA_SHA2_256S: return &slh_dsa_sha2_256s;
        case ALG_SLH_DSA_SHA2_256F: return &slh_dsa_sha2_256f;
        case ALG_SLH_DSA_SHAKE_128S: return &slh_dsa_shake_128s;
        case ALG_SLH_DSA_SHAKE_128F: return &slh_dsa_shake_128f;
        case ALG_SLH_DSA_SHAKE_192S: return &slh_dsa_shake_192s;
        case ALG_SLH_DSA_SHAKE_192F: return &slh_dsa_shake_192f;
        case ALG_SLH_DSA_SHAKE_256S: return &slh_dsa_shake_256s;
        case ALG_SLH_DSA_SHAKE_256F: return &slh_dsa_shake_256f;
        default: return NULL;
    }
}

size_t CRYPTO_SLH_DSA_PUBLIC_KEY_SIZE(AlgID ALG) {
    const slh_param_t *prm = slh_dsa_parameters(ALG);
    return prm ? slh_pk_sz(prm) : 0u;
}

size_t CRYPTO_SLH_DSA_PRIVATE_KEY_SIZE(AlgID ALG) {
    const slh_param_t *prm = slh_dsa_parameters(ALG);
    return prm ? slh_sk_sz(prm) : 0u;
}

size_t CRYPTO_SLH_DSA_SIGNATURE_SIZE(AlgID ALG) {
    const slh_param_t *prm = slh_dsa_parameters(ALG);
    return prm ? slh_sig_sz(prm) : 0u;
}

CryptoError CRYPTO_SLH_DSA_KEYGEN(AlgID ALG,
                           uint8_t *PUBLIC_KEY, size_t PUBLIC_KEY_LENGTH,
                           uint8_t *PRIVATE_KEY, size_t PRIVATE_KEY_LENGTH) {
    const slh_param_t *prm = slh_dsa_parameters(ALG);
    uint8_t seed[96];
    size_t pk_length, sk_length, n;
    CryptoError err;
    int rc;

    if (!prm) return CRYPTO_ERROR_INVALID_ALG_ID;
    if (!PUBLIC_KEY || !PRIVATE_KEY) return CRYPTO_ERROR_INVALID_ARGUMENT;
    pk_length = slh_pk_sz(prm);
    sk_length = slh_sk_sz(prm);
    if (PUBLIC_KEY_LENGTH < pk_length || PRIVATE_KEY_LENGTH < sk_length)
        return CRYPTO_ERROR_BUFFER_TOO_SMALL;
    n = pk_length / 2u;

    err = CRYPTO_RANDOM_BYTES(seed, 3u * n);
    if (err != CRYPTO_SUCCESS) {
        crypto_zeroize(PUBLIC_KEY, pk_length);
        crypto_zeroize(PRIVATE_KEY, sk_length);
        crypto_zeroize(seed, sizeof(seed));
        return err;
    }

    rc = slh_keygen_internal(PRIVATE_KEY, PUBLIC_KEY,
                             seed, seed + n, seed + 2u * n, prm);
    crypto_zeroize(seed, sizeof(seed));
    if (rc != 0) {
        crypto_zeroize(PUBLIC_KEY, pk_length);
        crypto_zeroize(PRIVATE_KEY, sk_length);
        return CRYPTO_ERROR_INTERNAL;
    }
    return CRYPTO_SUCCESS;
}

CryptoError CRYPTO_SLH_DSA_SIGN(AlgID ALG,
                         const uint8_t *PRIVATE_KEY, size_t PRIVATE_KEY_LENGTH,
                         const uint8_t *MESSAGE, size_t MESSAGE_LENGTH,
                         const uint8_t *CONTEXT, size_t CONTEXT_LENGTH,
                         uint8_t *SIGNATURE, size_t SIGNATURE_LENGTH) {
    const slh_param_t *prm = slh_dsa_parameters(ALG);
    uint8_t addrnd[32];
    size_t sk_length, sig_length, n, written;
    CryptoError err;

    if (!prm) return CRYPTO_ERROR_INVALID_ALG_ID;
    if (!PRIVATE_KEY || (!MESSAGE && MESSAGE_LENGTH) || (!CONTEXT && CONTEXT_LENGTH) || !SIGNATURE)
        return CRYPTO_ERROR_INVALID_ARGUMENT;
    if (CONTEXT_LENGTH > SLH_DSA_CONTEXT_MAX_BYTES) return CRYPTO_ERROR_INVALID_ARGUMENT;
    sk_length = slh_sk_sz(prm);
    sig_length = slh_sig_sz(prm);
    if (PRIVATE_KEY_LENGTH != sk_length) return CRYPTO_ERROR_INVALID_KEY;
    if (SIGNATURE_LENGTH < sig_length) return CRYPTO_ERROR_BUFFER_TOO_SMALL;
    n = slh_pk_sz(prm) / 2u;

    err = CRYPTO_RANDOM_BYTES(addrnd, n);
    if (err != CRYPTO_SUCCESS) {
        crypto_zeroize(SIGNATURE, sig_length);
        crypto_zeroize(addrnd, sizeof(addrnd));
        return err;
    }

    written = slh_sign(SIGNATURE, MESSAGE, MESSAGE_LENGTH,
                       CONTEXT, CONTEXT_LENGTH, PRIVATE_KEY, addrnd, prm);
    crypto_zeroize(addrnd, sizeof(addrnd));
    if (written != sig_length) {
        crypto_zeroize(SIGNATURE, sig_length);
        return CRYPTO_ERROR_INTERNAL;
    }
    return CRYPTO_SUCCESS;
}

CryptoError CRYPTO_SLH_DSA_VERIFY(AlgID ALG,
                           const uint8_t *PUBLIC_KEY, size_t PUBLIC_KEY_LENGTH,
                           const uint8_t *MESSAGE, size_t MESSAGE_LENGTH,
                           const uint8_t *CONTEXT, size_t CONTEXT_LENGTH,
                           const uint8_t *SIGNATURE, size_t SIGNATURE_LENGTH) {
    const slh_param_t *prm = slh_dsa_parameters(ALG);
    size_t pk_length, sig_length;

    if (!prm) return CRYPTO_ERROR_INVALID_ALG_ID;
    if (!PUBLIC_KEY || (!MESSAGE && MESSAGE_LENGTH) || (!CONTEXT && CONTEXT_LENGTH) || !SIGNATURE)
        return CRYPTO_ERROR_INVALID_ARGUMENT;
    if (CONTEXT_LENGTH > SLH_DSA_CONTEXT_MAX_BYTES) return CRYPTO_ERROR_INVALID_ARGUMENT;
    pk_length = slh_pk_sz(prm);
    sig_length = slh_sig_sz(prm);
    if (PUBLIC_KEY_LENGTH != pk_length) return CRYPTO_ERROR_INVALID_KEY;
    if (SIGNATURE_LENGTH != sig_length) return CRYPTO_ERROR_SIGNATURE_INVALID;

    return slh_verify(MESSAGE, MESSAGE_LENGTH, SIGNATURE, SIGNATURE_LENGTH,
                      CONTEXT, CONTEXT_LENGTH, PUBLIC_KEY, prm)
               ? CRYPTO_SUCCESS
               : CRYPTO_ERROR_SIGNATURE_INVALID;
}
