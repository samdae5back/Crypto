#include "BlockCipher.h"
#include "BlockCipher/AES/aes_internal.h"

typedef struct {
    size_t KEY_LENGTH;
    CryptoAesMode MODE;
} BlockCipherParameters;

/* Whitelist complete parameter-set identifiers; partial/malformed IDs fail. */
static CryptoError block_cipher_parameters(AlgID alg,
                                           BlockCipherParameters *parameters) {
    size_t key_length;
    CryptoAesMode mode;

    switch (alg) {
        case ALG_AES_128_ECB:
            key_length = CRYPTO_AES_128_KEY_BYTES;
            mode = CRYPTO_AES_MODE_ECB;
            break;
        case ALG_AES_192_ECB:
            key_length = CRYPTO_AES_192_KEY_BYTES;
            mode = CRYPTO_AES_MODE_ECB;
            break;
        case ALG_AES_256_ECB:
            key_length = CRYPTO_AES_256_KEY_BYTES;
            mode = CRYPTO_AES_MODE_ECB;
            break;
        case ALG_AES_128_CBC:
            key_length = CRYPTO_AES_128_KEY_BYTES;
            mode = CRYPTO_AES_MODE_CBC;
            break;
        case ALG_AES_192_CBC:
            key_length = CRYPTO_AES_192_KEY_BYTES;
            mode = CRYPTO_AES_MODE_CBC;
            break;
        case ALG_AES_256_CBC:
            key_length = CRYPTO_AES_256_KEY_BYTES;
            mode = CRYPTO_AES_MODE_CBC;
            break;
        case ALG_AES_128_CTR:
            key_length = CRYPTO_AES_128_KEY_BYTES;
            mode = CRYPTO_AES_MODE_CTR;
            break;
        case ALG_AES_192_CTR:
            key_length = CRYPTO_AES_192_KEY_BYTES;
            mode = CRYPTO_AES_MODE_CTR;
            break;
        case ALG_AES_256_CTR:
            key_length = CRYPTO_AES_256_KEY_BYTES;
            mode = CRYPTO_AES_MODE_CTR;
            break;
        case ALG_AES_128_CCM:
            key_length = CRYPTO_AES_128_KEY_BYTES;
            mode = CRYPTO_AES_MODE_CCM;
            break;
        case ALG_AES_192_CCM:
            key_length = CRYPTO_AES_192_KEY_BYTES;
            mode = CRYPTO_AES_MODE_CCM;
            break;
        case ALG_AES_256_CCM:
            key_length = CRYPTO_AES_256_KEY_BYTES;
            mode = CRYPTO_AES_MODE_CCM;
            break;
        case ALG_AES_128_GCM:
            key_length = CRYPTO_AES_128_KEY_BYTES;
            mode = CRYPTO_AES_MODE_GCM;
            break;
        case ALG_AES_192_GCM:
            key_length = CRYPTO_AES_192_KEY_BYTES;
            mode = CRYPTO_AES_MODE_GCM;
            break;
        case ALG_AES_256_GCM:
            key_length = CRYPTO_AES_256_KEY_BYTES;
            mode = CRYPTO_AES_MODE_GCM;
            break;
        default:
            return CRYPTO_ERROR_INVALID_ALG_ID;
    }

    if (parameters) {
        parameters->KEY_LENGTH = key_length;
        parameters->MODE = mode;
    }
    return CRYPTO_SUCCESS;
}

size_t CRYPTO_BLOCK_CIPHER_KEY_SIZE(AlgID ALG) {
    BlockCipherParameters parameters;

    if (block_cipher_parameters(ALG, &parameters) != CRYPTO_SUCCESS)
        return 0u;
    return parameters.KEY_LENGTH;
}

CryptoError CRYPTO_BLOCK_CIPHER_ENCRYPT(
    uint8_t *OUTPUT, size_t OUTPUT_CAPACITY,
    uint8_t *TAG, size_t TAG_LENGTH,
    const uint8_t *INPUT, size_t INPUT_LENGTH,
    const uint8_t *KEY, size_t KEY_LENGTH,
    const uint8_t *IV, size_t IV_LENGTH,
    const uint8_t *AAD, size_t AAD_LENGTH,
    AlgID ALG) {
    BlockCipherParameters parameters;
    CryptoError err = block_cipher_parameters(ALG, &parameters);

    if (err != CRYPTO_SUCCESS) return err;
    return crypto_aes_encrypt(
        OUTPUT, OUTPUT_CAPACITY, TAG, TAG_LENGTH,
        INPUT, INPUT_LENGTH, KEY, KEY_LENGTH,
        IV, IV_LENGTH, AAD, AAD_LENGTH,
        parameters.KEY_LENGTH, parameters.MODE);
}

CryptoError CRYPTO_BLOCK_CIPHER_DECRYPT(
    uint8_t *OUTPUT, size_t OUTPUT_CAPACITY,
    const uint8_t *TAG, size_t TAG_LENGTH,
    const uint8_t *INPUT, size_t INPUT_LENGTH,
    const uint8_t *KEY, size_t KEY_LENGTH,
    const uint8_t *IV, size_t IV_LENGTH,
    const uint8_t *AAD, size_t AAD_LENGTH,
    AlgID ALG) {
    BlockCipherParameters parameters;
    CryptoError err = block_cipher_parameters(ALG, &parameters);

    if (err != CRYPTO_SUCCESS) return err;
    return crypto_aes_decrypt(
        OUTPUT, OUTPUT_CAPACITY, TAG, TAG_LENGTH,
        INPUT, INPUT_LENGTH, KEY, KEY_LENGTH,
        IV, IV_LENGTH, AAD, AAD_LENGTH,
        parameters.KEY_LENGTH, parameters.MODE);
}
