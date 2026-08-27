#include "Def.h"
#include "BlockCipher.h"
#include "HashFunction.h"
#include "RandomNumberGeneration.h"
#include "Util.h"
#include "AsymmetricCipher.h"
#include "KeyEncapsulation.h"
#include "DigitalSignature.h"
#include "Crypto.h"

int main(void) {
    CRYPTO_BIGNUM value;
    CRYPTO_CTR_DRBG_CONTEXT drbg;
    AlgID alg = ALG_HASH_SHA2_256;
    CryptoError error = CRYPTO_SUCCESS;

    (void)value;
    (void)drbg;
    (void)alg;
    (void)error;
    return 0;
}
