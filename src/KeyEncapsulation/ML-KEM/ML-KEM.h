#ifndef ML_KEM_H
#define ML_KEM_H

#include "Def.h"

CryptoError ML_KEM_KeyGen_internal(const unsigned char seed[32],
                                   const unsigned char rejection_seed[32],
                                   unsigned char *public_key,
                                   unsigned char *private_key);
CryptoError ML_KEM_Encaps_internal(const unsigned char *public_key,
                                   const unsigned char message[32],
                                   unsigned char shared_secret[32],
                                   unsigned char *ciphertext);
CryptoError ML_KEM_Decaps_internal(const unsigned char *private_key,
                                   const unsigned char *ciphertext,
                                   unsigned char shared_secret[32]);

CryptoError ML_KEM_KeyGen(unsigned char *public_key,
                          unsigned char *private_key);
CryptoError ML_KEM_Encaps(const unsigned char *public_key,
                          unsigned char shared_secret[32],
                          unsigned char *ciphertext);
CryptoError ML_KEM_Decaps(const unsigned char *private_key,
                          const unsigned char *ciphertext,
                          unsigned char shared_secret[32]);

#endif
