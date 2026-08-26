#ifndef ML_KEM_H
#define ML_KEM_H

void ML_KEM_KeyGen_internal(unsigned char* d, unsigned char* z, unsigned char* ek, unsigned char* dk);

void ML_KEM_Encaps_internal(unsigned char* ek, unsigned char* m, unsigned char* SharedSecretKey, unsigned char* ciphertext);

void ML_KEM_Decaps_internal(unsigned char* dk, unsigned char* ciphertext, unsigned char* SharedSecretKey_);

void ML_KEM_KeyGen(unsigned char* ek, unsigned char* dk);

void ML_KEM_Encaps(unsigned char* ek, unsigned char* SharedSecretKey, unsigned char* c);

void ML_KEM_Decaps(unsigned char* dk, unsigned char* c, unsigned char* SharedSecretKey_);

#endif // ML_KEM_H