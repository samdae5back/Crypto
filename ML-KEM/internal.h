#pragma once

void ML_KEM_KeyGen_internal(unsigned char* d, unsigned char* z, unsigned char** ek, unsigned char** dk);

void ML_KEM_Encaps_internal(unsigned char** ek, unsigned char* m, unsigned char* SharedSecretKey, unsigned char** ciphertext);

void ML_KEM_Decaps_internal(unsigned char** dk, unsigned char** ciphertext, unsigned char* SharedSecretKey_);