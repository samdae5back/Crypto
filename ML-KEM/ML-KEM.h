#pragma once

void ML_KEM_KeyGen(unsigned char** ek, unsigned char** dk);

void ML_KEM_Encaps(unsigned char** ek, unsigned char* SharedSecretKey, unsigned char** c);

void ML_KEM_Decaps(unsigned char** dk, unsigned char** c, unsigned char* SharedSecretKey_);