#ifndef K_PKE_H
#define K_PKE_H

void K_PKE_KeyGen(unsigned char* d, unsigned char* ek_pke, unsigned char* dk_pke);

void K_PKE_Enc(unsigned char* ek_pke, unsigned char* message, unsigned char* randomness, unsigned char* ciphertext);

void K_PKE_Dec(unsigned char* dk_pke, unsigned char* ciphertext, unsigned char* message_);

#endif // K_PKE_H