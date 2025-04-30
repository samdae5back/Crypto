#pragma once
#ifndef SHA3_512_H
#define SHA3_512_H

#include <stddef.h> // size_t Ÿ���� ���� ����

// �Լ� ����
void sha3_512_hash(const unsigned char* input, size_t input_len, unsigned char* output);


#define SHA3_512_DIGEST_LENGTH 64 // SHA3-512 �ؽ� ���� ���� (����Ʈ)

#endif // SHA3_512_H