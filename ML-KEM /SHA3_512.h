#pragma once
#ifndef SHA3_512_H
#define SHA3_512_H

#include <stddef.h> // size_t 타입을 위해 포함

// 함수 선언
void sha3_512_hash(const unsigned char* input, size_t input_len, unsigned char* output);


#define SHA3_512_DIGEST_LENGTH 64 // SHA3-512 해시 값의 길이 (바이트)

#endif // SHA3_512_H
