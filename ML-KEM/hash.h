#pragma once
#ifndef HASH_H
#define HASH_H

#include <openssl/evp.h>

void sha3_256_hash(const unsigned char* input, size_t input_len, unsigned char* output);

void sha3_512_hash(const unsigned char* input, size_t input_len, unsigned char* output);

void shake_256_hash(const unsigned char* input, size_t input_len, unsigned char* output, size_t output_len);

void PRF(size_t n, unsigned char* s, unsigned char* b, unsigned char* output);

void H(unsigned char* input, unsigned char* output);

void J(unsigned char* input, unsigned char* output);

void G(unsigned char* input, unsigned char* output_1, unsigned char* output_2);

// 초기화 함수 선언
void XOF_init(EVP_MD_CTX** ctx);

// 데이터 흡수 함수 선언
void XOF_absorb(EVP_MD_CTX* ctx, unsigned char* str, size_t input_length);

// 스퀴즈 함수 선언
unsigned char* XOF_squeeze(EVP_MD_CTX* ctx, size_t length);

#endif // XOF_H