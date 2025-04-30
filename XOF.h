#pragma once
#ifndef XOF_H
#define XOF_H

#include <openssl/evp.h>

// 초기화 함수 선언
void XOF_init(EVP_MD_CTX** ctx);

// 데이터 흡수 함수 선언
void XOF_absorb(EVP_MD_CTX* ctx, char* str);

// 스퀴즈 함수 선언
unsigned char* XOF_squeeze(EVP_MD_CTX* ctx, unsigned int length);

#endif // XOF_H