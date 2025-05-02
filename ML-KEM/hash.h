#pragma once
#ifndef HASH_H
#define HASH_H

#include <openssl/evp.h>

// �ʱ�ȭ �Լ� ����
void XOF_init(EVP_MD_CTX** ctx);

// ������ ��� �Լ� ����
void XOF_absorb(EVP_MD_CTX* ctx, char* str);

// ������ �Լ� ����
unsigned char* XOF_squeeze(EVP_MD_CTX* ctx, unsigned int length);

#endif // XOF_H