#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "NTT_.h"
#include "hash.h"
#include "parameter.h"


void RBG(unsigned char* seed, size_t len) {
    if (RAND_bytes(seed, len) == 1) {
        return;
    }
    else {
        perror("RBG failed");
        exit(EXIT_FAILURE);
    }
}

void sha3_256_hash(const unsigned char* input, size_t input_len, unsigned char* output) {
    EVP_MD_CTX* mdctx;
    const EVP_MD* md;
    unsigned int md_len;

    md = EVP_sha3_256(); // SHA3-256 �˰��� ��������
    mdctx = EVP_MD_CTX_new();

    if (mdctx == NULL || md == NULL) {
        // ���� ó��
        printf("Error setting up SHA3-256 context.\n");
        if (mdctx) EVP_MD_CTX_free(mdctx);
        return;
    }

    EVP_DigestInit_ex(mdctx, md, NULL); // ���ؽ�Ʈ �ʱ�ȭ
    EVP_DigestUpdate(mdctx, input, input_len); // �ؽ��� ������ ������Ʈ
    EVP_DigestFinal_ex(mdctx, output, &md_len); // ���� �ؽ� �� ��� (output ���۴� �ּ� 32����Ʈ���� ��)
    EVP_MD_CTX_free(mdctx); // ���ؽ�Ʈ ����
}

void sha3_512_hash(const unsigned char* input, size_t input_len, unsigned char* output) {
    EVP_MD_CTX* mdctx;
    const EVP_MD* md;
    unsigned int md_len;

    md = EVP_sha3_512(); // SHA3-512 �˰��� ��������
    mdctx = EVP_MD_CTX_new();

    if (mdctx == NULL || md == NULL) {
        // ���� ó��
        printf("Error setting up SHA3-512 context.\n");
        if (mdctx) EVP_MD_CTX_free(mdctx);
        return;
    }

    EVP_DigestInit_ex(mdctx, md, NULL); // ���ؽ�Ʈ �ʱ�ȭ
    EVP_DigestUpdate(mdctx, input, input_len); // �ؽ��� ������ ������Ʈ
    EVP_DigestFinal_ex(mdctx, output, &md_len); // ���� �ؽ� �� ��� (output ���۴� �ּ� 64����Ʈ���� ��)
    EVP_MD_CTX_free(mdctx); // ���ؽ�Ʈ ����
}

void shake_256_hash(const unsigned char* input, size_t input_len, unsigned char* output, size_t output_len) {
    EVP_MD_CTX* mdctx;
    const EVP_MD* md;

    md = EVP_shake256(); // SHAKE-256 �˰��� ��������
    mdctx = EVP_MD_CTX_new();

    if (mdctx == NULL || md == NULL) {
        // ���� ó��
        printf("Error setting up SHAKE-256 context.\n");
        if (mdctx) EVP_MD_CTX_free(mdctx);
        return;
    }

    EVP_DigestInit_ex(mdctx, md, NULL); // ���ؽ�Ʈ �ʱ�ȭ
    EVP_DigestUpdate(mdctx, input, input_len); // �ؽ��� ������ ������Ʈ
    EVP_DigestFinalXOF(mdctx, output, output_len); // ���� �ؽ� �� ���

    EVP_MD_CTX_free(mdctx); // ���ؽ�Ʈ ����
}

void PRF(size_t n_, unsigned char* s, unsigned char b, unsigned char* output) {
    //n=2 or n=3, s ������ 32, b ������ 1
    if (n_ != 2 && n_ != 3) {
        perror("Size Error");
        exit(EXIT_FAILURE);
    }
    unsigned char t[33] = { 0 };
    memcpy(t, s, 32);
    t[32] = b;
    shake_256_hash(t, sizeof(unsigned char) * 33, output, 64 * n_);
    return;
}

void H(unsigned char* input, size_t input_length, unsigned char* output) {
    sha3_256_hash(input, input_length, output);
}

void J(unsigned char* input, size_t input_length, unsigned char* output) {
    shake_256_hash(input, input_length, output, 32);
}

void G(unsigned char* input, size_t input_length, unsigned char* output_1, unsigned char* output_2) {
    unsigned char output[64] = { 0 };
    sha3_512_hash(input, input_length, output);
    memcpy(output_1, output, 32);
    memcpy(output_2, output + 32, 32);
}

//XOF �ʱ�ȭ �Լ� (�ܺο��� ctx ���� ������ ���·� �޾Ƽ� *ctx�� �ʱ�ȭ�� ���� �ּҸ� ����Ű���� ��)
void XOF_init(EVP_MD_CTX** ctx) {
    EVP_MD_CTX* mdctx = NULL;
    EVP_MD* shake128 = NULL;

    shake128 = EVP_shake128();
    if (!shake128) {
        fprintf(stderr, "Error: SHAKE-128 algorithm not found.\n");
        if (mdctx) {
            EVP_MD_CTX_free(mdctx);
        }
        EVP_cleanup();
        return;
    }
    
    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        perror("EVP_MD_CTX_new failed");
        if (mdctx) {
            EVP_MD_CTX_free(mdctx);
        }
        EVP_cleanup();
        return;
    }
    
    if (!EVP_DigestInit_ex(mdctx, shake128, NULL)) {
        fprintf(stderr, "Error: EVP_DigestInit_ex failed.\n");
        if (mdctx) {
            EVP_MD_CTX_free(mdctx);
        }
        EVP_cleanup();
        return;
    }
    *ctx = mdctx;
    return;
}

//XOF ������ ��� �Լ�
void XOF_absorb(EVP_MD_CTX* ctx, unsigned char* input, size_t input_length) {
    if (ctx == NULL) {
        fprintf(stderr, "Error: Message Digest Context is NULL in XOF_absorb.\n");
        EVP_cleanup();
        return;
    }
    if (input == NULL) {
        fprintf(stderr, "Warning: Input data is NULL in XOF_absorb.\n");
        return;
    }
    if (!EVP_DigestUpdate(ctx, input, input_length)) {
        fprintf(stderr, "Error: EVP_DigestUpdate (block 1) failed.\n");
        if (ctx) {
            EVP_MD_CTX_free(ctx);
        }
        EVP_cleanup();
        return;
    }
    return;
}

//XOF ������ �Լ�
unsigned char* XOF_squeeze(EVP_MD_CTX* ctx, size_t length) {
    if (ctx == NULL || length <= 0) {
        fprintf(stderr, "Error: Invalid input to XOF_squeeze.\n");
        return NULL;
    }
    unsigned char* output = (unsigned char*)malloc(sizeof(unsigned char) * length);
    if (output == NULL) {
        perror("malloc failed in XOF_squeeze (output)");
        return NULL;
    }
    if (!EVP_DigestSqueeze(ctx, output, length)) {
        fprintf(stderr, "Error: EVP_DigestSqueeze failed.\n");
        if (ctx) {
            EVP_MD_CTX_free(ctx);
        }
        EVP_cleanup();
        free(output);
        return NULL;
    }
    return output;
}