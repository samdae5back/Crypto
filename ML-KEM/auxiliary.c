#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hash.h"
#include "NTT_.h"
#include "auxiliary.h"
#include "parameter.h"

int exp_int(int x, int exp) {
    int r = 1;
    while (exp > 0) {
        if (exp % 2 == 1) {
            r = (r * x);
        }
        x = x * x;
        exp /= 2;
    }
    return r;
}

void Bit2Byte(unsigned char* b, unsigned char* B, size_t output_length) {
    if (B == NULL) {
        perror("Bit2Byte Failed ");
        exit(EXIT_FAILURE);
    }
    memset(B, 0, sizeof(unsigned char) * output_length);
    for (int i = 0;i < 8 * output_length;i++) {
        B[i / 8] += b[i] * exp_int(2, i % 8);
    }
    return;
}

void Byte2Bit(unsigned char* B, unsigned char* b, size_t input_length) {
    if (B == NULL) {
        perror("Byte2Bit Failed ");
        exit(EXIT_FAILURE);
    }
    unsigned char t = 0;
    for (int i = 0;i < input_length;i++) {
        t = B[i];
        for (int j = 0;j < 8;j++) {
            b[(8 * i) + j] = t % 2;
            t /= 2;
        }
    }
    return;
}

void ByteEncode(int* F, size_t d, unsigned char* output) {
    if (d < 1 || d > 12) {
        perror("Err : bit length incorrect");
        exit(EXIT_FAILURE);
    }
    unsigned char* b = (unsigned char*)malloc(sizeof(unsigned char) * d * 256);
    if (b == NULL) {
        perror("Failed to allocate memory for b"); // 오류 메시지 출력
        exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
    }
    for (int i = 0;i < 256;i++) {
        int t = F[i];
        for (int j = 0;j < d;j++) {
            b[i * d + j] = t % 2;
            t = (t - b[i * d + j]) / 2;
        }
    }
    size_t output_length = sizeof(unsigned char) * d * 32;
    Bit2Byte(b, output, output_length);
    free(b);
}
void ByteDecode(unsigned char* B, size_t d, int* output) {
    int m = 0;
    if (d == 12) {
        m = q;
    }
    else if (d > 13 || d < 1) {
        perror("Err : bit length incorrect");
        exit(EXIT_FAILURE);
    }
    else {
        m = exp_int(2, d);
    }
    unsigned char* b = (unsigned char*)malloc(sizeof(unsigned char) * d * n);
    if (b == NULL) {
        perror("Failed to allocate memory for b");
        exit(EXIT_FAILURE);
    }
    size_t input_size = sizeof(unsigned char) * d * 32;
    Byte2Bit(B, b, input_size);
    memset(output, 0, sizeof(int) * n);
    for (int i = 0;i < n;i++) {
        for (int j = 0;j < d;j++) {
            output[i] = (output[i] + (b[i * d + j] * exp_int(2, j))) % m;
        }
    }
    free(b);
}

void SampleNTT(unsigned char* B, int* a, size_t input_length) {
    EVP_MD_CTX* ctx = NULL;
    int l = 3;
    XOF_init(&ctx);
    if (ctx != NULL) {
        XOF_absorb(ctx, B, input_length);
    }
    else {
        fprintf(stderr, "Error initializing SHAKE-128 context in SampleNTT.\n");
        EVP_cleanup();
        return;
    }
    int t[3] = { 0 };
    int j = 0;
    while (j < n) {
        unsigned char* m = XOF_squeeze(ctx, l);

        //int 형으로 형변환
        t[0] = m[0];
        t[1] = m[1];
        t[2] = m[2];

        int d1 = (t[0] + n * (t[1] % 16));
        int d2 = ((t[1] / 16) + (16 * t[2]));
        if (d1 < q) {
            a[j] = d1;
            j++;
        }
        if (d2 < q && j < n) {
            a[j] = d2;
            j++;
        }
        free(m);// 스퀴즈 결과 메모리 해제
    }
    EVP_MD_CTX_free(ctx); // 컨텍스트 해제
}

void SamplePolyCBD(unsigned char* B, int* f, size_t input_length) {
    int n_ = (int)(input_length / 64);
    if (n_ != 2 && n_ != 3) {
        perror("Input length error SamplePolyCBD");
        exit(EXIT_FAILURE);
    }
    unsigned char* b = (unsigned char*)malloc(sizeof(unsigned char) * input_length * 8);
    if (b == NULL) {
        perror("Failed to allocate memory for b");
        exit(EXIT_FAILURE);
    }
    Byte2Bit(B, b, input_length);
    for (int i = 0;i < 256;i++) {
        int x = 0;
        int y = 0;
        unsigned char* b_p_x = b + (2 * i) * n_;
        unsigned char* b_p_y = b + (2 * i + 1) * n_;
        for (int j = 0;j < n_;j++) {
            x += b_p_x[j];
            y += b_p_y[j];
        }
        f[i] = (x - y + q) % q;
    }
    free(b);
}

void Comp(int* input, int d, int* output, size_t inout_length) {
    int pow2 = exp_int(2, d);
    int half_q = q / 2;
    for (int i = 0;i < inout_length;i++) {
        output[i] = (pow2 * input[i] + half_q) / q;
        output[i] = output[i] % pow2;
    }
    return;
}

void Decomp(int* input, int d, int* output, size_t inout_length) {
    int pow2 = exp_int(2, d);
    int half_pow2 = exp_int(2, d - 1);
    for (int i = 0;i < inout_length;i++) {
        output[i] = (q * input[i] + half_pow2) / pow2;
    }
    return;
}
