#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include "hash.h"
#include "parameter.h"

int exp(int x, int exp) {
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
        perror("Failed to allocate memory for input of Bit2Byte"); // 오류 메시지 출력
        exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
    }
    for (int i = 0;i < output_length;i++) {
        B[i] = 0;
    }
    for (int i = 0;i < 8 * output_length;i++) {
        B[i / 8] = B[i / 8] + b[i] * exp(2, i % 8);
    }
    return;
}

void Byte2Bit(unsigned char* B, unsigned char* b, size_t input_length) {
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
        m = exp(2, d);
    }
    unsigned char* b = (unsigned char*)malloc(sizeof(unsigned char) * d * 256);
    if (b == NULL) {
        perror("Failed to allocate memory for b"); // 오류 메시지 출력
        exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
    }
    size_t input_size = sizeof(unsigned char) * d * 32;
    Byte2Bit(B, b, input_size);
    for (int i = 0;i < 256;i++) {
        output[i] = 0;
        for (int j = 0;j < d;j++) {
            output[i] = (output[i] + (b[i * d + j] * exp(2, j))) % m;
        }
    }
    free(b);
}

void SampleNTT(unsigned char* B, int* a, size_t input_length) {
    EVP_MD_CTX* ctx = NULL;
    int l = 3;
    unsigned char* m = (unsigned char*)malloc(sizeof(unsigned char) * l);
    if (m == NULL) {
        perror("Failed to allocate memory for m"); // 오류 메시지 출력
        exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
    }
    XOF_init(&ctx);
    if (ctx != NULL) { // 초기화 성공 여부 확인
        XOF_absorb(ctx, B, input_length);//메세지 흡수
    }
    else {
        fprintf(stderr, "Error initializing SHAKE-128 context in SampleNTT.\n");
        EVP_cleanup();
        return ; // 오류 발생 시 0이 아닌 값 반환
    }
    int j = 0;
    while (j < 256) {
        m = XOF_squeeze(ctx, l);
        for (int i = 0; i < l; i++) {
            // printf("%u  ", m[i]);
        }
        unsigned char d1 = m[0] + 256 * (m[1] % 16);
        unsigned char d2 = (m[1] / 16) + (16 * m[2]);
        if (d1 < q) {
            a[j] = d1;
            j++;
        }
        if (d2 < q && j < 256) {
            a[j] = d2;
            j++;
        }
    }
    free(m); // 스퀴즈 결과 메모리 해제
    EVP_MD_CTX_free(ctx); // 컨텍스트 해제
    EVP_cleanup();
}

void SamplePolyCBD(unsigned char* B, int* f, size_t input_length) {
    size_t n = input_length / 64;
    if (input_length != 128 && input_length != 192) {
        perror("Input length error SamplePolyCBD");
        exit(EXIT_FAILURE);
    }
    unsigned char* b = (unsigned char*)malloc(sizeof(unsigned char) * input_length * 8);
    if (b == NULL) {
        perror("Failed to allocate memory for b"); // 오류 메시지 출력
        exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
    }
    Byte2Bit(B, b, input_length);
    for (int i = 0;i < 256;i++) {
        int x = 0;
        int y = 0;
        for (int j = 0;j < n;j++) {
            x = x + b[((2 * i) * n) + j];
        }
        for (int j = 0;j < n;j++) {
            y = y + b[((2 * i) * n) + n + j];
        }
        f[i] = (x - y + q) % q;
    }
    free(b);
}

void Comp(int* input, int d, int* output, size_t inout_length) {
    for (int i = 0;i < inout_length;i++) {
        output[i] = (exp(2, d) * input[i]) / q;
        if (((exp(2, d) * input[i]) % q) > (q / 2)) {
            output[i]++;
        }
        output[i] = output[i] % (exp(2, d));
    }
    
    return;
}

void Decomp(int* input, int d, int* output, size_t inout_length) {
    for (int i = 0;i < inout_length;i++) {
        output[i] = (q * input[i]) / (exp(2, d));
        if (((q * input[i]) % exp(2, d)) > ((exp(2, d)) / 2)) {
            output[i] = output[i] + 1;
        }
    }
    return;
}

/*
int main() {
    unsigned char* A = (char*)malloc(sizeof(unsigned char) * 256);
    if (A == NULL) {
        perror("Failed to allocate memory for A"); // 오류 메시지 출력
        exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
    }
    SampleNTT("test message 122314142324234234251", A);
    for (int i = 0;i < 256;i++) {
        printf("%u ", A[i]);
    }
    size_t l = _msize(A) / sizeof(unsigned char);
    printf("\n size of A %zu \n", l);

    unsigned char* a = (char*)malloc(sizeof(unsigned char) * 256 * 8);
    if (a == NULL) {
        perror("Failed to allocate memory for a"); // 오류 메시지 출력
        exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
    }
    Byte2Bit(A, a);
    for (int i = 0;i < 256*8;i++) {
        printf("%u ", a[i]);
    }
    unsigned char* Aa = (char*)malloc(sizeof(unsigned char) * 256);
    if (Aa == NULL) {
        perror("Failed to allocate memory for Aa"); // 오류 메시지 출력
        exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
    }
    printf("\n");
    Bit2Byte(a, Aa);
    for (int i = 0;i < 256;i++) {
        printf("%u ", Aa[i]);
        if (A[i] != Aa[i]) {
            printf("Error");
            return 0;
        }
        
    }
    free(a);

    
    unsigned char* alpha = "alpha";
    unsigned char* beta = "beta";
    printf("%s", alpha);

    return 0;
    

}
*/