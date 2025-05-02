#include <openssl/evp.h> // 또는 <openssl/sha.h> 구버전 방식
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include "SHA3_512.h"

void sha3_256_hash(const unsigned char* input, size_t input_len, unsigned char* output) {
    EVP_MD_CTX* mdctx;
    const EVP_MD* md;
    unsigned int md_len;

    md = EVP_sha3_256(); // SHA3-256 알고리즘 가져오기
    mdctx = EVP_MD_CTX_new();

    if (mdctx == NULL || md == NULL) {
        // 오류 처리
        printf("Error setting up SHA3-256 context.\n");
        if (mdctx) EVP_MD_CTX_free(mdctx);
        return;
    }

    EVP_DigestInit_ex(mdctx, md, NULL); // 컨텍스트 초기화
    EVP_DigestUpdate(mdctx, input, input_len); // 해시할 데이터 업데이트
    EVP_DigestFinal_ex(mdctx, output, &md_len); // 최종 해시 값 계산 (output 버퍼는 최소 64바이트여야 함)

    EVP_MD_CTX_free(mdctx); // 컨텍스트 해제
}

void sha3_512_hash(const unsigned char* input, size_t input_len, unsigned char* output) {
    EVP_MD_CTX* mdctx;
    const EVP_MD* md;
    unsigned int md_len;

    md = EVP_sha3_512(); // SHA3-512 알고리즘 가져오기
    mdctx = EVP_MD_CTX_new();

    if (mdctx == NULL || md == NULL) {
        // 오류 처리
        printf("Error setting up SHA3-512 context.\n");
        if (mdctx) EVP_MD_CTX_free(mdctx);
        return;
    }

    EVP_DigestInit_ex(mdctx, md, NULL); // 컨텍스트 초기화
    EVP_DigestUpdate(mdctx, input, input_len); // 해시할 데이터 업데이트
    EVP_DigestFinal_ex(mdctx, output, &md_len); // 최종 해시 값 계산 (output 버퍼는 최소 64바이트여야 함)

    EVP_MD_CTX_free(mdctx); // 컨텍스트 해제
}

void shake_256_hash(const unsigned char* input, size_t input_len, unsigned char* output, size_t output_len) {
    EVP_MD_CTX* mdctx;
    const EVP_MD* md;
    unsigned int md_len;

    md = EVP_shake256(); // SHAKE-256 알고리즘 가져오기
    mdctx = EVP_MD_CTX_new();

    if (mdctx == NULL || md == NULL) {
        // 오류 처리
        printf("Error setting up SHAKE-256 context.\n");
        if (mdctx) EVP_MD_CTX_free(mdctx);
        return;
    }

    EVP_DigestInit_ex(mdctx, md, NULL); // 컨텍스트 초기화
    EVP_DigestUpdate(mdctx, input, input_len); // 해시할 데이터 업데이트
    EVP_DigestFinalXOF(mdctx, output, output_len); // 최종 해시 값 계산 (output 버퍼는 최소 64바이트여야 함)

    EVP_MD_CTX_free(mdctx); // 컨텍스트 해제
}

void PRF(size_t n, unsigned char* s, unsigned char* b, unsigned char* output) {
    if (_msize(s) != 32) {
        perror("Input length Error");
        exit(EXIT_FAILURE);
    }
    unsigned char* t = (unsigned char*)malloc(sizeof(unsigned char) * 33);
    if (t == NULL) {
        perror("Failed to allocate memory for t"); // 오류 메시지 출력
        exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
    }
    for (int i = 0;i < 32;i++) {
        t[i] = s[i];
    }
    t[32] = b;
    shake_256_hash(t, sizeof(unsigned char) * 33, output, 64 * n);
    free(t);
    return;
}


int main() {
    const char* message = "This is a test message.";
    unsigned char hash[EVP_MAX_MD_SIZE]; // 충분한 크기의 버퍼 (SHA3-512는 64바이트)
    size_t message_len = strlen(message);

    sha3_512_hash((const unsigned char*)message, message_len, hash);

    printf("%p\n",message);
    printf("SHA3-512 Hash: ");
    for (int i = 0; i < SHA3_512_DIGEST_LENGTH; i++) { // SHA3-512 출력은 64바이트
        printf("%02x ", hash[i]);
    }
    printf("\n");
    for (int i = 0; i < SHA3_512_DIGEST_LENGTH; i++) { // SHA3-512 출력은 64바이트
        printf("%u ", hash[i]);
    }
    printf("\n");
    unsigned char* t = (unsigned char*)malloc(sizeof(unsigned char) * 32);
    if (t == NULL) {
        perror("Failed to allocate memory for t"); // 오류 메시지 출력
        exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
    }
    for (int i = 0; i < 32; i++) { 
        t[i] = hash[i];
    }
    unsigned char* hash1 = (unsigned char*)malloc(sizeof(unsigned char) * 512);
    if (hash1 == NULL) {
        perror("Failed to allocate memory for t"); // 오류 메시지 출력
        exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
    }
    PRF(3, t, 12, hash1);
    printf("PRF\n");
    for (int i = 0; i < 512; i++) { // SHA3-512 출력은 64바이트
        printf("(%d)%u\n ",i, hash1[i]);
    }
    printf("\n");
    return 0;
}
