#include <openssl/evp.h> // 또는 <openssl/sha.h> 구버전 방식
#include <stdio.h>
#include <string.h>
#include "SHA3_512.h"

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

/*
int main() {
    const char* message = "This is a test message.";
    unsigned char hash[EVP_MAX_MD_SIZE]; // 충분한 크기의 버퍼 (SHA3-512는 64바이트)
    size_t message_len = strlen(message);

    sha3_512_hash((const unsigned char*)message, message_len, hash);

    printf("%p\n",message);
    printf("SHA3-512 Hash: ");
    for (int i = 0; i < SHA3_512_DIGEST_LENGTH; i++) { // SHA3-512 출력은 64바이트
        printf("%02x", hash[i]);
    }
    
    return 0;
}
*/