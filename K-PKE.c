#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "hash.h"


void SampleNTT(unsigned char* B, unsigned char* a) {
    EVP_MD_CTX* ctx = NULL;
    int q = 3329;
    unsigned int l = 3;
    unsigned char* m = (char*)malloc(sizeof(unsigned char) * l);
    if (m == NULL) {
        perror("Failed to allocate memory for m"); // 오류 메시지 출력
        exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
    }
    XOF_init(&ctx);
    if (ctx != NULL) { // 초기화 성공 여부 확인
        XOF_absorb(ctx, B);//메세지 흡수
    }
    else {
        fprintf(stderr, "Error initializing SHAKE-128 context in SampleNTT.\n");
        EVP_cleanup();
        return ; // 오류 발생 시 0이 아닌 값 반환
    }

    int j = 0;
    while (j < 256) {
        m = XOF_squeeze(ctx, l);
        for (unsigned int i = 0; i < l; i++) {
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

int main() {
    unsigned char* a = (char*)malloc(sizeof(unsigned char) * 256);
    if (a == NULL) {
        perror("Failed to allocate memory for a"); // 오류 메시지 출력
        exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
    }
    SampleNTT("test message", a);
    for (int i = 0;i < 256;i++) {
        printf("%u", a[i]);
    }
}
