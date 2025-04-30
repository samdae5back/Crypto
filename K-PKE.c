#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "XOF.h"

int main() {
    EVP_MD_CTX* ctx = NULL;
    unsigned int l = 3;
    unsigned char* m = (char*)malloc(sizeof(unsigned char) * l);
    XOF_init(&ctx);
    if (ctx != NULL) { // 초기화 성공 여부 확인
        XOF_absorb(ctx, "message");
        m = XOF_squeeze(ctx, l);
        for (unsigned int i = 0; i < l; i++) {
            // printf("%u  ", m[i]);
        }
        free(m); // 스퀴즈 결과 메모리 해제
        EVP_MD_CTX_free(ctx); // 컨텍스트 해제
        EVP_cleanup();
    }
    else {
        fprintf(stderr, "Error initializing SHAKE-128 context.\n");
        EVP_cleanup();
        return 1; // 오류 발생 시 0이 아닌 값 반환
    }
}
