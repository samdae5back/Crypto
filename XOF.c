#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

//초기화 함수 (외부에서 ctx 이중 포인터 형태로 받아서 *ctx가 초기화된 값의 주소를 가리키도록 함)
void XOF_init(EVP_MD_CTX** ctx) {
    EVP_MD_CTX* mdctx = NULL;
    const EVP_MD* shake128 = NULL;

    OpenSSL_add_all_digests();
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

//데이터 흡수 함수
void XOF_absorb(EVP_MD_CTX* ctx, char* str) {
    if (ctx == NULL) {
        fprintf(stderr, "Error: Message Digest Context is NULL in XOF_absorb.\n");
        EVP_cleanup();
        return;
    }

    if (str == NULL) {
        fprintf(stderr, "Warning: Input message is NULL in XOF_absorb.\n");
        return;
    }

    size_t len = strlen(str);
    printf("Absorbing data block ...\n");
    if (!EVP_DigestUpdate(ctx, str, len)) {
        fprintf(stderr, "Error: EVP_DigestUpdate (block 1) failed.\n");
        if (ctx) {
            EVP_MD_CTX_free(ctx);
        }
        EVP_cleanup();
        return;
    }
    return;
}

//스퀴즈 함수
unsigned char* XOF_squeeze(EVP_MD_CTX* ctx, unsigned int length) {
    if (ctx == NULL || length <= 0) {
        fprintf(stderr, "Error: Invalid input to XOF_squeeze.\n");
        return NULL;
    }

    unsigned char* output = (unsigned char*)malloc(sizeof(unsigned char) * length);
    if (output == NULL) {
        perror("malloc failed in XOF_squeeze (output)");
        return NULL;
    }

    printf("Squeezing output (%d bytes)...\n", length);
    if (!EVP_DigestFinalXOF(ctx, output, length)) {
        fprintf(stderr, "Error: EVP_DigestFinalXOF (first squeeze) failed.\n");
        if (ctx) {
            EVP_MD_CTX_free(ctx);
        }
        EVP_cleanup();
        free(output);
        return NULL;
    }
    unsigned char* r = (unsigned char*)malloc(sizeof(unsigned char) * length);
    if (r == NULL) {
        perror("malloc failed in XOF_squeeze (r)");
        free(output);
        free(r);
        return NULL;
    }

    printf("SHAKE-128 Output (first %d bytes, hex): ", length);
    for (unsigned int i = 0; i < length; i++) {
        r[i] = output[i];
        printf("%02x", output[i]);
    }
    printf("\n");

    free(output);

    return r;
}

/*
int main() {
    EVP_MD_CTX* mdctx = NULL;
    const EVP_MD* shake128 = NULL;
    unsigned char output[32]; // 원하는 출력 길이 (조정 가능)
    unsigned int output_len = sizeof(output);
    const char* message1 = "Data block 1 to be absorbed.";
    const char* message2 = "Another data block.";
    size_t len1 = strlen(message1);
    size_t len2 = strlen(message2);

    OpenSSL_add_all_digests();

    // 1. shake.init (EVP_DigestInit_ex)
    shake128 = EVP_shake128();
    if (!shake128) {
        fprintf(stderr, "Error: SHAKE-128 algorithm not found.\n");
        goto err;
    }

    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        perror("EVP_MD_CTX_new failed");
        goto err;
    }

    if (!EVP_DigestInit_ex(mdctx, shake128, NULL)) {
        fprintf(stderr, "Error: EVP_DigestInit_ex failed.\n");
        goto err;
    }

    // 2. shake.absorb (EVP_DigestUpdate - 여러 번 호출 가능)
    printf("Absorbing data block 1...\n");
    if (!EVP_DigestUpdate(mdctx, message1, len1)) {
        fprintf(stderr, "Error: EVP_DigestUpdate (block 1) failed.\n");
        goto err;
    }

    printf("Absorbing data block 2...\n");
    if (!EVP_DigestUpdate(mdctx, message2, len2)) {
        fprintf(stderr, "Error: EVP_DigestUpdate (block 2) failed.\n");
        goto err;
    }

    // 3. shake.squeeze (EVP_DigestFinalXOF - 원하는 길이만큼 반복 호출 가능)
    printf("Squeezing output (first %u bytes)...\n", output_len);
    if (!EVP_DigestFinalXOF(mdctx, output, output_len)) {
        fprintf(stderr, "Error: EVP_DigestFinalXOF (first squeeze) failed.\n");
        goto err;
    }

    printf("SHAKE-128 Output (first %u bytes, hex): ", output_len);
    for (unsigned int i = 0; i < output_len; i++) {
        printf("%02x", output[i]);
    }
    printf("\n");

    // 추가적인 짜내기 (squeeze) 예시
    unsigned char output2[16];
    unsigned int output2_len = sizeof(output2);
    printf("Squeezing more output (%u bytes)...\n", output2_len);
    if (!EVP_DigestFinalXOF(mdctx, output2, output2_len)) {
        fprintf(stderr, "Error: EVP_DigestFinalXOF (second squeeze) failed.\n");
        goto err;
    }

    printf("SHAKE-128 Output (next %u bytes, hex): ", output2_len);
    for (unsigned int i = 0; i < output2_len; i++) {
        printf("%02x", output2[i]);
    }
    printf("\n");

err:
    if (mdctx) {
        EVP_MD_CTX_free(mdctx);
    }
    EVP_cleanup();
    return 0;
}
*/