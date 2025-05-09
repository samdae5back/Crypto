#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>// _msize ��뿡 �ʿ�
#include "parameter.h"

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
    unsigned int md_len;

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

void PRF(size_t n, unsigned char* s, unsigned char b, unsigned char* output) {
    //n=2 or n=3, s ������ 32, b ������ 1
    if (n != 2 && n != 3) {
        perror("Size Error");
        exit(EXIT_FAILURE);
    }
    unsigned char* t = (unsigned char*)malloc(sizeof(unsigned char) * 33);
    if (t == NULL) {
        perror("Failed to allocate memory for t"); // ���� �޽��� ���
        exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
    }
    for (int i = 0;i < 32;i++) {
        t[i] = s[i];
    }
    t[32] = b;
    shake_256_hash(t, sizeof(unsigned char) * 33, output, 64 * n);
    free(t);
    return;
}

void H(unsigned char* input, unsigned char* output) {
    size_t d = _msize(input);
    sha3_256_hash(input, d, output);
}

void J(unsigned char* input, unsigned char* output) {
    size_t d = _msize(input);
    shake_256_hash(input, d, output, 32);
}

void G(unsigned char* input, unsigned char* output_1, unsigned char* output_2) {
    size_t d = _msize(input);
    unsigned char* output = (unsigned char*)malloc(sizeof(unsigned char) * 64);
    if (output == NULL) {
        perror("Failed to allocate memory for output"); // ���� �޽��� ���
        exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
    }
    sha3_512_hash(input, d, output);
    for (int i = 0;i < 32;i++) {
        output_1[i] = output[i];
        output_2[i] = output[32 + i];
    }
    free(output);
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

    printf("Absorbing data block ...\n");
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

    //printf("Squeezing output (%zu bytes)...\n", length);
    if (!EVP_DigestSqueeze(ctx, output, length)) {
        fprintf(stderr, "Error: EVP_DigestSqueeze failed.\n");
        if (ctx) {
            EVP_MD_CTX_free(ctx);
        }
        EVP_cleanup();
        free(output);
        return NULL;
    }
    /*
    printf("SHAKE-128 Output (first %zu bytes, hex): ", length);
    for (unsigned int i = 0; i < length; i++) {
        printf("%02x ", output[i]);
    }
    printf("\n");
    */
    return output;
}



/*
int main() {
    EVP_MD_CTX* mdctx = NULL;
    const EVP_MD* shake128 = NULL;
    unsigned char output[32]; // ���ϴ� ��� ���� (���� ����)
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

    // 2. shake.absorb (EVP_DigestUpdate - ���� �� ȣ�� ����)
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

    // 3. shake.squeeze (EVP_DigestFinalXOF - ���ϴ� ���̸�ŭ �ݺ� ȣ�� ����)
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

    // �߰����� ¥���� (squeeze) ����
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
/*
int main() {
    const char* message = "This is a test message.";
    unsigned char hash[EVP_MAX_MD_SIZE]; // ����� ũ���� ���� (SHA3-512�� 64����Ʈ)
    size_t message_len = strlen(message);

    sha3_512_hash((const unsigned char*)message, message_len, hash);

    printf("%p\n", message);
    printf("SHA3-512 Hash: ");
    for (int i = 0; i < 64; i++) { // SHA3-512 ����� 64����Ʈ
        printf("%02x ", hash[i]);//16������ ǥ��
    }
    printf("\n");
    for (int i = 0; i < 64; i++) { // SHA3-512 ����� 64����Ʈ
        printf("%u ", hash[i]);//10������ ǥ��
    }
    printf("\n");
    unsigned char* t = (unsigned char*)malloc(sizeof(unsigned char) * 32);
    if (t == NULL) {
        perror("Failed to allocate memory for t"); // ���� �޽��� ���
        exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
    }
    for (int i = 0; i < 32; i++) {
        t[i] = hash[i];
    }
    unsigned char* hash1 = (unsigned char*)malloc(sizeof(unsigned char) * 512);
    if (hash1 == NULL) {
        perror("Failed to allocate memory for t"); // ���� �޽��� ���
        exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
    }
    PRF(3, t, 12, hash1);
    printf("PRF\n");
    for (int i = 0; i < 512; i++) { // SHA3-512 ����� 64����Ʈ
        printf("(%d)%u\n ", i, hash1[i]);
    }
    printf("\n");
    size_t l1 = _msize(hash1);
    size_t l2 = strlen(hash1);
    printf("%zu,%zu\n", l1, l2);
    printf("%s,%u\n", message, message);

    return 0;
}*/