#include <openssl/evp.h> // �Ǵ� <openssl/sha.h> ������ ���
#include <stdio.h>
#include <string.h>
#include "SHA3_512.h"

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

/*
int main() {
    const char* message = "This is a test message.";
    unsigned char hash[EVP_MAX_MD_SIZE]; // ����� ũ���� ���� (SHA3-512�� 64����Ʈ)
    size_t message_len = strlen(message);

    sha3_512_hash((const unsigned char*)message, message_len, hash);

    printf("%p\n",message);
    printf("SHA3-512 Hash: ");
    for (int i = 0; i < SHA3_512_DIGEST_LENGTH; i++) { // SHA3-512 ����� 64����Ʈ
        printf("%02x", hash[i]);
    }
    
    return 0;
}
*/