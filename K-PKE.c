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
        perror("Failed to allocate memory for m"); // ���� �޽��� ���
        exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
    }
    XOF_init(&ctx);
    if (ctx != NULL) { // �ʱ�ȭ ���� ���� Ȯ��
        XOF_absorb(ctx, B);//�޼��� ���
    }
    else {
        fprintf(stderr, "Error initializing SHAKE-128 context in SampleNTT.\n");
        EVP_cleanup();
        return ; // ���� �߻� �� 0�� �ƴ� �� ��ȯ
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

    free(m); // ������ ��� �޸� ����
    EVP_MD_CTX_free(ctx); // ���ؽ�Ʈ ����
    EVP_cleanup();
}

int main() {
    unsigned char* a = (char*)malloc(sizeof(unsigned char) * 256);
    if (a == NULL) {
        perror("Failed to allocate memory for a"); // ���� �޽��� ���
        exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
    }
    SampleNTT("test message", a);
    for (int i = 0;i < 256;i++) {
        printf("%u", a[i]);
    }
}
