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
    if (ctx != NULL) { // �ʱ�ȭ ���� ���� Ȯ��
        XOF_absorb(ctx, "message");
        m = XOF_squeeze(ctx, l);
        for (unsigned int i = 0; i < l; i++) {
            // printf("%u  ", m[i]);
        }
        free(m); // ������ ��� �޸� ����
        EVP_MD_CTX_free(ctx); // ���ؽ�Ʈ ����
        EVP_cleanup();
    }
    else {
        fprintf(stderr, "Error initializing SHAKE-128 context.\n");
        EVP_cleanup();
        return 1; // ���� �߻� �� 0�� �ƴ� �� ��ȯ
    }
}
