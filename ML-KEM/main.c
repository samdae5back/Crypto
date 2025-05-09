#include <stdio.h>
#include <stdlib.h>
#include <string.h>//strlen ���� �ʿ�
#include <malloc.h>//_msize ���� �ʿ�
#include <time.h>
#include "NTT.h"
#include "hash.h"
#include "auxiliary.h"
#include "K-PKE_KeyGen.h"
#include "K-PKE_Enc.h"
#include "K-PKE_Dec.h"
#include "internal.h"
#include "ML-KEM.h"
#include "parameter.h"

int main() {

	//ek, dk ����
	unsigned char** ek = (unsigned char**)malloc(sizeof(unsigned char*) * (k + 1));
	unsigned char** dk = (unsigned char**)malloc(sizeof(unsigned char*) * (2 * k + 3));
	if (ek == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}
	if (dk == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}
	for (int i = 0;i < k;i++) {
		ek[i] = (unsigned char*)malloc(sizeof(unsigned char) * 32 * 12);
		if (ek[i] == NULL) {
			perror("Failed to allocate memory"); // ���� �޽��� ���
			exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
		}
		dk[i] = (unsigned char*)malloc(sizeof(unsigned char) * 32 * 12);
		if (dk[i] == NULL) {
			perror("Failed to allocate memory"); // ���� �޽��� ���
			exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
		}
		dk[i + k] = (unsigned char*)malloc(sizeof(unsigned char) * 32 * 12);
		if (dk[i + k] == NULL) {
			perror("Failed to allocate memory"); // ���� �޽��� ���
			exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
		}
	}
	ek[k] = (unsigned char*)malloc(sizeof(unsigned char) * 32);
	if (ek[k] == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}
	for (int i = 2 * k;i < 2 * k + 3;i++) {
		dk[i] = (unsigned char*)malloc(sizeof(unsigned char) * 32);
		if (dk[i] == NULL) {
			perror("Failed to allocate memory"); // ���� �޽��� ���
			exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
		}
	}

	ML_KEM_KeyGen(ek, dk);

	//SharedSecretKey ����
	unsigned char* SharedSecretKey = (unsigned char*)malloc(sizeof(unsigned char) * 32);
	if (SharedSecretKey == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}
	//ciphertext ����
	unsigned char** ciphertext = (unsigned char**)malloc(sizeof(unsigned char*) * (k + 1));
	if (ciphertext == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}
	for (int i = 0;i < k;i++) {
		ciphertext[i] = (unsigned char*)malloc(sizeof(unsigned char) * 32 * d_u);
		if (ciphertext[i] == NULL) {
			perror("Failed to allocate memory"); // ���� �޽��� ���
			exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
		}
	}
	ciphertext[k] = (char*)malloc(sizeof(char) * 32 * d_v);
	if (ciphertext[k] == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}


	ML_KEM_Encaps(ek, SharedSecretKey, ciphertext);

	//SharedSecretKey_ ����
	unsigned char* SharedSecretKey_ = (unsigned char*)malloc(sizeof(unsigned char) * 32);
	if (SharedSecretKey_ == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}

	ML_KEM_Decaps(dk, ciphertext, SharedSecretKey_);

	for (int i = 0;i < 32;i++) {
		if (SharedSecretKey[i] != SharedSecretKey_[i]) {
			printf("ML-KEM Fail\n");
			return 0;
		}
	}
	printf("\nML-KEM Succeed\n");
	return 0;

}