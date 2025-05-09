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
#include "parameter.h"

/*



int main() {

	//Internal KeyGen

	//d ����
	unsigned char* d = (unsigned char*)malloc(sizeof(unsigned char) * 32);
	if (d == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}
	unsigned char* text_d = "message  test test";
	size_t text_length_d = strlen(text_d);
	sha3_256_hash(text_d, text_length_d, d);

	//z ����
	unsigned char* z = (unsigned char*)malloc(sizeof(unsigned char) * 32);
	if (z == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}
	unsigned char* text_z = "message   test test test";
	size_t text_length_z = strlen(text_z);
	sha3_256_hash(text_z, text_length_z, z);

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

	ML_KEM_KeyGen_internal(d, z, ek, dk);

	//Internal Encaps

	//m ����
	unsigned char* m = (unsigned char*)malloc(sizeof(unsigned char) * 32);
	if (m == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}
	unsigned char* text_m = "message  test dd test";
	size_t text_length_m = strlen(text_m);
	sha3_256_hash(text_m, text_length_m, m);
	
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

	ML_KEM_Encaps_internal(ek, m, SharedSecretKey, ciphertext);

	//Internal Decaps
	
	//SharedSecretKey_ ����
	unsigned char* SharedSecretKey_ = (unsigned char*)malloc(sizeof(unsigned char) * 32);
	if (SharedSecretKey_ == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}
	
	ML_KEM_Decaps_internal(dk, ciphertext, SharedSecretKey_);

	
	unsigned char* seed;
	seed = (unsigned char*)malloc(sizeof(unsigned char) * 25);
	if (seed == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}

	srand(time(NULL));
	for (int i = 0;i < 24;i++) {
		seed[i] = 'a' + (rand() % 26);
	}
	seed[24] = 0;
	printf("%s\n",seed);
	for (int i = 0;i < 24;i++) {
		seed[i] = 'a' + (rand() % 26);
	}
	seed[24] = 0;
	printf("%s\n", seed);
	

	return 0;
}

*/