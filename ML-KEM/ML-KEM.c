#include <stdio.h>
#include <string.h>//strlen ���� �ʿ�
#include <time.h>
#include "NTT.h"
#include "hash.h"
#include "auxiliary.h"
#include "K-PKE_KeyGen.h"
#include "K-PKE_Enc.h"
#include "K-PKE_Dec.h"
#include "internal.h"
#include "parameter.h"


void ML_KEM_KeyGen(unsigned char** ek, unsigned char** dk) {

	unsigned char* seed;
	seed = (unsigned char*)malloc(sizeof(unsigned char) * 128);
	if (seed == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}

	srand(time(NULL));
	

	//d ����
	for (int i = 0;i < 127;i++) {
		seed[i] = 'a' + (rand() % 26);
	}
	seed[127] = 0;

	unsigned char* d = (unsigned char*)malloc(sizeof(unsigned char) * 32);
	if (d == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}
	unsigned char* text_d = seed;
	size_t text_length_d = strlen(text_d);
	sha3_256_hash(text_d, text_length_d, d);

	//z ����
	for (int i = 0;i < 127;i++) {
		seed[i] = 'a' + (rand() % 26);
	}
	seed[127] = 0;
	
	unsigned char* z = (unsigned char*)malloc(sizeof(unsigned char) * 32);
	if (z == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}
	unsigned char* text_z = seed;
	size_t text_length_z = strlen(text_z);
	sha3_256_hash(text_z, text_length_z, z);

	//ek, dk ����

	ML_KEM_KeyGen_internal(d, z, ek, dk);

	printf("\nML-KEM Internal Key Generatinon Succeed\n");
	return;
}

void ML_KEM_Encaps(unsigned char** ek, unsigned char* SharedSecretKey, unsigned char** c) {

	unsigned char* seed;
	seed = (unsigned char*)malloc(sizeof(unsigned char) * 128);
	if (seed == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}

	srand(time(NULL));

	//m ����
	for (int i = 0;i < 127;i++) {
		seed[i] = 'a' + (rand() % 26);
	}
	seed[127] = 0;

	unsigned char* m = (unsigned char*)malloc(sizeof(unsigned char) * 32);
	if (m == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}
	unsigned char* text_m = seed;
	size_t text_length_m = strlen(text_m);
	sha3_256_hash(text_m, text_length_m, m);

	ML_KEM_Encaps_internal(ek, m, SharedSecretKey, c);

	printf("\nML-KEM Internal Encapsulation Succeed\n");
} 

void ML_KEM_Decaps(unsigned char** dk, unsigned char** c, unsigned char* SharedSecretKey_) {
	ML_KEM_Decaps_internal(dk, c, SharedSecretKey_);
	printf("\nML-KEM Decapsulation Succeed\n");
}
