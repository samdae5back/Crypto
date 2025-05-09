#include <stdio.h>
#include <string.h>
#include "hash.h"
#include "NTT.h"
#include "auxiliary.h"
#include "parameter.h"

void K_PKE_Dec(unsigned char** dk_pke, unsigned char** ciphertext, unsigned char* message_) {

	//c_1, c_2 ����
	unsigned char** c_1 = (unsigned char**)malloc(sizeof(unsigned char*) * (k + 1));
	if (c_1 == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}
	for (unsigned char i = 0;i < k;i++) {
		c_1[i] = (unsigned char*)malloc(sizeof(unsigned char) * 32 * d_u);
		if (c_1[i] == NULL) {
			perror("Failed to allocate memory"); // ���� �޽��� ���
			exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
		}
	}
	unsigned char* c_2 = (unsigned char*)malloc(sizeof(unsigned char) * 32 * d_v);
	if (c_2 == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}

	//c_1, c_2�� ciphertext����
	for (int i = 0;i < k;i++) {
		for (int j = 0;j < 32 * d_u;j++) {
			c_1[i][j] = ciphertext[i][j];
		}
	}
	for (int i = 0;i < 32 * d_v;i++) {
		c_2[i] = ciphertext[k][i];
	}

	//u ����
	int** u = (int**)malloc(sizeof(int*) * k);
	if (u == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}
	for (int i = 0;i < k;i++) {
		u[i] = (int*)malloc(sizeof(int) * 256);
		if (u[i] == NULL) {
			perror("Failed to allocate memory"); // ���� �޽��� ���
			exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
		}
	}


	//u �� c_1 ��ȯ
	unsigned int* buffer_int;

	for (int i = 0;i < k;i++) {
		buffer_int = (int*)malloc(sizeof(int) * 256);
		if (buffer_int == NULL) {
			perror("Failed to allocate memory"); // ���� �޽��� ���
			exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
		}
		ByteDecode(c_1[i], d_u, buffer_int);
		Decomp(buffer_int, d_u, u[i], 256);
		free(buffer_int);
	}

	//v ����
	int* v = (int*)malloc(sizeof(int) * 256);
	if (v == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}

	//v �� c_2 ��ȯ
	buffer_int = (int*)malloc(sizeof(int) * 256);
	if (buffer_int == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}
	ByteDecode(c_2, d_v, buffer_int);
	Decomp(buffer_int, d_v, v, 256);
	free(buffer_int);
	
	//s_hat ����
	int** s_hat = (int**)malloc(sizeof(int*) * k);
	if (s_hat == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}
	for (int i = 0;i < k;i++) {
		s_hat[i] = (int*)malloc(sizeof(int) * 256);
		if (s_hat[i] == NULL) {
			perror("Failed to allocate memory"); // ���� �޽��� ���
			exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
		}
	}

	//s_hat �� dk_pke ��ȯ
	for (int i = 0;i < k;i++) {
		ByteDecode(dk_pke[i], 12, s_hat[i]);
	}

	//w ����, 0���� �ʱ�ȭ
	int* w = (int*)malloc(sizeof(int) * 256);
	if (w == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}
	for (int i = 0;i < 256;i++) {
		w[i] = 0;
	}

	//NTT�������ؼ� zeta�ҷ�����
	int* zeta = GenZeta();

	//NTT ���� ���� u_hat=NTT(u) ����
	int** u_hat = (int**)malloc(sizeof(int*) * k);
	if (u_hat == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}
	for (int i = 0;i < k;i++) {
		u_hat[i] = (int*)malloc(sizeof(int) * 256);
		if (u_hat[i] == NULL) {
			perror("Failed to allocate memory"); // ���� �޽��� ���
			exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
		}
		NTT(u[i], u_hat[i], zeta);
	}

	

	int* buffer_int_hat;

	

	for (int i = 0;i < k;i++) {
		buffer_int = (int*)malloc(sizeof(int) * 256);
		if (buffer_int == NULL) {
			perror("Failed to allocate memory"); // ���� �޽��� ���
			exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
		}
		buffer_int_hat = (int*)malloc(sizeof(int) * 256);
		if (buffer_int_hat == NULL) {
			perror("Failed to allocate memory"); // ���� �޽��� ���
			exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
		}
		Multiply_NTT(s_hat[i], u_hat[i], buffer_int_hat, zeta);
		NTT_inv(buffer_int_hat, buffer_int, zeta);
		for (int j = 0;j < 256;j++) {
			w[j] = (w[j] + buffer_int[j]) % q;
		}
		free(buffer_int);
		free(buffer_int_hat);
	}

	for (int i = 0;i < 256;i++) {
		w[i] = (v[i] - w[i] + q) % q;
	}



	buffer_int = (int*)malloc(sizeof(int) * 256);
	if (buffer_int == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}

	Comp(w, 1, buffer_int, 256);

	ByteEncode(buffer_int, 1, message_);

	free(buffer_int);


	for (int i = 0;i < k;i++) {
		free(c_1[i]);
		free(u[i]);
		free(s_hat[i]);
		free(u_hat[i]);
	}
	free(c_1);
	free(c_2);
	free(u);
	free(v);
	free(s_hat);
	free(u_hat);
	free(zeta);

	printf("\nK-PKE Decryption Succeed\n");
	return;



}