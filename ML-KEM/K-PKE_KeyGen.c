#include <stdio.h>
//#include <string.h>//strlen ���� �ʿ�
//#include <malloc.h>//_msize ���� �ʿ�
#include "hash.h"
#include "NTT.h"
#include "auxiliary.h"
#include "parameter.h"

void K_PKE_KeyGen(unsigned char* d, unsigned char** ek_pke, unsigned char** dk_pke) {
	/*
	if (_msize(d) != 32) {
		perror("Input length Error");
		exit(EXIT_FAILURE);
	}//input ���� üũ(malloc.h ����ʿ��ؼ� ����)
	*/
	//G �Լ� ����ؼ� �ؽð� ����
	unsigned char* input = (unsigned char*)malloc(sizeof(unsigned char) * 33);
	if (input == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}
	for (int i = 0;i < 32;i++) {
		input[i] = d[i];
	}
	input[32] = k;
	unsigned char* rho = (unsigned char*)malloc(sizeof(unsigned char) * 32);
	if (rho == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}
	unsigned char* sigma = (unsigned char*)malloc(sizeof(unsigned char) * 32);
	if (sigma == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}
	G(input, rho, sigma);
	free(input);


	int N = 0;

	//generate A
	int*** A = (int***)malloc(sizeof(int**) * k);
	if (A == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}
	for (int i = 0;i < k;i++) {
		A[i] = (int**)malloc(sizeof(int*) * k);
		if (A[i] == NULL) {
			perror("Failed to allocate memory"); // ���� �޽��� ���
			exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
		}
	}
	for (int i = 0;i < k;i++) {
		for (int j = 0;j < k;j++) {
			unsigned char* input = (unsigned char*)malloc(sizeof(unsigned char) * 34);
			if (input == NULL) {
				perror("Failed to allocate memory"); // ���� �޽��� ���
				exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
			}
			for (int i = 0;i < 32;i++) {
				input[i] = rho[i];
			}
			input[32] = j;
			input[33] = i;
			A[i][j] = (int*)malloc(sizeof(int) * 256);
			if (A[i][j] == NULL) {
				perror("Failed to allocate memory"); // ���� �޽��� ���
				exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
			}
			SampleNTT(input, A[i][j], 34);
			free(input);
		}
	}


	//generate s
	int** s = (int**)malloc(sizeof(int*) * k);
	if (s == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}
	for (int i = 0;i < k;i++) {
		s[i] = (int*)malloc(sizeof(int) * 256);
		if (s[i] == NULL) {
			perror("Failed to allocate memory"); // ���� �޽��� ���
			exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
		}
	}
	for (int i = 0;i < k;i++) {
		unsigned char* output = (unsigned char*)malloc(sizeof(unsigned char) * 64 * n_1);
		if (output == NULL) {
			perror("Failed to allocate memory"); // ���� �޽��� ���
			exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
		}
		PRF(n_1, sigma, N, output);
		SamplePolyCBD(output, s[i], 64 * n_1);
		free(output);
		N++;
	}

	//generate e
	int** e = (int**)malloc(sizeof(int*) * k);
	if (e == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}
	for (int i = 0;i < k;i++) {
		e[i] = (int*)malloc(sizeof(int) * 256);
		if (e[i] == NULL) {
			perror("Failed to allocate memory"); // ���� �޽��� ���
			exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
		}
	}
	for (int i = 0;i < k;i++) {
		unsigned char* output = (unsigned char*)malloc(sizeof(unsigned char) * 64 * n_1);
		if (output == NULL) {
			perror("Failed to allocate memory"); // ���� �޽��� ���
			exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
		}
		PRF(n_1, sigma, N, output);
		SamplePolyCBD(output, e[i], 64 * n_1);
		free(output);
		N++;
	}


	//NTT���� ���� zeta�ҷ�����
	int* zeta = GenZeta();

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
		NTT(s[i], s_hat[i], zeta);
	}

	//e_hat ����
	int** e_hat = (int**)malloc(sizeof(int*) * k);
	if (e_hat == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}
	for (int i = 0;i < k;i++) {
		e_hat[i] = (int*)malloc(sizeof(int*) * 256);
		if (e_hat[i] == NULL) {
			perror("Failed to allocate memory"); // ���� �޽��� ���
			exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
		}
		NTT(e[i], e_hat[i], zeta);
	}

	//t_hat ����
	int** t = (int**)malloc(sizeof(int*) * k);
	if (t == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}
	for (int i = 0;i < k;i++) {
		t[i] = (int*)malloc(sizeof(int) * 256);
		if (t[i] == NULL) {
			perror("Failed to allocate memory"); // ���� �޽��� ���
			exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
		}
		for (int l = 0;l < 256;l++) {
			t[i][l] = e_hat[i][l];
		}
		for (int j = 0;j < k;j++) {
			//output�� ���۷� Ȱ���Ͽ� A_hat*s_hat ���
			int* output = (int*)malloc(sizeof(int) * 256);
			if (output == NULL) {
				perror("Failed to allocate memory"); // ���� �޽��� ���
				exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
			}
			Multiply_NTT(A[i][j], s_hat[j], output, zeta);
			//t���� �� ���׽� �������� ����
			for (int l = 0;l < 256;l++) {
				t[i][l] = (t[i][l] + output[l]) % q;
			}
			free(output);
		}
	}

	//�� Ű�� ���� �Է�
	for (int i = 0;i < k;i++) {
		ByteEncode(t[i], 12, ek_pke[i]);
		ByteEncode(s_hat[i], 12, dk_pke[i]);
	}
	for (int i = 0;i < 32;i++) {
		ek_pke[k][i] = rho[i];
	}

	for (int i = 0;i < k;i++) {
		for (int j = 0;j < k;j++) {
			free(A[i][j]);
		}
		free(s[i]);
		free(s_hat[i]);
		free(e[i]);
		free(e_hat[i]);
		free(A[i]);
		free(t[i]);
	}
	free(s);
	free(s_hat);
	free(e);
	free(e_hat);
	free(A);
	free(t);
	free(rho);
	free(sigma);
	free(zeta);

	printf("\nK-PKE Key Generatinon Succeed\n");
	return;
}

/*
int main() {
	unsigned char* d = (unsigned char*)malloc(sizeof(unsigned char) * 32);
	if (d == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}

	//KeyGen�� input ����
	unsigned char* text = "message  test test";
	size_t text_length = strlen(text);
	sha3_256_hash(text, text_length, d);

	unsigned char** ek_pke = (unsigned char**)malloc(sizeof(unsigned char*) * (k + 1));
	unsigned char** dk_pke = (unsigned char**)malloc(sizeof(unsigned char*) * k);
	if (ek_pke == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}
	if (dk_pke == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}
	for (int i = 0;i < k;i++) {
		ek_pke[i]= (int*)malloc(sizeof(int) * 32 * 12);
		if (ek_pke[i] == NULL) {
			perror("Failed to allocate memory"); // ���� �޽��� ���
			exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
		}
		dk_pke[i] = (int*)malloc(sizeof(int) * 32 * 12);
		if (dk_pke[i] == NULL) {
			perror("Failed to allocate memory"); // ���� �޽��� ���
			exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
		}
	}
	ek_pke[k] = (int*)malloc(sizeof(int) * 32);
	if (ek_pke[k] == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}
	

	K_PKE_KeyGen(d, ek_pke, dk_pke);

	printf("ek_pke :\n");
	for (int i = 0;i < k;i++) {
		printf("i = %d \n",i);
		for (int j = 0;j < 384;j++) {
			printf("%u ", ek_pke[i][j]);
		}
		printf("\n");

	}
	printf("rho = \n");
	for (int i = 0;i < 32;i++) {
		printf("%u ", ek_pke[k][i]);
	}
	printf("\n");

	printf("dk_pke :\n");
	for (int i = 0;i < k;i++) {
		printf("i = %d \n", i);
		for (int j = 0;j < 384;j++) {
			printf("%u ", dk_pke[i][j]);
		}
		printf("\n");

	}
	for (int i = 0;i < k;i++) {
		free(ek_pke[i]);
		free(dk_pke[i]);
	}
	free(ek_pke);
	free(dk_pke);

	return 0;
}
*/