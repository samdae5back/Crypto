#include <stdio.h>
#include <string.h>
#include "hash.h"
#include "NTT.h"
#include "auxiliary.h"
#include "parameter.h"

void K_PKE_Enc(unsigned char** ek_pke, unsigned char* message, unsigned char* randomness, unsigned char** ciphertext) {

	int N = 0;
	int* buffer_int;


	//����Ű���� ���� ����
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
		ByteDecode(ek_pke[i], 12, t[i]);
	}
	unsigned char* rho = (unsigned char*)malloc(sizeof(unsigned char) * 32);
	if (rho == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}
	for (int i = 0;i < 32;i++) {
		rho[i] = ek_pke[k][i];
	}

	//Ȯ���� ���
	/*
	printf("\nt :\n");
	for (int i = 0;i < k;i++) {
		printf("i = %d \n", i);
		for (int j = 0;j < 256;j++) {
			printf("%d ", t[i][j]);
		}
		printf("\n");
	}
	printf("rho = \n");
	for (int i = 0;i < 32;i++) {
		printf("%d ",rho[i]);
	}
	printf("\n");
	*/

	//re-generate A
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



	//generate y
	int** y = (int**)malloc(sizeof(int*) * k);
	if (y == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}
	for (int i = 0;i < k;i++) {
		y[i] = (int*)malloc(sizeof(int) * 256);
		if (y[i] == NULL) {
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
		PRF(n_1, randomness, N, output);

		SamplePolyCBD(output, y[i], 64 * n_1);
		free(output);
		N++;
	}

	//generate e_1
	int** e_1 = (int**)malloc(sizeof(int*) * k);
	if (e_1 == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}
	for (int i = 0;i < k;i++) {
		e_1[i] = (int*)malloc(sizeof(int) * 256);
		if (e_1[i] == NULL) {
			perror("Failed to allocate memory"); // ���� �޽��� ���
			exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
		}
	}
	for (int i = 0;i < k;i++) {
		unsigned char* output = (unsigned char*)malloc(sizeof(unsigned char) * 64 * n_2);
		if (output == NULL) {
			perror("Failed to allocate memory"); // ���� �޽��� ���
			exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
		}
		PRF(n_2, randomness, N, output);
		SamplePolyCBD(output, e_1[i], 64 * n_2);
		free(output);
		N++;
	}

	//generate e_2
	int* e_2 = (int*)malloc(sizeof(int) * 256);
	if (e_2 == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}
	unsigned char* output = (unsigned char*)malloc(sizeof(unsigned char) * 64 * n_2);
	if (output == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}
	PRF(n_2, randomness, N, output);
	SamplePolyCBD(output, e_2, 64 * n_2);
	free(output);

	//NTT ���� ���� zeta��������
	int* zeta = GenZeta();

	//y_hat ���
	int** y_hat = (int**)malloc(sizeof(int*) * k);
	if (y_hat == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}
	for (int i = 0;i < k;i++) {
		y_hat[i] = (int*)malloc(sizeof(int) * 256);
		if (y_hat[i] == NULL) {
			perror("Failed to allocate memory"); // ���� �޽��� ���
			exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
		}
		NTT(y[i], y_hat[i], zeta);
	}



	//u ���, ���߿� NTT ��ȯ �� �� �ޱ� ���� u_hat ����
	int** u = (int**)malloc(sizeof(int*) * k);
	if (u == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}
	int** u_hat = (int**)malloc(sizeof(int*) * k);
	if (u_hat == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}
	for (int i = 0;i < k;i++) {
		u[i] = (int*)malloc(sizeof(int) * 256);
		if (u[i] == NULL) {
			perror("Failed to allocate memory"); // ���� �޽��� ���
			exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
		}
		u_hat[i] = (int*)malloc(sizeof(int) * 256);
		if (u_hat[i] == NULL) {
			perror("Failed to allocate memory"); // ���� �޽��� ���
			exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
		}
		//u_hat 0���� �ʱ�ȭ
		for (int j = 0;j < 256;j++) {
			u_hat[i][j] = 0;
		}
		for (int j = 0;j < k;j++) {
			//buffer_int�� ���۷� Ȱ���Ͽ� A^t_hat*y_hat ���
			buffer_int = (int*)malloc(sizeof(int) * 256);
			if (buffer_int == NULL) {
				perror("Failed to allocate memory"); // ���� �޽��� ���
				exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
			}
			Multiply_NTT(A[j][i], y_hat[j], buffer_int, zeta);
			//u_hat���� �� ���׽� �������� ����
			for (int l = 0;l < 256;l++) {
				u_hat[i][l] = (u_hat[i][l] + buffer_int[l]) % q;
			}
			free(buffer_int);
			
		}
		//u_hat���� u�� NTT_inverse ����
		NTT_inv(u_hat[i], u[i], zeta);
		//e_1 ���ϱ�
		for (int j = 0;j< 256;j++) {
			u[i][j] = (u[i][j] + e_1[i][j]) % q;
		}
	}



	//buffer_int ���۷� Ȱ���ؼ� mu ���
	buffer_int = (int*)malloc(sizeof(int) * 256);
	if (buffer_int == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}

	ByteDecode(message, 1, buffer_int);


	int* mu = (int*)malloc(sizeof(int) * 256);
	if (mu == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}

	Decomp(buffer_int, 1, mu, 256);
	free(buffer_int);
	

	//v ���, ���߿� NTT ��ȯ �� �� �ޱ� ���� v_hat ����
	int* v = (int*)malloc(sizeof(int) * 256);
	if (v == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}
	int* v_hat = (int*)malloc(sizeof(int) * 256);
	if (v_hat == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}

	//v_hat0���� �ʱ�ȭ
	for (int j = 0;j < 256;j++) {
		v_hat[j] =0;
	}

	//buffer_int�� ���۷� Ȱ���Ͽ� t_hat*y_hat ���
	for (int i = 0;i < k;i++) {
		buffer_int = (int*)malloc(sizeof(int) * 256);
		if (buffer_int == NULL) {
			perror("Failed to allocate memory"); // ���� �޽��� ���
			exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
		}
		Multiply_NTT(t[i], y_hat[i], buffer_int, zeta);
		for (int j = 0;j < 256;j++) {
			v_hat[j] = (v_hat[j] + buffer_int[j]) % q;
		}
		free(buffer_int);
	}
	//v_hat���� v�� NTT_inverse ����
	NTT_inv(v_hat, v, zeta);
	//e_2, mu ���ϱ�
	for (int i = 0;i < 256;i++) {
		v[i] = (v[i] + e_2[i] + mu[i]) % q;
	}

	//Ű�� �� ����
	for (int i = 0;i < k;i++) {
		buffer_int = (int*)malloc(sizeof(int) * 256);
		if (buffer_int == NULL) {
			perror("Failed to allocate memory"); // ���� �޽��� ���
			exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
		}
		Comp(u[i], d_u, buffer_int, 256);
		ByteEncode(buffer_int, d_u, ciphertext[i]);
		free(buffer_int);
	}
	buffer_int = (int*)malloc(sizeof(int) * 256);
	if (buffer_int == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}
	Comp(v, d_v, buffer_int, 256);
	ByteEncode(buffer_int, d_v, ciphertext[k]);
	free(buffer_int);

	for (int i = 0;i < k;i++) {
		for (int j = 0;j < k;j++) {
			free(A[i][j]);
		}
		free(y[i]);
		free(y_hat[i]);
		free(e_1[i]);
		free(A[i]);
		free(t[i]);
		free(u[i]);
	}
	free(y);
	free(y_hat);
	free(e_1);
	free(e_2);
	free(A);
	free(t);
	free(rho);
	free(u);
	free(v);
	free(zeta);

	printf("\nK-PKE Encryption Succeed\n");
	return;
}