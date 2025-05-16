#include <stdio.h>
#include <string.h> //memcpy �Լ�
#include "hash.h"
#include "NTT_.h"
#include "auxiliary.h"
#include "K-PKE.h"
#include "KAT.h"
#include "parameter.h"

void K_PKE_KeyGen(unsigned char* d, unsigned char* ek_pke, unsigned char* dk_pke) {

	int N = 0;
	unsigned char* buffer_char = NULL;
	int* buffer_int = NULL;

	//G ��� ���� ���ۿ� �޸� �Ҵ�
	buffer_char = (unsigned char*)malloc(sizeof(unsigned char) * 33);
	if (buffer_char == NULL) {
		perror("Failed to allocate memory");
		exit(EXIT_FAILURE);
	}

	//G �Լ� ����ؼ� �ؽð� ����
	memcpy(buffer_char, d, 32);
	buffer_char[32] = k;
	unsigned char rho[32] = { 0 };
	unsigned char sigma[32] = { 0 };
	G(buffer_char, 33, rho, sigma);

	free(buffer_char);

	//A ��� ���� ���ۿ� �޸� �Ҵ�
	buffer_char = (unsigned char*)malloc(sizeof(unsigned char) * 34);
	if (buffer_char == NULL) {
		perror("Failed to allocate memory");
		exit(EXIT_FAILURE);
	}

	//generate A
	int*** A = (int***)malloc(sizeof(int**) * k);
	if (A == NULL) {
		perror("Failed to allocate memory");
		exit(EXIT_FAILURE);
	}
	for (int i = 0;i < k;i++) {
		A[i] = (int**)malloc(sizeof(int*) * k);
		if (A[i] == NULL) {
			perror("Failed to allocate memory");
			exit(EXIT_FAILURE);
		}
		for (int j = 0;j < k;j++) {
			A[i][j] = (int*)malloc(sizeof(int) * n);
			if (A[i][j] == NULL) {
				perror("Failed to allocate memory");
				exit(EXIT_FAILURE);
			}
			memcpy(buffer_char, rho, 32);
			buffer_char[32] = j;
			buffer_char[33] = i;
			SampleNTT(buffer_char, A[i][j], 34);
		}
	}

	free(buffer_char);

	//s, e ��� ���� ���ۿ� �޸� �Ҵ�
	buffer_char = (unsigned char*)malloc(sizeof(unsigned char) * 64 * n_1);
	if (buffer_char == NULL) {
		perror("Failed to allocate memory");
		exit(EXIT_FAILURE);
	}

	//generate s
	int s[k][n] = { 0 };
	for (int i = 0;i < k;i++) {
		PRF(n_1, sigma, N, buffer_char);
		SamplePolyCBD(buffer_char, s[i], 64 * n_1);
		N++;
	}

	//generate e
	int e[k][n] = { 0 };
	for (int i = 0;i < k;i++) {
		PRF(n_1, sigma, N, buffer_char);
		SamplePolyCBD(buffer_char, e[i], 64 * n_1);
		N++;
	}

	free(buffer_char);

	//NTT���� ���� zeta�ҷ�����
	int* zeta = GenZeta();

	//s_hat, e_hat ���� �� ���
	int s_hat[k][n] = { 0 };
	int e_hat[k][n] = { 0 };
	for (int i = 0;i < k;i++) {
		NTT(s[i], s_hat[i], zeta);
		NTT(e[i], e_hat[i], zeta);
	}

	//t_hat ��� ���� ���ۿ� �޸� �Ҵ�
	buffer_int = (int*)malloc(sizeof(int) * n);
	if (buffer_int == NULL) {
		perror("Failed to allocate memory");
		exit(EXIT_FAILURE);
	}

	//t_hat ���� �� ���
	int t_hat[k][n] = { 0 };
	for (int i = 0;i < k;i++) {
		for (int l = 0;l < n;l++) {
			t_hat[i][l] = e_hat[i][l];
		}
		for (int j = 0;j < k;j++) {
			//�� ��, �� ���� A_hat*s_hat ���
			Multiply_NTT(A[i][j], s_hat[j], buffer_int, zeta);
			//t_hat�� �� ���׽� �������� ����
			for (int l = 0;l < n;l++) {
				t_hat[i][l] = (t_hat[i][l] + buffer_int[l]) % q;
			}
		}
	}

	//�޸� �Ҵ� ����
	for (int i = 0;i < k;i++) {
		for (int j = 0;j < k;j++) {
			free(A[i][j]);
		}
		free(A[i]);
	}
	free(A);
	free(buffer_int);

	//�� Ű�� ���� �Է�
	for (int i = 0;i < k;i++) {
		ByteEncode(t_hat[i], 12, ek_pke + (i * 384));
		ByteEncode(s_hat[i], 12, dk_pke + (i * 384));
	}
	memcpy(ek_pke + (k * 384), rho, 32);

	//��� ���
	//printf("\nK-PKE KeyGen Succeed\n");

	return;
}

void K_PKE_Enc(unsigned char* ek_pke, unsigned char* message, unsigned char* randomness, unsigned char* ciphertext) {

	int N = 0;
	unsigned char* buffer_char = NULL;
	int* buffer_int = NULL;

	//����Ű���� ���� ����
	int** t_hat = (int**)malloc(sizeof(int*) * k);
	if (t_hat == NULL) {
		perror("Failed to allocate memory");
		exit(EXIT_FAILURE);
	}
	for (int i = 0;i < k;i++) {
		t_hat[i] = (int*)malloc(sizeof(int) * n);
		if (t_hat[i] == NULL) {
			perror("Failed to allocate memory");
			exit(EXIT_FAILURE);
		}
		ByteDecode(ek_pke + i * 384, 12, t_hat[i]);
	}

	unsigned char rho[32] = { 0 };
	memcpy(rho, ek_pke + 384 * k, 32);

	//A ��� ���� ���ۿ� �޸� �Ҵ�
	buffer_char = (unsigned char*)malloc(sizeof(unsigned char) * 34);
	if (buffer_char == NULL) {
		perror("Failed to allocate memory");
		exit(EXIT_FAILURE);
	}

	//re-generate A
	int*** A = (int***)malloc(sizeof(int**) * k);
	if (A == NULL) {
		perror("Failed to allocate memory");
		exit(EXIT_FAILURE);
	}
	for (int i = 0;i < k;i++) {
		A[i] = (int**)malloc(sizeof(int*) * k);
		if (A[i] == NULL) {
			perror("Failed to allocate memory");
			exit(EXIT_FAILURE);
		}
		for (int j = 0;j < k;j++) {
			A[i][j] = (int*)malloc(sizeof(int) * n);
			if (A[i][j] == NULL) {
				perror("Failed to allocate memory");
				exit(EXIT_FAILURE);
			}
			memcpy(buffer_char, rho, 32);
			buffer_char[32] = j;
			buffer_char[33] = i;
			SampleNTT(buffer_char, A[i][j], 34);
		}
	}

	free(buffer_char);

	//y ��� ���� ���ۿ� �޸� �Ҵ�
	buffer_char = (unsigned char*)malloc(sizeof(unsigned char) * 64 * n_1);
	if (buffer_char == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}

	//generate y
	int y[k][n] = { 0 };
	for (int i = 0;i < k;i++) {
		PRF(n_1, randomness, N, buffer_char);
		SamplePolyCBD(buffer_char, y[i], 64 * n_1);
		N++;
	}

	free(buffer_char);

	//e_1, e_2 ��� ���� ���ۿ� �޸� �Ҵ�
	buffer_char = (unsigned char*)malloc(sizeof(unsigned char) * 64 * n_2);
	if (buffer_char == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}

	//generate e_1
	int e_1[k][n] = { 0 };
	for (int i = 0;i < k;i++) {
		PRF(n_2, randomness, N, buffer_char);
		SamplePolyCBD(buffer_char, e_1[i], 64 * n_2);
		N++;
	}

	//generate e_2
	int e_2[n] = { 0 };
	PRF(n_2, randomness, N, buffer_char);
	SamplePolyCBD(buffer_char, e_2, 64 * n_2);

	free(buffer_char);

	//NTT ���� ���� zeta��������
	int* zeta = GenZeta();

	//y_hat ���
	int y_hat[k][n] = { 0 };
	for (int i = 0;i < k;i++) {
		NTT(y[i], y_hat[i], zeta);
	}

	//A^t_hat*y_hat ��� ���� ���ۿ� �޸� �Ҵ�
	buffer_int = (int*)malloc(sizeof(int) * n);
	if (buffer_int == NULL) {
		perror("Failed to allocate memory");
		exit(EXIT_FAILURE);
	}


	//u ���, ���߿� NTT ��ȯ �� �� �ޱ� ���� u_hat ����
	int u[k][n] = { 0 };
	int u_hat[k][n] = { 0 };
	for (int i = 0;i < k;i++) {
		for (int j = 0;j < k;j++) {
			//�� ��, �� ���� A^t_hat*y_hat ���
			Multiply_NTT(A[j][i], y_hat[j], buffer_int, zeta);
			//u_hat���� �� ���׽� �������� ����
			for (int l = 0;l < n;l++) {
				u_hat[i][l] = (u_hat[i][l] + buffer_int[l]) % q;
			}
		}
		//u_hat���� u�� NTT_inverse ����
		NTT_inv(u_hat[i], u[i], zeta);
		//e_1 ���ϱ�
		for (int j = 0;j < n;j++) {
			u[i][j] = (u[i][j] + e_1[i][j]) % q;
		}
	}

	//�޸� �Ҵ� ����
	for (int i = 0;i < k;i++) {
		for (int j = 0;j < k;j++) {
			free(A[i][j]);
		}
		free(A[i]);
	}
	free(A);
	free(buffer_int);

	//mu ��� ���� ���ۿ� �޸� �Ҵ�
	buffer_int = (int*)malloc(sizeof(int) * n);
	if (buffer_int == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}

	//mu ���� �� ���
	int mu[n] = { 0 };
	ByteDecode(message, 1, buffer_int);
	Decomp(buffer_int, 1, mu, 256);

	free(buffer_int);

	//v ���, ���߿� NTT ��ȯ �� �� �ޱ� ���� v_hat ����
	int v[n] = { 0 };
	int v_hat[n] = { 0 };

	//t_hat* y_hat ��� ���� ���ۿ� �޸� �Ҵ�
	buffer_int = (int*)malloc(sizeof(int) * n);
	if (buffer_int == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}

	//buffer_int�� ���۷� Ȱ���Ͽ� t_hat*y_hat ���
	for (int i = 0;i < k;i++) {
		Multiply_NTT(t_hat[i], y_hat[i], buffer_int, zeta);
		for (int j = 0;j < 256;j++) {
			v_hat[j] = (v_hat[j] + buffer_int[j]) % q;
		}
	}

	for (int i = 0;i < k;i++) {
		free(t_hat[i]);
	}
	free(t_hat);

	//v_hat���� v�� NTT_inverse ����
	NTT_inv(v_hat, v, zeta);

	//e_2, mu ���ϱ�
	for (int i = 0;i < n;i++) {
		v[i] = (v[i] + e_2[i] + mu[i]) % q;
	}

	//��ȣ�� ��� ���� ���ۿ� �޸� �Ҵ�
	buffer_int = (int*)malloc(sizeof(int) * n);
	if (buffer_int == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}

	//��ȣ���� �� ����
	for (int i = 0;i < k;i++) {
		Comp(u[i], d_u, buffer_int, n);
		ByteEncode(buffer_int, d_u, ciphertext + i * 32 * d_u);
	}
	Comp(v, d_v, buffer_int, n);
	ByteEncode(buffer_int, d_v, ciphertext + k * 32 * d_u);

	free(buffer_int);

	//��� ���
	//printf("\nK-PKE Encryption Succeed\n");

	return;
}

void K_PKE_Dec(unsigned char* dk_pke, unsigned char* ciphertext, unsigned char* message_) {

	int* buffer_int = NULL;
	int* buffer_int_hat = NULL;

	//c_1, c_2 ����
	unsigned char c_1[32 * d_u * k] = { 0 };
	unsigned char c_2[32 * d_v] = { 0 };

	//c_1, c_2�� ciphertext����
	memcpy(c_1, ciphertext, 32 * d_u * k);
	memcpy(c_2, ciphertext + 32 * d_u * k, 32 * d_v);

	//u ����
	int u[k][n] = { 0 };

	//u_ ��� ���� ���ۿ� �޸� �Ҵ�
	buffer_int = (int*)malloc(sizeof(int) * n);

	//u �� c_1 ��ȯ
	for (int i = 0;i < k;i++) {
		ByteDecode(c_1 + i * 32 * d_u, d_u, buffer_int);
		Decomp(buffer_int, d_u, u[i], n);
	}

	free(buffer_int);

	//v ����
	int v_[n] = { 0 };

	//v_ ��� ���� ���ۿ� �޸� �Ҵ�
	buffer_int = (int*)malloc(sizeof(int) * n);
	if (buffer_int == NULL) {
		perror("Failed to allocate memory");
		exit(EXIT_FAILURE);
	}

	//v_ �� c_2 ��ȯ
	ByteDecode(c_2, d_v, buffer_int);
	Decomp(buffer_int, d_v, v_, n);

	free(buffer_int);


	//s_hat ����
	int s_hat[k][n] = { 0 };

	//s_hat �� dk_pke ��ȯ
	for (int i = 0;i < k;i++) {
		ByteDecode(dk_pke + i * 384, 12, s_hat[i]);
	}

	//w ����, 0���� �ʱ�ȭ
	int w[n] = { 0 };

	//NTT�������ؼ� zeta�ҷ�����
	int* zeta = GenZeta();

	//NTT ���� ���� u_hat=NTT(u) ����, u_hat ���
	int u_hat[k][n] = { 0 };

	for (int i = 0;i < k;i++) {

		NTT(u[i], u_hat[i], zeta);
	}

	//w ��� ���� ���ۿ� �޸� �Ҵ�
	buffer_int = (int*)malloc(sizeof(int) * n);
	buffer_int_hat = (int*)malloc(sizeof(int) * n);
	if (buffer_int == NULL || buffer_int_hat == NULL) {
		perror("Failed to allocate memory");
		exit(EXIT_FAILURE);
	}


	for (int i = 0;i < k;i++) {
		//s_hat^t*u_hat ���
		Multiply_NTT(s_hat[i], u_hat[i], buffer_int_hat, zeta);
		//NTT inverse ��� �� w�� ����
		NTT_inv(buffer_int_hat, buffer_int, zeta);
		for (int j = 0;j < n;j++) {
			w[j] = (w[j] + buffer_int[j]) % q;
		}
	}

	free(buffer_int);
	free(buffer_int_hat);

	//w ���
	for (int i = 0;i < n;i++) {
		w[i] = (v_[i] - w[i] + q) % q;
	}

	//m_ ��� ���� ���ۿ� �޸� �Ҵ�
	buffer_int = (int*)malloc(sizeof(int) * n);
	if (buffer_int == NULL) {
		perror("Failed to allocate memory");
		exit(EXIT_FAILURE);
	}

	//m_ ���
	Comp(w, 1, buffer_int, n);
	ByteEncode(buffer_int, 1, message_);

	free(buffer_int);

	//��� ���
	//printf("\nK-PKE Decryption Succeed\n");
	return;
}