#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include "hash.h"
#include "NTT.h"
#include "AuxiliaryAlgorithm.h"
#include "parameter.h"

void K_PKE_KeyGen(unsigned char* d, unsigned char* ek_pke, unsigned char* dk_pke) {
	if (_msize(d) != 32) {
		perror("Input length Error");
		exit(EXIT_FAILURE);
	}//input 길이 체크

	unsigned char* input = (unsigned char*)malloc(sizeof(unsigned char) * 33);
	if (input == NULL) {
		perror("Failed to allocate memory"); // 오류 메시지 출력
		exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
	}
	for (int i = 0;i < 32;i++) {
		input[i] = d[i];
	}
	input[32] = k;
	unsigned char* rho = (unsigned char*)malloc(sizeof(unsigned char) * 32);
	if (rho == NULL) {
		perror("Failed to allocate memory"); // 오류 메시지 출력
		exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
	}
	unsigned char* sigma = (unsigned char*)malloc(sizeof(unsigned char) * 32);
	if (sigma == NULL) {
		perror("Failed to allocate memory"); // 오류 메시지 출력
		exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
	}
	G(input, rho, sigma);
	free(input);
	
	int N = 0;

	//generate A
	int*** A = (int***)malloc(sizeof(int**) * k);
	if (A == NULL) {
		perror("Failed to allocate memory"); // 오류 메시지 출력
		exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
	}
	for (int i = 0;i < k;i++) {
		A[i] = (int**)malloc(sizeof(int*) * k);
		if (A[i] == NULL) {
			perror("Failed to allocate memory"); // 오류 메시지 출력
			exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
		}
	}

	for (int i = 0;i < k;i++) {
		for (int j = 0;j < k;j++) {
			unsigned char* input = (unsigned char*)malloc(sizeof(unsigned char) * 34);
			if (input == NULL) {
				perror("Failed to allocate memory"); // 오류 메시지 출력
				exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
			}
			for (int i = 0;i < 32;i++) {
				input[i] = rho[i];
			}
			input[32] = j;
			input[33] = i;
			A[i][j] = (int*)malloc(sizeof(int) * 256);
			if (A[i][j] == NULL) {
				perror("Failed to allocate memory"); // 오류 메시지 출력
				exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
			}
			SampleNTT(input, A[i][j], 32);
			free(input);
		}
	}

	//확인용으로 출력
	for (int i = 0;i < k;i++) {
		for (int j = 0;j < k;j++) {
			printf("A[%d],[%d]= ", i, j);
			for (int l = 0;l < 256;l++) {
				printf("%u ", A[i][j][l]);
			}
			printf("\n");
		}
	}


	//generate s
	int** s = (int**)malloc(sizeof(int*) * k);
	if (s == NULL) {
		perror("Failed to allocate memory"); // 오류 메시지 출력
		exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
	}
	for (int i = 0;i < k;i++) {
		s[i] = (int*)malloc(sizeof(int) * 256);
		if (s[i] == NULL) {
			perror("Failed to allocate memory"); // 오류 메시지 출력
			exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
		}
	}
	for (int i = 0;i < k;i++) {
		unsigned char* output = (unsigned char*)malloc(sizeof(unsigned char) * 64 * n_1);
		if (output == NULL) {
			perror("Failed to allocate memory"); // 오류 메시지 출력
			exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
		}
		PRF(n_1, sigma, N, output);
		SamplePolyCBD(output, s[i], 64 * n_1);
		free(output);
		N++;
	}

	//generate e
	int** e = (int**)malloc(sizeof(int*) * k);
	if (e == NULL) {
		perror("Failed to allocate memory"); // 오류 메시지 출력
		exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
	}
	for (int i = 0;i < k;i++) {
		e[i] = (int*)malloc(sizeof(int) * 256);
		if (e[i] == NULL) {
			perror("Failed to allocate memory"); // 오류 메시지 출력
			exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
		}
	}
	for (int i = 0;i < k;i++) {
		unsigned char* output = (unsigned char*)malloc(sizeof(unsigned char) * 64 * n_1);
		if (output == NULL) {
			perror("Failed to allocate memory"); // 오류 메시지 출력
			exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
		}
		PRF(n_1, sigma, N, output);
		SamplePolyCBD(output, e[i], 64 * n_1);
		free(output);
		N++;
	}

	int* zeta = GenZeta();

	int** s_hat = (int**)malloc(sizeof(int*) * k);
	if (s_hat == NULL) {
		perror("Failed to allocate memory"); // 오류 메시지 출력
		exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
	}
	for (int i = 0;i < k;i++) {
		s_hat[i] = (int*)malloc(sizeof(int) * 256);
		if (s_hat[i] == NULL) {
			perror("Failed to allocate memory"); // 오류 메시지 출력
			exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
		}
		NTT(s[i], s_hat[i], zeta);
	}

	int** e_hat = (int**)malloc(sizeof(int*) * k);
	if (e_hat == NULL) {
		perror("Failed to allocate memory"); // 오류 메시지 출력
		exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
	}
	for (int i = 0;i < k;i++) {
		e_hat[i] = (int*)malloc(sizeof(int*) * 256);
		if (e_hat[i] == NULL) {
			perror("Failed to allocate memory"); // 오류 메시지 출력
			exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
		}
		NTT(e[i], e_hat[i], zeta);
	}

	int** t = (int**)malloc(sizeof(int*) * k);
	if (t == NULL) {
		perror("Failed to allocate memory"); // 오류 메시지 출력
		exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
	}
	for (int i = 0;i < k;i++) {
		t[i] = (int*)malloc(sizeof(int) * 256);
		if (t[i] == NULL) {
			perror("Failed to allocate memory"); // 오류 메시지 출력
			exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
		}
		for (int l = 0;l < 256;l++) {
			t[i][l] = e_hat[i][l];
		}
		for (int j = 0;j < k;j++) {
			int* output = (int*)malloc(sizeof(int) * 256);
			if (output == NULL) {
				perror("Failed to allocate memory"); // 오류 메시지 출력
				exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
			}
			Multiply_NTT(A[i][j], s_hat[j], output, zeta);
			for (int l = 0;l < 256;l++) {
				t[i][l] = (t[i][l] + output[l]) % q;
			}
			free(output);
		}
		
	}
	printf("okay");

	for (int i = 0;i < k;i++) {
		ByteEncode(t[i], 12, ek_pke[i]);
		//size_t siz = _msize(ek_pke[i]);
		//printf("%zu", siz);
		for (int j = 0;j < 256;j++) {
			printf("% d", t[i][j]);
		}
			
		ByteEncode(s_hat[i], 12, dk_pke[i]);
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
	}
	free(s);
	free(s_hat);
	free(e);
	free(e_hat);
	free(A);

	printf("\nSuccess");
	return;
}

int main() {
	unsigned char* d = (unsigned char*)malloc(sizeof(unsigned char) * 32);
	if (d == NULL) {
		perror("Failed to allocate memory"); // 오류 메시지 출력
		exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
	}

	//KeyGen의 input 생성
	unsigned char* text = "message";
	size_t text_length = strlen(text);
	sha3_256_hash(text, text_length, d);

	unsigned char** ek_pke = (unsigned char**)malloc(sizeof(unsigned char*) * k);
	unsigned char** dk_pke = (unsigned char**)malloc(sizeof(unsigned char*) * k);
	if (ek_pke == NULL) {
		perror("Failed to allocate memory"); // 오류 메시지 출력
		exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
	}
	if (dk_pke == NULL) {
		perror("Failed to allocate memory"); // 오류 메시지 출력
		exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
	}
	for (int i = 0;i < k;i++) {
		ek_pke[i]= (int*)malloc(sizeof(int) * 32 * 12);
		if (ek_pke[i] == NULL) {
			perror("Failed to allocate memory"); // 오류 메시지 출력
			exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
		}
		dk_pke[i] = (int*)malloc(sizeof(int) * 32 * 12);
		if (dk_pke[i] == NULL) {
			perror("Failed to allocate memory"); // 오류 메시지 출력
			exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
		}
	}

	

	K_PKE_KeyGen(d, ek_pke, dk_pke);

	/*unsigned char** A = (unsigned char**)malloc(sizeof(unsigned char) * 3);
	if (A == NULL) {
		perror("Failed to allocate memory"); // 오류 메시지 출력
		exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
	}
	for (int i = 0;i < 3;i++) {
		A[i] = (unsigned char*)malloc(sizeof(unsigned char) * 4);
		if (A[i] == NULL) {
			perror("Failed to allocate memory"); // 오류 메시지 출력
			exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
		}
	}
	for (int i = 0;i < 3;i++) {
		for (int j = 0;j < 3;j++) {
			A[i][j] = 1;
		}
	}
	for (int i = 0;i < 3;i++) {
		for (int j = 0;j < 4;j++) {
			A[i][j] = 1;
			printf("A[%d],[%d]=%u\n", i, j, A[i][j]);
		}
	}*/


	return 0;
}