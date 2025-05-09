#include <stdio.h>
#include "NTT.h"
#include "hash.h"
#include "auxiliary.h"
#include "K-PKE_KeyGen.h"
#include "K-PKE_Enc.h"
#include "K-PKE_Dec.h"
#include "parameter.h"

void ML_KEM_KeyGen_internal(unsigned char* d, unsigned char* z, unsigned char** ek, unsigned char** dk) {

	//K-PKE 사용하여 키 생성
	unsigned char** ek_pke = (unsigned char**)malloc(sizeof(unsigned char*) * (k + 1));
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
		ek_pke[i] = (unsigned char*)malloc(sizeof(unsigned char) * 32 * 12);
		if (ek_pke[i] == NULL) {
			perror("Failed to allocate memory"); // 오류 메시지 출력
			exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
		}
		dk_pke[i] = (unsigned char*)malloc(sizeof(unsigned char) * 32 * 12);
		if (dk_pke[i] == NULL) {
			perror("Failed to allocate memory"); // 오류 메시지 출력
			exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
		}
	}
	ek_pke[k] = (unsigned char*)malloc(sizeof(unsigned char) * 32);
	if (ek_pke[k] == NULL) {
		perror("Failed to allocate memory"); // 오류 메시지 출력
		exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
	}
	K_PKE_KeyGen(d, ek_pke, dk_pke);

	//ek 생성
	for (int i = 0;i < k;i++) {
		for (int j = 0;j < 384;j++) {
			ek[i][j] = ek_pke[i][j];
		}
	}
	for (int j = 0;j < 32;j++) {
		ek[k][j] = ek_pke[k][j];
	}

	//dk 생성
	for (int i = 0;i < k;i++) {
		for (int j = 0;j < 384;j++) {
			dk[i][j] = dk_pke[i][j];
		}
	}
	unsigned char* buffer_char = (unsigned char*)malloc(sizeof(unsigned char) * (384 * k + 32));
	if (buffer_char == NULL) {
		perror("Failed to allocate memory"); // 오류 메시지 출력
		exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
	}
	for (int i = 0;i < k;i++) {
		for (int j = 0;j < 384;j++) {
			buffer_char[384 * i + j] = ek_pke[i][j];
			dk[k + i][j] = ek_pke[i][j];
		}
	}
	for (int j = 0;j < 32;j++) {
		buffer_char[384 * k + j] = ek_pke[k][j];
		dk[2 * k][j] = ek_pke[k][j];
	}
	for (int i = 0;i < k + 1;i++) {
		free(ek_pke[i]);
	}
	free(ek_pke);
	unsigned char* buffer_hash_char = (unsigned char*)malloc(sizeof(unsigned char) * 32);
	if (buffer_hash_char == NULL) {
		perror("Failed to allocate memory"); // 오류 메시지 출력
		exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
	}
	H(buffer_char, buffer_hash_char);
	free(buffer_char);
	for (int j = 0;j < 32;j++) {
		dk[2 * k + 1][j] = buffer_hash_char[j];
	}
	free(buffer_hash_char);
	for (int j = 0;j < 32;j++) {
		dk[2 * k + 2][j] = z[j];
	}
	for (int i = 0;i < k;i++) {
		free(dk_pke[i]);
	}
	free(dk_pke);

	printf("\nML-KEM Internal Key Generatinon Succeed\n");
	return;
}

void ML_KEM_Encaps_internal(unsigned char** ek, unsigned char* m, unsigned char* SharedSecretKey, unsigned char** ciphertext) {
	//G의 입력 생성
	unsigned char* buffer_ek = (unsigned char*)malloc(sizeof(unsigned char) * 384 * k + 32);
	if (buffer_ek == NULL) {
		perror("Failed to allocate memory"); // 오류 메시지 출력
		exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
	}
	for (int i = 0;i < k;i++) {
		for (int j = 0;j < 384;j++) {
			buffer_ek[384 * i + j] = ek[i][j];
		}
	}
	for (int j = 0;j < 32;j++) {
		buffer_ek[384 * k + j] = ek[k][j];
	}
	unsigned char* buffer_hash = (unsigned char*)malloc(sizeof(unsigned char) * 64);
	if (buffer_hash == NULL) {
		perror("Failed to allocate memory"); // 오류 메시지 출력
		exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
	}
	H(buffer_ek, buffer_hash);
	free(buffer_ek);
	unsigned char* buffer_char = (unsigned char*)malloc(sizeof(unsigned char) * 64);
	if (buffer_char == NULL) {
		perror("Failed to allocate memory"); // 오류 메시지 출력
		exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
	}
	for (int i = 0;i < 32;i++) {
		buffer_char[i] = m[i];
		buffer_char[32 + i] = buffer_hash[i];
	}
	free(buffer_hash);
	unsigned char* r = (unsigned char*)malloc(sizeof(unsigned char) * 32);
	if (r == NULL) {
		perror("Failed to allocate memory"); // 오류 메시지 출력
		exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
	}
	G(buffer_char, SharedSecretKey, r);
	free(buffer_char);
	K_PKE_Enc(ek, m, r, ciphertext);

	printf("\nML-KEM Internal Encapsulation Succeed\n");
	return;
}

void ML_KEM_Decaps_internal(unsigned char** dk, unsigned char** ciphertext, unsigned char* SharedSecretKey_) {
	//ek, dk 추출
	unsigned char** ek_pke = (unsigned char**)malloc(sizeof(unsigned char*) * (k + 1));
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
		ek_pke[i] = (unsigned char*)malloc(sizeof(unsigned char) * 32 * 12);
		if (ek_pke[i] == NULL) {
			perror("Failed to allocate memory"); // 오류 메시지 출력
			exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
		}
		dk_pke[i] = (unsigned char*)malloc(sizeof(unsigned char) * 32 * 12);
		if (dk_pke[i] == NULL) {
			perror("Failed to allocate memory"); // 오류 메시지 출력
			exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
		}
	}
	ek_pke[k] = (unsigned char*)malloc(sizeof(unsigned char) * 32);
	if (ek_pke[k] == NULL) {
		perror("Failed to allocate memory"); // 오류 메시지 출력
		exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
	}

	for (int i = 0;i < k;i++) {
		for (int j = 0;j < 384;j++) {
			dk_pke[i][j] = dk[i][j];
		}
	}
	for (int i = 0;i < k;i++) {
		for (int j = 0;j < 384;j++) {
			ek_pke[i][j] = dk[k + i][j];
		}
	}
	for (int j = 0;j < 32;j++) {
		ek_pke[k][j] = dk[2 * k][j];
	}

	//h, z qhrtk
	unsigned char* h = (unsigned char*)malloc(sizeof(unsigned char) * 32);
	if (h == NULL) {
		perror("Failed to allocate memory"); // 오류 메시지 출력
		exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
	}
	unsigned char* z = (unsigned char*)malloc(sizeof(unsigned char) * 32);
	if (z == NULL) {
		perror("Failed to allocate memory"); // 오류 메시지 출력
		exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
	}
	for (int j = 0;j < 32;j++) {
		h[j] = dk[2 * k + 1][j];
		z[j] = dk[2 * k + 2][j];
	}

	//m_ 생성
	unsigned char* m_ = (unsigned char*)malloc(sizeof(unsigned char) * 32);
	if (m_ == NULL) {
		perror("Failed to allocate memory"); // 오류 메시지 출력
		exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
	}
	K_PKE_Dec(dk_pke, ciphertext, m_);

	//G의 입력 생성
	unsigned char* buffer_char = (unsigned char*)malloc(sizeof(unsigned char) * 64);
	if (buffer_char == NULL) {
		perror("Failed to allocate memory"); // 오류 메시지 출력
		exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
	}
	//SharedSecretKey_, r 생성
	unsigned char* r = (unsigned char*)malloc(sizeof(unsigned char) * 64);
	if (r == NULL) {
		perror("Failed to allocate memory"); // 오류 메시지 출력
		exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
	}
	for (int j = 0;j < 32;j++) {
		buffer_char[j] = m_[j];
		buffer_char[j + 32] = h[j];
	}

	G(buffer_char, SharedSecretKey_, r);
	free(buffer_char);

	//j의 입력 생성
	buffer_char = (unsigned char*)malloc(sizeof(unsigned char) * 32 * (d_u * k + d_v + 1));
	if (buffer_char == NULL) {
		perror("Failed to allocate memory"); // 오류 메시지 출력
		exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
	}
	for (int j = 0;j < 32;j++) {
		buffer_char[j] = z[j];
	}
	for (int i = 0;i < k;i++) {
		for (int j = 0;j < 32 * d_u;j++) {
			buffer_char[32 * (i + 1) + j] = ciphertext[i][j];
		}
	}
	for (int j = 0;j < 32 * d_v;j++) {
		buffer_char[32 * (k + 1) + j] = ciphertext[k][j];
	}
	//거짓 키 생성
	unsigned char* buffer_key = (unsigned char*)malloc(sizeof(unsigned char) * 32);
	if (buffer_key == NULL) {
		perror("Failed to allocate memory"); // 오류 메시지 출력
		exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
	}
	J(buffer_char, buffer_key);
	free(buffer_char);

	//ciphertext_ 생성
	unsigned char** ciphertext_ = (unsigned char**)malloc(sizeof(unsigned char*) * (k + 1));
	if (ciphertext_ == NULL) {
		perror("Failed to allocate memory"); // 오류 메시지 출력
		exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
	}
	for (int i = 0;i < k;i++) {
		ciphertext_[i] = (unsigned char*)malloc(sizeof(unsigned char) * 32 * d_u);
		if (ciphertext_[i] == NULL) {
			perror("Failed to allocate memory"); // 오류 메시지 출력
			exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
		}
	}
	ciphertext_[k] = (char*)malloc(sizeof(char) * 32 * d_v);
	if (ciphertext_[k] == NULL) {
		perror("Failed to allocate memory"); // 오류 메시지 출력
		exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
	}
	K_PKE_Enc(ek_pke, m_, r, ciphertext_);
	for (int i = 0;i < k;i++) {
		for (int j = 0;j < 32 * d_u;j++) {
			if (ciphertext[i][j] != ciphertext_[i][j]) {
				for (int l = 0;l < 32;l++) {
					SharedSecretKey_[l] = buffer_key[l];
				}
				printf("\nML-KEM Internal Decapsulation Failed\n");
				return;
			}
		}
	}
	for (int j = 0;j < 32 * d_v;j++) {
		if (ciphertext[k][j] != ciphertext_[k][j]) {
			for (int l = 0;l < 32;l++) {
				SharedSecretKey_[l] = buffer_key[l];
			}
			printf("\nML-KEM Internal Decapsulation Failed\n");
			return;
		}
	}

	printf("\nML-KEM Internal Decapsulation Succeed\n");
	return;
}

