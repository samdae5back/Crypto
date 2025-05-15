#include <stdio.h>
#include <string.h>
#include "NTT_.h"
#include "hash.h"
#include "auxiliary.h"
#include "K-PKE.h"
#include "ML-KEM.h"
#include "parameter.h"

void ML_KEM_KeyGen_internal(unsigned char* d, unsigned char* z, unsigned char* ek, unsigned char* dk) {

	//ek에 키 복사, dk 앞 부분에 키 복사
	K_PKE_KeyGen(d, ek, dk);

	//dk 중간에 ek 복사
	memcpy(dk + 384 * k, ek, 384 * k + 32);

	//버퍼에 해쉬값 받기
	unsigned char* buffer_char = (unsigned char*)malloc(sizeof(unsigned char) * 32);
	if (buffer_char == NULL) {
		perror("Failed to allocate memory"); // 오류 메시지 출력
		exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
	}
	H(ek, 384 * k + 32, buffer_char);

	//해쉬값 dk에 복사
	memcpy(dk + 768 * k + 32, buffer_char, 32);
	free(buffer_char);

	//z값 dk에 복사
	memcpy(dk + 768 * k + 64, z, 32);

	//결과 출력
	//printf("\nML-KEM Internal Key Generatinon Succeed\n");

	return;
}

void ML_KEM_Encaps_internal(unsigned char* ek, unsigned char* m, unsigned char* SharedSecretKey, unsigned char* ciphertext) {

	unsigned char* buffer_char = NULL;

	//G 계산 위해 버퍼에 메모리 할당
	buffer_char = (unsigned char*)malloc(sizeof(unsigned char) * 384 * k + 32);
	if (buffer_char == NULL) {
		perror("Failed to allocate memory"); // 오류 메시지 출력
		exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
	}

	//G의 입력 생성
	memcpy(buffer_char, m, 32);
	H(ek, 384 * k + 32, buffer_char + 32);

	//G 계산
	unsigned char r[32] = { 0 };
	G(buffer_char, 64, SharedSecretKey, r);

	free(buffer_char);

	//ciphertext 계산
	K_PKE_Enc(ek, m, r, ciphertext);

	//결과 출력
	//printf("\nML-KEM Internal Encapsulation Succeed\n");
	return;
}

void ML_KEM_Decaps_internal(unsigned char* dk, unsigned char* ciphertext, unsigned char* SharedSecretKey_) {

	unsigned char* buffer_char = NULL;

	//ek, dk 추출
	unsigned char ek_pke[384 * k + 32] = { 0 };
	unsigned char dk_pke[384 * k] = { 0 };

	memcpy(dk_pke, dk, 384 * k);
	memcpy(ek_pke, dk + 384 * k, 384 * k + 32);

	//h, z 추출
	unsigned char h[32] = { 0 };
	unsigned char z[32] = { 0 };

	memcpy(h, dk + 768 * k + 32, 32);
	memcpy(z, dk + 768 * k + 64, 32);

	//m_ 생성
	unsigned char m_[32] = { 0 };
	K_PKE_Dec(dk_pke, ciphertext, m_);

	//G의 계산 위해 버퍼에 메모리 할당
	buffer_char = (unsigned char*)malloc(sizeof(unsigned char) * 64);
	if (buffer_char == NULL) {
		perror("Failed to allocate memory");
		exit(EXIT_FAILURE);
	}
	//G 계산하여 SharedSecretKey_, r 생성
	unsigned char r[32] = { 0 };

	memcpy(buffer_char, m_, 32);
	memcpy(buffer_char + 32, h, 32);

	G(buffer_char, 64, SharedSecretKey_, r);

	free(buffer_char);

	//J 계산 위해 버퍼에 메모리 할당
	buffer_char = (unsigned char*)malloc(sizeof(unsigned char) * 32 * (d_u * k + d_v + 1));
	if (buffer_char == NULL) {
		perror("Failed to allocate memory");
		exit(EXIT_FAILURE);
	}

	memcpy(buffer_char, m_, 32);
	memcpy(buffer_char + 32, ciphertext, 32);

	//거짓 키 생성
	unsigned char SharedSecretKey__false[32] = { 0 };
	J(buffer_char, 32, SharedSecretKey__false);

	free(buffer_char);

	//ciphertext_ 생성
	unsigned char ciphertext_[32 * (d_u * k + d_v)] = { 0 };
	K_PKE_Enc(ek_pke, m_, r, ciphertext_);

	for (int i = 0;i < 32 * (d_u * k + d_v);i++) {
		if (ciphertext[i] != ciphertext_[i]) {
			memcpy(SharedSecretKey_, SharedSecretKey__false, 32);
			printf("\nML-KEM Internal Decapsulation Failed\n");
			return;
		}
	}

	//결과 출력
	//printf("\nML-KEM Internal Decapsulation Succeed\n");
	return;
}

void ML_KEM_KeyGen(unsigned char* ek, unsigned char* dk) {
	//d 생성
	unsigned char d[32] = { 0 };
	RBG(d, 32);

	//z 생성
	unsigned char z[32] = { 0 };
	RBG(z, 32);

	//ek, dk 생성
	ML_KEM_KeyGen_internal(d, z, ek, dk);
	
	//결과 출력
	//printf("\nML-KEM Key Generatinon Succeed\n");

	return;
}

void ML_KEM_Encaps(unsigned char* ek, unsigned char* SharedSecretKey, unsigned char* c) {

	//m 생성
	unsigned char m[32] = { 0 };
	RBG(m, 32);

	ML_KEM_Encaps_internal(ek, m, SharedSecretKey, c);

	//결과 출력
	//printf("\nML-KEM Encapsulation Succeed\n");

	return;
} 

void ML_KEM_Decaps(unsigned char* dk, unsigned char* c, unsigned char* SharedSecretKey_) {

	ML_KEM_Decaps_internal(dk, c, SharedSecretKey_);

	//결과 출력
	//printf("\nML-KEM Decapsulation Succeed\n");
}
