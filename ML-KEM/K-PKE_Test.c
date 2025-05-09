#include <stdio.h>
#include <string.h>//strlen 사용시 필요
#include <malloc.h>//_msize 사용시 필요
#include "NTT.h"
#include "hash.h"
#include "auxiliary.h"
#include "K-PKE_KeyGen.h"
#include "K-PKE_Enc.h"
#include "K-PKE_Dec.h"
#include "parameter.h"
/*
int main() {
	unsigned char* d = (unsigned char*)malloc(sizeof(unsigned char) * 32);
	if (d == NULL) {
		perror("Failed to allocate memory"); // 오류 메시지 출력
		exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
	}

	//KeyGen의 input 생성
	unsigned char* text = "message  test test";
	size_t text_length = strlen(text);
	sha3_256_hash(text, text_length, d);

	//Key Generation
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

	printf("ek_pke :\n");
	for (int i = 0;i < k;i++) {
		printf("i = %d \n", i);
		for (int j = 0;j < 384;j++) {
			printf("%02x ", ek_pke[i][j]);
		}
		printf("\n");

	}
	printf("rho = \n");
	for (int i = 0;i < 32;i++) {
		printf("%02x ", ek_pke[k][i]);
	}
	printf("\n");

	printf("dk_pke :\n");
	for (int i = 0;i < k;i++) {
		printf("i = %d \n", i);
		for (int j = 0;j < 384;j++) {
			printf("%02x ", dk_pke[i][j]);
		}
		printf("\n");

	}

	//Encryption
	unsigned char* message = (unsigned char*)malloc(sizeof(unsigned char) * 32);
	if (message == NULL) {
		perror("Failed to allocate memory"); // 오류 메시지 출력
		exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
	}
	unsigned char* plaintext = "ab";
	size_t plaintext_length = strlen(plaintext);
	sha3_256_hash(plaintext, plaintext_length, message);

	printf("\nOriginal message : ");
	for (int i = 0;i < 32;i++) {
		printf("(%d)%02x ", i, message[i]);
	}
	printf("\n");

	unsigned char* randomness = (unsigned char*)malloc(sizeof(unsigned char) * 32);
	if (randomness == NULL) {
		perror("Failed to allocate memory"); // 오류 메시지 출력
		exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
	}
	unsigned char* random = "randomness";
	size_t random_length = strlen(random);
	sha3_256_hash(random, random_length, randomness);

	printf("\nRandomness input to Enc : ");
	for (int i = 0;i < 32;i++) {
		printf("(%d)%02x ", i, randomness[i]);
	}
	printf("\n");

	unsigned char** ciphertext = (unsigned char**)malloc(sizeof(unsigned char*) * (k + 1));
	if (ciphertext == NULL) {
		perror("Failed to allocate memory"); // 오류 메시지 출력
		exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
	}
	for (int i = 0;i < k;i++) {
		ciphertext[i] = (unsigned char*)malloc(sizeof(unsigned char) * 32 * d_u);
		if (ciphertext[i] == NULL) {
			perror("Failed to allocate memory"); // 오류 메시지 출력
			exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
		}
	}
	ciphertext[k] = (char*)malloc(sizeof(char) * 32 * d_v);
	if (ciphertext[k] == NULL) {
		perror("Failed to allocate memory"); // 오류 메시지 출력
		exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
	}
	K_PKE_Enc(ek_pke, message, randomness, ciphertext);

	printf("\n ciphertext :\n");
	for (int i = 0;i < k;i++) {
		printf("i = %d \n", i);
		for (int j = 0;j < 32 * d_u;j++) {
			printf("%02x ", ciphertext[i][j]);
		}
		printf("\n");

	}
	printf("i = %d\n", k);
	for (int j = 0;j < 32 * d_v;j++) {
		printf("%02x ", ciphertext[k][j]);
	}
	printf("\n");

	/// Decryption
	unsigned char* message_ = (unsigned char*)malloc(sizeof(unsigned char) * 32);
	if (message_ == NULL) {
		perror("Failed to allocate memory"); // 오류 메시지 출력
		exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
	}

	K_PKE_Dec(dk_pke, ciphertext, message_);

	printf("\nOriginal message : ");
	for (int i = 0;i < 32;i++) {
		printf("(%d)%02x ", i, message[i]);
	}
	printf("\n");

	printf("\Decrypted message : ");
	for (int i = 0;i < 32;i++) {
		printf("(%d)%02x ", i, message_[i]);
	}
	printf("\n");





	for (int i = 0;i < 32;i++) {
		if (message[i] != message_[i]) {
			printf("K-PKE Fail\n");
				return 0;
		}
	}
	printf("K-PKE Succeed\n");
	return 0;
}
*/