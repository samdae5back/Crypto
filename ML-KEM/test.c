#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>//strlen 사용시 필요
#include <time.h>
#include "NTT_.h"
#include "hash.h"
#include "auxiliary.h"
#include "K-PKE.h"
#include "ML-KEM.h"
#include "KAT.h"
#include "parameter.h"

int main() {
	FILE* fip;
	char* filename = "ml_kem_512.kat";
	fip = fopen(filename, "r");
	if (fip == NULL) {
		perror("File open failed");
		return 1;
	}

	int state = 0;
	int i = 0;
	int s = 0;
	int f = 0;

	for (i = 0; ; i++) { // 무한 루프처럼 보이지만 내부에서 break
		printf("Test vector number (%d) : ", i);
		state = ScanKAT(fip);

		if (state == -1) { // EOF 또는 심각한 오류로 더 이상 진행 불가
			break;
		}
		else if (state == 0) {
			s++;
		}
		else if (state == 1) {
			f++;
		}
	}

	printf("\n Result\n Success:(%d), Fail:(%d)\n", s, f);
	fclose(fip);


	clock_t start = 0, finish = 0;
	double duration = 0;
	double total_time_GeyGen = 0;
	double total_time_Enc = 0;
	double total_time_Dec = 0;
	double mean_time_GeyGen = 0;
	double mean_time_Enc = 0;
	double mean_time_Dec = 0;

	int test_num = 1000;
	
	//ek, dk 생성
	unsigned char ek[384 * k + 32] = { 0 };
	unsigned char dk[768 * k + 96] = { 0 };

	//SharedSecretKey 생성
	unsigned char SharedSecretKey[32] = { 0 };

	//ciphertext 생성
	unsigned char ciphertext[32 * (d_u * k + d_v)] = { 0 };
	
	//SharedSecretKey_ 생성
	unsigned char SharedSecretKey_[32] = { 0 };

	ML_KEM_KeyGen(ek, dk);
	ML_KEM_Encaps(ek, SharedSecretKey, ciphertext);
	ML_KEM_Decaps(dk, ciphertext, SharedSecretKey_);

	for (int i = 0;i < test_num;i++) {

		//KeyGen test
		start = clock();
		ML_KEM_KeyGen(ek, dk);
		finish = clock();
		duration = ((double)finish - (double)start) / CLOCKS_PER_SEC;
		total_time_GeyGen = total_time_GeyGen + duration;

		//Enc test
		start = clock();
		ML_KEM_Encaps(ek, SharedSecretKey, ciphertext);
		finish = clock();
		duration = ((double)finish - (double)start) / CLOCKS_PER_SEC;
		total_time_Enc = total_time_Enc + duration;

		//Dec test
		start = clock();
		ML_KEM_Decaps(dk, ciphertext, SharedSecretKey_);
		finish = clock();
		duration = ((double)finish - (double)start) / CLOCKS_PER_SEC;
		total_time_Dec = total_time_Dec + duration;
	}

	printf("\n Test number : %d ", test_num);

	mean_time_GeyGen = total_time_GeyGen / test_num;
	printf("\n Total time KeyGen:(%f) sec , Mean time KeyGen:(%f) sec", total_time_GeyGen, mean_time_GeyGen);

	mean_time_Enc = total_time_Enc / test_num;
	printf("\n Total time Enc:(%f) sec, Mean time Enc:(%f) sec", total_time_Enc, mean_time_Enc);

	mean_time_Dec = total_time_Dec / test_num;
	printf("\n Total time Dec:(%f) sec, Mean time Dec:(%f) sec", total_time_Dec, mean_time_Dec);
	printf("\n");

	return 0;
}
