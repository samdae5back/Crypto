#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>//strlen 荤侩矫 鞘夸
#include <time.h>
#include "NTT_.h"
#include "hash.h"
#include "auxiliary.h"
#include "K-PKE.h"
#include "ML-KEM.h"
#include "parameter.h"

int main() {
	
	clock_t start = 0, finish = 0;
	double duration = 0;
	double total_time_GeyGen = 0;
	double total_time_Enc = 0;
	double total_time_Dec = 0;
	double mean_time_GeyGen = 0;
	double mean_time_Enc = 0;
	double mean_time_Dec = 0;

	int test_num = 1000;
	
	//ek, dk 积己
	unsigned char ek[384 * k + 32] = { 0 };
	unsigned char dk[768 * k + 96] = { 0 };

	//SharedSecretKey 积己
	unsigned char SharedSecretKey[32] = { 0 };

	//ciphertext 积己
	unsigned char ciphertext[32 * (d_u * k + d_v)] = { 0 };
	
	//SharedSecretKey_ 积己
	unsigned char SharedSecretKey_[32] = { 0 };

	ML_KEM_KeyGen(ek, dk);
	ML_KEM_Encaps(ek, SharedSecretKey, ciphertext);
	ML_KEM_Decaps(dk, ciphertext, SharedSecretKey_);

	for (int i = 0;i < test_num;i++) {

		//KeyGen test
		start = clock();
		ML_KEM_KeyGen(ek, dk);
		finish = clock();
		duration = (double)(finish - start) / CLOCKS_PER_SEC;
		total_time_GeyGen = total_time_GeyGen + duration;

		//Enc test
		start = clock();
		ML_KEM_Encaps(ek, SharedSecretKey, ciphertext);
		finish = clock();
		duration = (double)(finish - start) / CLOCKS_PER_SEC;
		total_time_Enc = total_time_Enc + duration;

		//Dec test
		start = clock();
		ML_KEM_Decaps(dk, ciphertext, SharedSecretKey_);
		finish = clock();
		duration = (double)(finish - start) / CLOCKS_PER_SEC;
		total_time_Dec = total_time_Dec + duration;
	}

	printf("\n Test number : %d ", test_num);

	mean_time_GeyGen = total_time_GeyGen / test_num;
	printf("\n Total time KeyGen:(%f) sec , Mean time KeyGen:(%f) sec", total_time_GeyGen, mean_time_GeyGen);

	mean_time_Enc = total_time_Enc / test_num;
	printf("\n Total time Enc:(%f) sec, Mean time Enc:(%f) sec", total_time_Enc, mean_time_Enc);

	mean_time_Dec = total_time_Dec / test_num;
	printf("\n Total time Dec:(%f) sec, Mean time Dec:(%f) sec", total_time_Dec, mean_time_Dec);

	return;
}
