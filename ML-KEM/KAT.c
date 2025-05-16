#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "NTT_.h"
#include "hash.h"
#include "auxiliary.h"
#include "K-PKE.h"
#include "ML-KEM.h"
#include "parameter.h"

int ScanKAT(FILE* fip) {//scan a file and run Known Answer Test
	unsigned char* read_buffer = (unsigned char*)malloc(sizeof(unsigned char) * 4096);
	if (read_buffer == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}
	unsigned int tt = 0;

	//d �б�
	unsigned char d[32] = { 0 };
	if (fscanf(fip, "d = ") == EOF) {
		printf("End of File");
		return -1;
	}
	for (int i = 0;i < 32;i++) {
		if (fscanf(fip, "%02x", &tt) != 1) {
			perror("File scan failed");
			return 1;
		}
		read_buffer[i] = tt;
	}
	if (fscanf(fip, "\n") == EOF) {
		printf("End of File");
		return -1;
	}
	memcpy(d, read_buffer, 32);

	//z �б�
	unsigned char z[32] = { 0 };
	if (fscanf(fip, "z = ") == EOF) {
		printf("End of File");
		return -1;
	}
	for (int i = 0;i < 32;i++) {
		if (fscanf(fip, "%02x", &tt) != 1) {
			perror("File scan failed");
			return 1;
		}
		read_buffer[i] = tt;
	}
	if (fscanf(fip, "\n") == EOF) {
		printf("End of File");
		return -1;
	}
	memcpy(z, read_buffer, 32);

	//pk �б�
	unsigned char* pk = (unsigned char*)malloc(sizeof(unsigned char) * (384 * k + 32));
	if (pk == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}
	if (fscanf(fip, "pk = ") == EOF) {
		printf("End of File");
		return -1;
	}
	for (int i = 0;i < 384 * k + 32;i++) {
		if (fscanf(fip, "%02x", &tt) != 1) {
			perror("File scan failed");
			return 1;
		}
		read_buffer[i] = tt;
	}
	if (fscanf(fip, "\n") == EOF) {
		printf("End of File");
		return -1;
	}
	memcpy(pk, read_buffer, 384 * k + 32);
	
	//sk �б�
	unsigned char* sk = (unsigned char*)malloc(sizeof(unsigned char) * (768 * k + 96));
	if (sk == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}
	if (fscanf(fip, "sk = ") == EOF) {
		printf("End of File");
		return -1;
	}
	for (int i = 0;i < 768 * k + 96;i++) {
		if (fscanf(fip, "%02x", &tt) != 1) {
			perror("File scan failed");
			return 1;
		}
		read_buffer[i] = tt;
	}
	if (fscanf(fip, "\n") == EOF) {
		printf("End of File");
		return -1;
	}
	memcpy(sk, read_buffer, 768 * k + 96);
	
	//m �б�
	unsigned char m[32] = { 0 };
	if (fscanf(fip, "m = ") == EOF) {
		printf("End of File");
		return -1;
	}
	for (int i = 0;i < 32;i++) {
		if (fscanf(fip, "%02x", &tt) != 1) {
			perror("File scan failed");
			return 1;
		}
		read_buffer[i] = tt;
	}
	if (fscanf(fip, "\n") == EOF) {
		printf("End of File");
		return -1;
	}
	for (int i = 0;i < 32;i++) {
		m[i] = read_buffer[i];
	}
	memcpy(m, read_buffer, 32);

	//ct �б�
	unsigned char ct[32 * (d_u * k + d_v)] = { 0 };
	if (fscanf(fip, "ct = ") == EOF) {
		printf("End of File");
		return -1;
	}
	for (int i = 0;i < 32 * (d_u * k + d_v);i++) {
		if (fscanf(fip, "%02x", &tt) != 1) {
			perror("File scan failed");
			return 1;
		}
		read_buffer[i] = tt;
	}
	if (fscanf(fip, "\n") == EOF) {
		printf("End of File");
		return -1;
	}
	memcpy(ct, read_buffer, 32 * (d_u * k + d_v));
	
	//ss �б�
	unsigned char ss[32] = { 0 };
	if (fscanf(fip, "ss = ") == EOF) {
		printf("End of File");
		return -1;
	}
	for (int i = 0;i < 32;i++) {
		if (fscanf(fip, "%02x", &tt) != 1) {
			perror("File scan failed");
			return 1;
		}
		read_buffer[i] = tt;
	}
	if (fscanf(fip, "\n") == EOF) {
		printf("End of File");
		return -1;
	}
	memcpy(ss, read_buffer, 32);
	
	free(read_buffer);


	//ek, dk ����
	unsigned char* pk_ = (unsigned char*)malloc(sizeof(unsigned char) * (384 * k + 32));
	if (pk_ == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}
	unsigned char* sk_ = (unsigned char*)malloc(sizeof(unsigned char) * (786 * k + 96));
	if (sk_ == NULL) {
		perror("Failed to allocate memory"); // ���� �޽��� ���
		exit(EXIT_FAILURE);// �޸� �Ҵ� ���� �� �� �̻� ���� �Ұ�, ���α׷� ���� �Ǵ� ���� ó��
	}

	//SharedSecretKey ����
	unsigned char ss_[32] = { 0 };

	//ciphertext ����
	unsigned char ct_[32 * (d_u * k + d_v)] = { 0 };

	//SharedSecretKey_ ����
	unsigned char ss__[32] = { 0 };

	//��
	ML_KEM_KeyGen_internal(d, z, pk_, sk_);
	ML_KEM_Encaps_internal(pk_, m, ss_, ct_);
	ML_KEM_Decaps_internal(sk_, ct_, ss__);
	
	int err = 0;
	int t_err = 0;
	for (int i = 0;i < 384 * k + 32;i++) {
		if (pk[i] != pk_[i]) {
			err++;
		}
	}
	if (err - t_err > 0) {
		printf("Encryption key does not fit at %d point\n", err - t_err);
	}
	t_err = err;
	for (int i = 0;i < 768 * k + 96;i++) {
		if (sk[i] != sk_[i]) {
			err++;
		}
	}
	if (err - t_err > 0) {
		printf("Decryption key does not fit at %d point\n", err - t_err);
	}
	t_err = err;
	for (int i = 0;i < 32 * (d_u * k + d_v);i++) {
		if (ct[i] != ct_[i]) {
			err++;
		}
	}
	if (err - t_err > 0) {
		printf("Ciphertext does not fit at %d point\n", err - t_err);
	}
	t_err = err;
	for (int i = 0;i < 32;i++) {
		if (ss[i] != ss_[i] || ss[i] != ss__[i]) {
			err++;
		}
	}
	if (err - t_err > 0) {
		printf("Shared secret key does not fit at %d point\n", err - t_err);
	}
	if (err > 0) {
		printf("KAT test failed; error : %d\n",err);
		return 1;
	}

	printf("KAT test succeed\n");

	free(pk);
	free(sk);
	free(pk_);
	free(sk_);

	return 0;

}

/*
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
	
	for (i = 0; ; i++) { // ���� ����ó�� �������� ���ο��� break
		printf("Test vector (%d) \n", i);
		state = ScanKAT(fip);
		printf("\n");

		if (state == -1) { // EOF �Ǵ� �ɰ��� ������ �� �̻� ���� �Ұ�
			break;
		}
		else if (state == 0) {
			s++;
		}
		else if (state == 1) {
			f++;
		}
	}

	printf("\n Result\n Success:(%d), Fail:(%d) ", s,f);
	fclose(fip);
	return 0;
}
*/