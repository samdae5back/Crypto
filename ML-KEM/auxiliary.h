#ifndef AUXILIARY_H
#define AUXILIARY_H

int exp_int(int x, int exp);

void Bit2Byte(unsigned char* b, unsigned char* B, size_t output_length);

void Byte2Bit(unsigned char* B, unsigned char* b, size_t input_length);

void ByteEncode(int* F, size_t d, unsigned char* output);

void ByteDecode(unsigned char* B, size_t d, int* output);

void SampleNTT(unsigned char* B, int* a, size_t input_length);

void SamplePolyCBD(unsigned char* B, int* f, size_t input_length);

void Comp(int* input, int d, int* output, size_t inout_length);

void Decomp(int* input, int d, int* output, size_t inout_length);

#endif // AUXILIARY_H