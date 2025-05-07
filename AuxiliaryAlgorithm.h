#pragma once

int exp(int x, int exp);

void Bit2Byte(unsigned char* b, unsigned char* B, size_t output_length);

void Byte2Bit(unsigned char* B, unsigned char* b, size_t input_length);

void ByteEncode(int* F, size_t d, unsigned char* output);

void ByteDecode(unsigned char* B, size_t d, int* output);

void SampleNTT(unsigned char* B, int* a, size_t input_length);

void SamplePolyCBD(unsigned char* B, int* f, size_t input_length);