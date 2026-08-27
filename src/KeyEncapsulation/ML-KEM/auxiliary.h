#ifndef ML_KEM_AUXILIARY_H
#define ML_KEM_AUXILIARY_H

#include <stddef.h>

int ByteEncode(const int *input, size_t bit_width, unsigned char *output);
int ByteDecode(const unsigned char *input, size_t bit_width, int *output);
int SampleNTT(const unsigned char *input, int *output, size_t input_length);
int SamplePolyCBD(const unsigned char *input, int *output,
                  size_t input_length);
int Comp(const int *input, int bit_width, int *output, size_t length);
int Decomp(const int *input, int bit_width, int *output, size_t length);

#endif
