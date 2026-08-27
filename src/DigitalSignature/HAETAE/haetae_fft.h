// SPDX-License-Identifier: MIT

#ifndef _HAETAE_FFT_H_
#define _HAETAE_FFT_H_

#include "haetae_poly.h"

#define CRYPTO_HAETAE_FFT_N 256
#define CRYPTO_HAETAE_FFT_LOG_N 8

typedef struct {
    int real;
    int imag;
} crypto_haetae_complex_fp32_16;

int crypto_haetae_complex_fp_sqabs(crypto_haetae_complex_fp32_16 x);
void crypto_haetae_fft(crypto_haetae_complex_fp32_16 data[CRYPTO_HAETAE_FFT_N]);
void crypto_haetae_fft_bitrev(crypto_haetae_complex_fp32_16 r[CRYPTO_HAETAE_FFT_N], const crypto_haetae_poly *x);

#endif /* _HAETAE_FFT_H_ */
