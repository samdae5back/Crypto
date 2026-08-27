// SPDX-License-Identifier: MIT

#ifndef _HAETAE_FFT_H_
#define _HAETAE_FFT_H_

#include "haetae_poly.h"

#define CRYPTO_HAETAE_FFT_N 256u
#define CRYPTO_HAETAE_FFT_LOG_N 8u

/*
 * Conservative fixed-point bounds for the key-generation FFT.
 * See haetae_fft.c for the derivation. The singular-value accumulator
 * reuses these constants so its width proof stays compile-time checked.
 */
#define CRYPTO_HAETAE_FFT_COMPONENT_BOUND UINT64_C(859963392)
#define CRYPTO_HAETAE_FFT_SQABS_BOUND UINT64_C(22568879259648)

typedef struct {
    int32_t real;
    int32_t imag;
} crypto_haetae_complex_fp32_16;

uint64_t crypto_haetae_complex_fp_sqabs(
    crypto_haetae_complex_fp32_16 x);
void crypto_haetae_fft(crypto_haetae_complex_fp32_16 data[CRYPTO_HAETAE_FFT_N]);
void crypto_haetae_fft_bitrev(crypto_haetae_complex_fp32_16 r[CRYPTO_HAETAE_FFT_N], const crypto_haetae_poly *x);

#endif /* _HAETAE_FFT_H_ */
