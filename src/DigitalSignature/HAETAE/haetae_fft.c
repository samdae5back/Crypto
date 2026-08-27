// SPDX-License-Identifier: MIT

#include "haetae_fft.h"
#include "Util/Bit/bit_internal.h"

/**************************************************************************
 * Roots of unity. This table is used to initialize the FFT data.
 * The even entries are reused as twiddle factors in the FFT.
 * To generate values in Python using numpy:
 *   rootsf = np.exp(-1j * np.pi * np.arange(256) / 256)
 *   roots = [(int(r.real), int(r.imag)) for r in np.round(65536 * rootsf)]
 **************************************************************************/
static const crypto_haetae_complex_fp32_16 roots[] = {
    {.real = +65536, .imag = +0},     {.real = +65531, .imag = -804},
    {.real = +65516, .imag = -1608},  {.real = +65492, .imag = -2412},
    {.real = +65457, .imag = -3216},  {.real = +65413, .imag = -4019},
    {.real = +65358, .imag = -4821},  {.real = +65294, .imag = -5623},
    {.real = +65220, .imag = -6424},  {.real = +65137, .imag = -7224},
    {.real = +65043, .imag = -8022},  {.real = +64940, .imag = -8820},
    {.real = +64827, .imag = -9616},  {.real = +64704, .imag = -10411},
    {.real = +64571, .imag = -11204}, {.real = +64429, .imag = -11996},
    {.real = +64277, .imag = -12785}, {.real = +64115, .imag = -13573},
    {.real = +63944, .imag = -14359}, {.real = +63763, .imag = -15143},
    {.real = +63572, .imag = -15924}, {.real = +63372, .imag = -16703},
    {.real = +63162, .imag = -17479}, {.real = +62943, .imag = -18253},
    {.real = +62714, .imag = -19024}, {.real = +62476, .imag = -19792},
    {.real = +62228, .imag = -20557}, {.real = +61971, .imag = -21320},
    {.real = +61705, .imag = -22078}, {.real = +61429, .imag = -22834},
    {.real = +61145, .imag = -23586}, {.real = +60851, .imag = -24335},
    {.real = +60547, .imag = -25080}, {.real = +60235, .imag = -25821},
    {.real = +59914, .imag = -26558}, {.real = +59583, .imag = -27291},
    {.real = +59244, .imag = -28020}, {.real = +58896, .imag = -28745},
    {.real = +58538, .imag = -29466}, {.real = +58172, .imag = -30182},
    {.real = +57798, .imag = -30893}, {.real = +57414, .imag = -31600},
    {.real = +57022, .imag = -32303}, {.real = +56621, .imag = -33000},
    {.real = +56212, .imag = -33692}, {.real = +55794, .imag = -34380},
    {.real = +55368, .imag = -35062}, {.real = +54934, .imag = -35738},
    {.real = +54491, .imag = -36410}, {.real = +54040, .imag = -37076},
    {.real = +53581, .imag = -37736}, {.real = +53114, .imag = -38391},
    {.real = +52639, .imag = -39040}, {.real = +52156, .imag = -39683},
    {.real = +51665, .imag = -40320}, {.real = +51166, .imag = -40951},
    {.real = +50660, .imag = -41576}, {.real = +50146, .imag = -42194},
    {.real = +49624, .imag = -42806}, {.real = +49095, .imag = -43412},
    {.real = +48559, .imag = -44011}, {.real = +48015, .imag = -44604},
    {.real = +47464, .imag = -45190}, {.real = +46906, .imag = -45769},
    {.real = +46341, .imag = -46341}, {.real = +45769, .imag = -46906},
    {.real = +45190, .imag = -47464}, {.real = +44604, .imag = -48015},
    {.real = +44011, .imag = -48559}, {.real = +43412, .imag = -49095},
    {.real = +42806, .imag = -49624}, {.real = +42194, .imag = -50146},
    {.real = +41576, .imag = -50660}, {.real = +40951, .imag = -51166},
    {.real = +40320, .imag = -51665}, {.real = +39683, .imag = -52156},
    {.real = +39040, .imag = -52639}, {.real = +38391, .imag = -53114},
    {.real = +37736, .imag = -53581}, {.real = +37076, .imag = -54040},
    {.real = +36410, .imag = -54491}, {.real = +35738, .imag = -54934},
    {.real = +35062, .imag = -55368}, {.real = +34380, .imag = -55794},
    {.real = +33692, .imag = -56212}, {.real = +33000, .imag = -56621},
    {.real = +32303, .imag = -57022}, {.real = +31600, .imag = -57414},
    {.real = +30893, .imag = -57798}, {.real = +30182, .imag = -58172},
    {.real = +29466, .imag = -58538}, {.real = +28745, .imag = -58896},
    {.real = +28020, .imag = -59244}, {.real = +27291, .imag = -59583},
    {.real = +26558, .imag = -59914}, {.real = +25821, .imag = -60235},
    {.real = +25080, .imag = -60547}, {.real = +24335, .imag = -60851},
    {.real = +23586, .imag = -61145}, {.real = +22834, .imag = -61429},
    {.real = +22078, .imag = -61705}, {.real = +21320, .imag = -61971},
    {.real = +20557, .imag = -62228}, {.real = +19792, .imag = -62476},
    {.real = +19024, .imag = -62714}, {.real = +18253, .imag = -62943},
    {.real = +17479, .imag = -63162}, {.real = +16703, .imag = -63372},
    {.real = +15924, .imag = -63572}, {.real = +15143, .imag = -63763},
    {.real = +14359, .imag = -63944}, {.real = +13573, .imag = -64115},
    {.real = +12785, .imag = -64277}, {.real = +11996, .imag = -64429},
    {.real = +11204, .imag = -64571}, {.real = +10411, .imag = -64704},
    {.real = +9616, .imag = -64827},  {.real = +8820, .imag = -64940},
    {.real = +8022, .imag = -65043},  {.real = +7224, .imag = -65137},
    {.real = +6424, .imag = -65220},  {.real = +5623, .imag = -65294},
    {.real = +4821, .imag = -65358},  {.real = +4019, .imag = -65413},
    {.real = +3216, .imag = -65457},  {.real = +2412, .imag = -65492},
    {.real = +1608, .imag = -65516},  {.real = +804, .imag = -65531},
    {.real = +0, .imag = -65536},     {.real = -804, .imag = -65531},
    {.real = -1608, .imag = -65516},  {.real = -2412, .imag = -65492},
    {.real = -3216, .imag = -65457},  {.real = -4019, .imag = -65413},
    {.real = -4821, .imag = -65358},  {.real = -5623, .imag = -65294},
    {.real = -6424, .imag = -65220},  {.real = -7224, .imag = -65137},
    {.real = -8022, .imag = -65043},  {.real = -8820, .imag = -64940},
    {.real = -9616, .imag = -64827},  {.real = -10411, .imag = -64704},
    {.real = -11204, .imag = -64571}, {.real = -11996, .imag = -64429},
    {.real = -12785, .imag = -64277}, {.real = -13573, .imag = -64115},
    {.real = -14359, .imag = -63944}, {.real = -15143, .imag = -63763},
    {.real = -15924, .imag = -63572}, {.real = -16703, .imag = -63372},
    {.real = -17479, .imag = -63162}, {.real = -18253, .imag = -62943},
    {.real = -19024, .imag = -62714}, {.real = -19792, .imag = -62476},
    {.real = -20557, .imag = -62228}, {.real = -21320, .imag = -61971},
    {.real = -22078, .imag = -61705}, {.real = -22834, .imag = -61429},
    {.real = -23586, .imag = -61145}, {.real = -24335, .imag = -60851},
    {.real = -25080, .imag = -60547}, {.real = -25821, .imag = -60235},
    {.real = -26558, .imag = -59914}, {.real = -27291, .imag = -59583},
    {.real = -28020, .imag = -59244}, {.real = -28745, .imag = -58896},
    {.real = -29466, .imag = -58538}, {.real = -30182, .imag = -58172},
    {.real = -30893, .imag = -57798}, {.real = -31600, .imag = -57414},
    {.real = -32303, .imag = -57022}, {.real = -33000, .imag = -56621},
    {.real = -33692, .imag = -56212}, {.real = -34380, .imag = -55794},
    {.real = -35062, .imag = -55368}, {.real = -35738, .imag = -54934},
    {.real = -36410, .imag = -54491}, {.real = -37076, .imag = -54040},
    {.real = -37736, .imag = -53581}, {.real = -38391, .imag = -53114},
    {.real = -39040, .imag = -52639}, {.real = -39683, .imag = -52156},
    {.real = -40320, .imag = -51665}, {.real = -40951, .imag = -51166},
    {.real = -41576, .imag = -50660}, {.real = -42194, .imag = -50146},
    {.real = -42806, .imag = -49624}, {.real = -43412, .imag = -49095},
    {.real = -44011, .imag = -48559}, {.real = -44604, .imag = -48015},
    {.real = -45190, .imag = -47464}, {.real = -45769, .imag = -46906},
    {.real = -46341, .imag = -46341}, {.real = -46906, .imag = -45769},
    {.real = -47464, .imag = -45190}, {.real = -48015, .imag = -44604},
    {.real = -48559, .imag = -44011}, {.real = -49095, .imag = -43412},
    {.real = -49624, .imag = -42806}, {.real = -50146, .imag = -42194},
    {.real = -50660, .imag = -41576}, {.real = -51166, .imag = -40951},
    {.real = -51665, .imag = -40320}, {.real = -52156, .imag = -39683},
    {.real = -52639, .imag = -39040}, {.real = -53114, .imag = -38391},
    {.real = -53581, .imag = -37736}, {.real = -54040, .imag = -37076},
    {.real = -54491, .imag = -36410}, {.real = -54934, .imag = -35738},
    {.real = -55368, .imag = -35062}, {.real = -55794, .imag = -34380},
    {.real = -56212, .imag = -33692}, {.real = -56621, .imag = -33000},
    {.real = -57022, .imag = -32303}, {.real = -57414, .imag = -31600},
    {.real = -57798, .imag = -30893}, {.real = -58172, .imag = -30182},
    {.real = -58538, .imag = -29466}, {.real = -58896, .imag = -28745},
    {.real = -59244, .imag = -28020}, {.real = -59583, .imag = -27291},
    {.real = -59914, .imag = -26558}, {.real = -60235, .imag = -25821},
    {.real = -60547, .imag = -25080}, {.real = -60851, .imag = -24335},
    {.real = -61145, .imag = -23586}, {.real = -61429, .imag = -22834},
    {.real = -61705, .imag = -22078}, {.real = -61971, .imag = -21320},
    {.real = -62228, .imag = -20557}, {.real = -62476, .imag = -19792},
    {.real = -62714, .imag = -19024}, {.real = -62943, .imag = -18253},
    {.real = -63162, .imag = -17479}, {.real = -63372, .imag = -16703},
    {.real = -63572, .imag = -15924}, {.real = -63763, .imag = -15143},
    {.real = -63944, .imag = -14359}, {.real = -64115, .imag = -13573},
    {.real = -64277, .imag = -12785}, {.real = -64429, .imag = -11996},
    {.real = -64571, .imag = -11204}, {.real = -64704, .imag = -10411},
    {.real = -64827, .imag = -9616},  {.real = -64940, .imag = -8820},
    {.real = -65043, .imag = -8022},  {.real = -65137, .imag = -7224},
    {.real = -65220, .imag = -6424},  {.real = -65294, .imag = -5623},
    {.real = -65358, .imag = -4821},  {.real = -65413, .imag = -4019},
    {.real = -65457, .imag = -3216},  {.real = -65492, .imag = -2412},
    {.real = -65516, .imag = -1608},  {.real = -65531, .imag = -804}};

/*
 * Fixed-point range proof for the FFT used by HAETAE key generation.
 *
 * Only secret-key polynomials reach this FFT. CRYPTO_HAETAE_ETA is 1, so s1
 * has |c| <= 1. For d == 0, s2 also has |c| <= 1. For d == 1, key generation
 * replaces s2 by s2 - b0; crypto_haetae_decompose_vk produces b0 in
 * {-1, 0, 1}, hence |s2| <= 2. We therefore use |c| <= 2 for every mode.
 *
 * The root table is Q16 with every real/imaginary component bounded by 2^16.
 * After fft_bitrev, every stored component is bounded by
 *   B0 = 2 * 2^16 = 131072.
 *
 * Suppose one radix-2 stage starts with component bound B. The Q16 scalar
 * product is floor((x*y + 2^15)/2^16). Since |y| <= 2^16, its rounded result
 * remains in [-B, B]. A complex-product component is a sum/difference of two
 * such products and is therefore bounded by 2B. The butterfly computes
 * u +/- t, giving the deliberately conservative recurrence B_next <= 3B.
 * Eight stages give
 *   B8 <= 3^8 * B0 = 6561 * 131072 = 859963392 < INT32_MAX.
 *
 * Therefore FFT real/imaginary storage is safely int32_t. Q16 products and
 * butterfly expressions are evaluated in int64_t so the C expressions cannot
 * overflow before the proven int32_t storage boundary. Squared magnitudes use
 * uint64_t because their conservative bound does not fit int32_t.
 */
_Static_assert(CRYPTO_HAETAE_ETA == 1,
               "HAETAE FFT input proof assumes ETA = 1");
_Static_assert(CRYPTO_HAETAE_MAX_D <= 1u,
               "HAETAE FFT input proof assumes d <= 1");
_Static_assert(CRYPTO_HAETAE_FFT_N == 256u,
               "HAETAE FFT proof assumes a 256-point transform");
_Static_assert(CRYPTO_HAETAE_FFT_LOG_N == 8u,
               "HAETAE FFT proof assumes eight radix-2 stages");
_Static_assert(CRYPTO_HAETAE_FFT_COMPONENT_BOUND ==
                   UINT64_C(131072) * UINT64_C(6561),
               "HAETAE FFT component bound must equal 3^8 * B0");
_Static_assert(CRYPTO_HAETAE_FFT_COMPONENT_BOUND <= INT32_MAX,
               "HAETAE FFT components must fit int32_t");
_Static_assert(
    CRYPTO_HAETAE_FFT_COMPONENT_BOUND <=
        (uint64_t)(INT64_MAX - INT64_C(32768)) /
            CRYPTO_HAETAE_FFT_COMPONENT_BOUND,
    "HAETAE FFT component square plus Q16 rounding must fit int64_t");
_Static_assert(
    CRYPTO_HAETAE_FFT_SQABS_BOUND ==
        UINT64_C(2) *
            ((CRYPTO_HAETAE_FFT_COMPONENT_BOUND *
                  CRYPTO_HAETAE_FFT_COMPONENT_BOUND + UINT64_C(32768)) /
             UINT64_C(65536)),
    "HAETAE FFT squared-magnitude bound must match Q16 rounding");

/*
 * Return floor((x*y + 2^15) / 2^16) without right-shifting a negative signed
 * value. Keeping this result in int64_t is part of the range proof above.
 */
static inline int64_t crypto_haetae_q16_mul_wide(
    int32_t x, int32_t y) {
  const int64_t product =
      (int64_t)x * (int64_t)y + INT64_C(32768);
  return crypto_floor_div_pow2_i64(product, 16u);
}

static inline int32_t crypto_haetae_complex_mul_real(
    crypto_haetae_complex_fp32_16 x,
    crypto_haetae_complex_fp32_16 y) {
  const int64_t value =
      crypto_haetae_q16_mul_wide(x.real, y.real) -
      crypto_haetae_q16_mul_wide(x.imag, y.imag);

  /* The stage proof bounds each complex-product component by 2B. */
  return (int32_t)value;
}

static inline int32_t crypto_haetae_complex_mul_imag(
    crypto_haetae_complex_fp32_16 x,
    crypto_haetae_complex_fp32_16 y) {
  const int64_t value =
      crypto_haetae_q16_mul_wide(x.real, y.imag) +
      crypto_haetae_q16_mul_wide(x.imag, y.real);

  /* The stage proof bounds each complex-product component by 2B. */
  return (int32_t)value;
}

static void crypto_haetae_complex_mul(
    crypto_haetae_complex_fp32_16 *r,
    crypto_haetae_complex_fp32_16 x,
    crypto_haetae_complex_fp32_16 y) {
  r->real = crypto_haetae_complex_mul_real(x, y);
  r->imag = crypto_haetae_complex_mul_imag(x, y);
}

/****************************************************************************
 * To generate values in Phython:
 *   brv8 = [int(f"{t:08b}"[::-1],2) for t in range(2**8)]
 ****************************************************************************/
static const uint16_t brv8[] = {
    0,  128, 64, 192, 32, 160, 96,  224, 16, 144, 80, 208, 48, 176, 112, 240,
    8,  136, 72, 200, 40, 168, 104, 232, 24, 152, 88, 216, 56, 184, 120, 248,
    4,  132, 68, 196, 36, 164, 100, 228, 20, 148, 84, 212, 52, 180, 116, 244,
    12, 140, 76, 204, 44, 172, 108, 236, 28, 156, 92, 220, 60, 188, 124, 252,
    2,  130, 66, 194, 34, 162, 98,  226, 18, 146, 82, 210, 50, 178, 114, 242,
    10, 138, 74, 202, 42, 170, 106, 234, 26, 154, 90, 218, 58, 186, 122, 250,
    6,  134, 70, 198, 38, 166, 102, 230, 22, 150, 86, 214, 54, 182, 118, 246,
    14, 142, 78, 206, 46, 174, 110, 238, 30, 158, 94, 222, 62, 190, 126, 254,
    1,  129, 65, 193, 33, 161, 97,  225, 17, 145, 81, 209, 49, 177, 113, 241,
    9,  137, 73, 201, 41, 169, 105, 233, 25, 153, 89, 217, 57, 185, 121, 249,
    5,  133, 69, 197, 37, 165, 101, 229, 21, 149, 85, 213, 53, 181, 117, 245,
    13, 141, 77, 205, 45, 173, 109, 237, 29, 157, 93, 221, 61, 189, 125, 253,
    3,  131, 67, 195, 35, 163, 99,  227, 19, 147, 83, 211, 51, 179, 115, 243,
    11, 139, 75, 203, 43, 171, 107, 235, 27, 155, 91, 219, 59, 187, 123, 251,
    7,  135, 71, 199, 39, 167, 103, 231, 23, 151, 87, 215, 55, 183, 119, 247,
    15, 143, 79, 207, 47, 175, 111, 239, 31, 159, 95, 223, 63, 191, 127, 255};

/****************************************************************************
 * Initialize the FFT array with coeffs[i] * root[i] and
 * store the values in bit-reversed order.
 ****************************************************************************/
void crypto_haetae_fft_bitrev(
    crypto_haetae_complex_fp32_16 r[CRYPTO_HAETAE_FFT_N],
    const crypto_haetae_poly *x) {
  uint32_t i;

  for (i = 0u; i < CRYPTO_HAETAE_FFT_N; i++) {
    const uint16_t inv_i = brv8[i];
    const int32_t coefficient = x->coeffs[i];
    const int64_t real =
        (int64_t)coefficient * (int64_t)roots[i].real;
    const int64_t imag =
        (int64_t)coefficient * (int64_t)roots[i].imag;

    /* |coefficient| <= 2 gives |real|, |imag| <= B0 = 131072. */
    r[inv_i].real = (int32_t)real;
    r[inv_i].imag = (int32_t)imag;
  }
}

uint64_t crypto_haetae_complex_fp_sqabs(
    crypto_haetae_complex_fp32_16 x) {
  const int64_t real_squared =
      crypto_haetae_q16_mul_wide(x.real, x.real);
  const int64_t imag_squared =
      crypto_haetae_q16_mul_wide(x.imag, x.imag);

  return (uint64_t)real_squared + (uint64_t)imag_squared;
}

/*************************************************
 * Name:        crypto_haetae_fft
 *
 * Description:
 *
 * Arguments:   - crypto_haetae_complex_fp32_16 data[FFT_N]
 *
 * Specification: Implements @[KS X 123456, Algorithm 43, FFT]
 **************************************************/
void crypto_haetae_fft(
    crypto_haetae_complex_fp32_16 data[CRYPTO_HAETAE_FFT_N]) {
  uint32_t stage;
  crypto_haetae_complex_fp32_16 u, t;

  for (stage = 1u; stage <= CRYPTO_HAETAE_FFT_LOG_N; stage++) {
    const uint32_t m = UINT32_C(1) << stage;
    const uint32_t half_m = m >> 1;
    uint32_t block;

    for (block = 0u; block < CRYPTO_HAETAE_FFT_N; block += m) {
      uint32_t k;
      for (k = 0u; k < half_m; k++) {
        const uint32_t even = block + k;
        const uint32_t odd = even + half_m;
        const uint32_t twiddle =
            k << (CRYPTO_HAETAE_FFT_LOG_N - stage + 1u);
        int64_t even_real;
        int64_t even_imag;
        int64_t odd_real;
        int64_t odd_imag;

        u = data[even];
        crypto_haetae_complex_mul(&t, roots[twiddle], data[odd]);

        /* Evaluate the butterfly wide before the proven int32_t store. */
        even_real = (int64_t)u.real + (int64_t)t.real;
        even_imag = (int64_t)u.imag + (int64_t)t.imag;
        odd_real = (int64_t)u.real - (int64_t)t.real;
        odd_imag = (int64_t)u.imag - (int64_t)t.imag;

        data[even].real = (int32_t)even_real;
        data[even].imag = (int32_t)even_imag;
        data[odd].real = (int32_t)odd_real;
        data[odd].imag = (int32_t)odd_imag;
      }
    }
  }
}
