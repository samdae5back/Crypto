from pathlib import Path


def read(path):
    return Path(path).read_text(encoding="utf-8")


def write(path, text):
    Path(path).write_text(text, encoding="utf-8")


def replace_exact(text, old, new, expected=1):
    count = text.count(old)
    if count != expected:
        raise RuntimeError(
            f"expected {expected} occurrence(s), found {count}: {old!r}")
    return text.replace(old, new)


# FFT interface: fixed-width representation plus shared conservative bounds.
path = "src/DigitalSignature/HAETAE/haetae_fft.h"
text = read(path)
text = replace_exact(
    text,
    "#define CRYPTO_HAETAE_FFT_N 256\n#define CRYPTO_HAETAE_FFT_LOG_N 8\n\n"
    "typedef struct {\n    int real;\n    int imag;\n} crypto_haetae_complex_fp32_16;\n\n"
    "int crypto_haetae_complex_fp_sqabs(crypto_haetae_complex_fp32_16 x);",
    "#define CRYPTO_HAETAE_FFT_N 256u\n#define CRYPTO_HAETAE_FFT_LOG_N 8u\n\n"
    "/*\n"
    " * Conservative fixed-point bounds for the key-generation FFT.\n"
    " * See haetae_fft.c for the derivation. The singular-value accumulator\n"
    " * reuses these constants so its width proof stays compile-time checked.\n"
    " */\n"
    "#define CRYPTO_HAETAE_FFT_COMPONENT_BOUND UINT64_C(859963392)\n"
    "#define CRYPTO_HAETAE_FFT_SQABS_BOUND UINT64_C(22568879259648)\n\n"
    "typedef struct {\n    int32_t real;\n    int32_t imag;\n} crypto_haetae_complex_fp32_16;\n\n"
    "uint64_t crypto_haetae_complex_fp_sqabs(\n"
    "    crypto_haetae_complex_fp32_16 x);",
)
write(path, text)


# FFT arithmetic. Keep the root and bit-reversal tables unchanged.
path = "src/DigitalSignature/HAETAE/haetae_fft.c"
text = read(path)
text = replace_exact(
    text,
    '#include "haetae_fft.h"\n',
    '#include "haetae_fft.h"\n#include "Util/Bit/bit_internal.h"\n',
)

helper_start = text.index("static inline int32_t _mulrnd16")
helper_end = text.index(
    "/****************************************************************************\n * To generate values in Phython:",
    helper_start,
)
helpers = r'''/*
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

'''
text = text[:helper_start] + helpers + text[helper_end:]

old = r'''void crypto_haetae_fft_bitrev(crypto_haetae_complex_fp32_16 r[CRYPTO_HAETAE_FFT_N], const crypto_haetae_poly *x) {
  int i, inv_i;
  int c;
  for (i = 0; i < CRYPTO_HAETAE_FFT_N; i++) {
    inv_i = brv8[i];
    c = x->coeffs[i];
    r[inv_i].real = c * roots[i].real;
    r[inv_i].imag = c * roots[i].imag;
  }
}

int32_t crypto_haetae_complex_fp_sqabs(crypto_haetae_complex_fp32_16 x) {
  return _mulrnd16(x.real, x.real) + _mulrnd16(x.imag, x.imag);
}
'''
new = r'''void crypto_haetae_fft_bitrev(
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
'''
text = replace_exact(text, old, new)

old = r'''void crypto_haetae_fft(crypto_haetae_complex_fp32_16 data[CRYPTO_HAETAE_FFT_N]) {
  unsigned int r, m, md2, n, k, even, odd, twid;
  crypto_haetae_complex_fp32_16 u, t;

  for (r = 1; r <= CRYPTO_HAETAE_FFT_LOG_N; r++) {
    m = 1 << r;
    md2 = m >> 1;
    for (n = 0; n < CRYPTO_HAETAE_FFT_N; n += m) {
      for (k = 0; k < md2; k++) {
        even = n + k;
        odd = even + md2;
        twid = k << (CRYPTO_HAETAE_FFT_LOG_N - r + 1);

        u = data[even];
        _complex_mul(&t, roots[twid], data[odd]);
        data[even].real = u.real + t.real;
        data[even].imag = u.imag + t.imag;
        data[odd].real = u.real - t.real;
        data[odd].imag = u.imag - t.imag;
      }
    }
  }
}'''
new = r'''void crypto_haetae_fft(
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
}'''
text = replace_exact(text, old, new)
write(path, text)


# Singular-value function signature.
path = "src/DigitalSignature/HAETAE/haetae_polyvec.h"
text = read(path)
text = replace_exact(
    text,
    "long long crypto_haetae_polyvecmk_sqsing_value(const crypto_haetae_polyvecm *s1, const crypto_haetae_polyveck *s2, const crypto_haetae_parameters *parameters);",
    "uint64_t crypto_haetae_polyvecmk_sqsing_value(\n"
    "    const crypto_haetae_polyvecm *s1,\n"
    "    const crypto_haetae_polyveck *s2,\n"
    "    const crypto_haetae_parameters *parameters);",
)
write(path, text)


# Singular-value accumulation and sorting: non-negative uint64_t end-to-end.
path = "src/DigitalSignature/HAETAE/haetae_polyvec.c"
text = read(path)
start = text.index("static void minmax(int* x, int* y)")
end = text.index(
    "/*************************************************\n * Name:        crypto_haetae_polyvecmk_uniform_eta",
    start,
)
replacement = r'''#define CRYPTO_HAETAE_FFT_SECRET_POLY_COUNT_MAX \
    (CRYPTO_HAETAE_MAX_M + CRYPTO_HAETAE_MAX_K)
#define CRYPTO_HAETAE_FFT_SUM_BOUND \
    (CRYPTO_HAETAE_FFT_SQABS_BOUND * \
     CRYPTO_HAETAE_FFT_SECRET_POLY_COUNT_MAX)
#define CRYPTO_HAETAE_FFT_BESTM_COUNT_MAX \
    (CRYPTO_HAETAE_N / CRYPTO_HAETAE_MIN_TAU + 1u)
#define CRYPTO_HAETAE_FFT_RESULT_ACC_BOUND \
    (CRYPTO_HAETAE_FFT_BESTM_COUNT_MAX * \
     (((CRYPTO_HAETAE_FFT_SUM_BOUND + UINT64_C(0x10200)) >> 10) * \
      CRYPTO_HAETAE_N))

_Static_assert(CRYPTO_HAETAE_FFT_SUM_BOUND < (UINT64_C(1) << 63),
               "HAETAE FFT norm sums must remain below 2^63");
_Static_assert(CRYPTO_HAETAE_FFT_RESULT_ACC_BOUND < (UINT64_C(1) << 63),
               "HAETAE singular-value accumulator must remain below 2^63");
_Static_assert(BESTM_MAX_SIZE == CRYPTO_HAETAE_FFT_BESTM_COUNT_MAX,
               "HAETAE best-m storage must match the range proof");

/*
 * Constant-time compare-and-swap for values proven below 2^63.
 * For a,b < 2^63, the high bit of unsigned b-a is set exactly when b < a.
 */
static void crypto_haetae_minmax_u64(uint64_t *x, uint64_t *y) {
    const uint64_t a = *x;
    const uint64_t b = *y;
    const uint64_t swap_mask = UINT64_C(0) - ((b - a) >> 63);
    const uint64_t delta = (a ^ b) & swap_mask;

    *x = a ^ delta;
    *y = b ^ delta;
}

uint64_t crypto_haetae_polyvecmk_sqsing_value(
    const crypto_haetae_polyvecm *s1,
    const crypto_haetae_polyveck *s2,
    const crypto_haetae_parameters *parameters) {
    uint64_t result = 0u;
    crypto_haetae_complex_fp32_16 input[CRYPTO_HAETAE_FFT_N] = {{0, 0}};
    uint64_t sum[CRYPTO_HAETAE_N] = {0};
    uint64_t bestm[BESTM_MAX_SIZE] = {0};
    uint64_t minimum;
    size_t i, j;
    const uint32_t haetae_k = parameters->k;
    const uint32_t haetae_m = parameters->l - 1u;
    const uint32_t haetae_tau = parameters->tau;
    const size_t bestm_size = CRYPTO_HAETAE_N / haetae_tau + 1u;

    for (i = 0u; i < haetae_m; ++i) {
        crypto_haetae_fft_bitrev(input, &s1->vec[i]);
        crypto_haetae_fft(input);
        for (j = 0u; j < CRYPTO_HAETAE_N; j++) {
            sum[j] += crypto_haetae_complex_fp_sqabs(input[j]);
        }
    }

    for (i = 0u; i < haetae_k; ++i) {
        crypto_haetae_fft_bitrev(input, &s2->vec[i]);
        crypto_haetae_fft(input);
        for (j = 0u; j < CRYPTO_HAETAE_N; j++) {
            sum[j] += crypto_haetae_complex_fp_sqabs(input[j]);
        }
    }

    for (i = 0u; i < bestm_size; ++i) {
        bestm[i] = sum[i];
    }
    for (i = bestm_size; i < CRYPTO_HAETAE_N; i++) {
        for (j = 0u; j < bestm_size; j++) {
            crypto_haetae_minmax_u64(&sum[i], &bestm[j]);
        }
    }

    minimum = bestm[0];
    for (i = 1u; i < bestm_size; i++) {
        uint64_t candidate = bestm[i];
        crypto_haetae_minmax_u64(&minimum, &candidate);
    }

    for (i = 0u; i < bestm_size; i++) {
        const uint64_t difference = bestm[i] - minimum;
        const uint64_t nonzero =
            (difference | (UINT64_C(0) - difference)) >> 63;
        const uint64_t different_mask = UINT64_C(0) - nonzero;
        const uint64_t factor =
            (different_mask & (uint64_t)haetae_tau) |
            (~different_mask &
             (uint64_t)(CRYPTO_HAETAE_N % haetae_tau));

        bestm[i] += UINT64_C(0x10200);
        bestm[i] >>= 10;
        bestm[i] *= factor;
        result += bestm[i];
    }

    /* Preserve the specification's final round-to-nearest by 2^6. */
    return (result + UINT64_C(32)) >> 6;
}

'''
text = text[:start] + replacement + text[end:]
write(path, text)


# Key-generation caller: the squared singular value is non-negative.
path = "src/DigitalSignature/HAETAE/haetae.c"
text = read(path)
text = replace_exact(
    text,
    "    long long squared_singular_value;",
    "    uint64_t squared_singular_value;",
)
write(path, text)


# Sanity guards against reintroducing the old width-sensitive forms.
fft = read("src/DigitalSignature/HAETAE/haetae_fft.c")
for bad in ["_mulrnd16", "return r >> 16"]:
    if bad in fft:
        raise RuntimeError(f"old FFT form remains: {bad}")
polyvec = read("src/DigitalSignature/HAETAE/haetae_polyvec.c")
for bad in [
    "static void minmax(int*",
    "int sum[CRYPTO_HAETAE_N]",
    "int bestm[BESTM_MAX_SIZE]",
    "UINT64_C(1 << 5)",
]:
    if bad in polyvec:
        raise RuntimeError(f"old singular-value form remains: {bad}")
