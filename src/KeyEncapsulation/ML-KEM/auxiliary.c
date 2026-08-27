#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hash.h"
#include "NTT_.h"
#include "auxiliary.h"
#include "parameter.h"

int exp_int(int x, int exp) {
    int r = 1;
    while (exp > 0) {
        if (exp % 2 == 1) {
            r = r * x;
        }
        x = x * x;
        exp /= 2;
    }
    return r;
}

void Bit2Byte(unsigned char *b, unsigned char *B, size_t output_length) {
    if (B == NULL) {
        perror("Bit2Byte Failed");
        exit(EXIT_FAILURE);
    }
    memset(B, 0, sizeof(unsigned char) * output_length);
    for (size_t i = 0u; i < 8u * output_length; i++) {
        B[i / 8u] |= (unsigned char)((b[i] & 1u) << (i % 8u));
    }
}

void Byte2Bit(unsigned char *B, unsigned char *b, size_t input_length) {
    if (B == NULL) {
        perror("Byte2Bit Failed");
        exit(EXIT_FAILURE);
    }
    for (int i = 0; i < (int)input_length; i++) {
        unsigned char t = B[i];
        for (int j = 0; j < 8; j++) {
            b[(8 * i) + j] = t % 2;
            t /= 2;
        }
    }
}

void ByteEncode(int *F, size_t d, unsigned char *output) {
    if (d < 1 || d > 12) {
        perror("Err: bit length incorrect");
        exit(EXIT_FAILURE);
    }

    unsigned char *b = (unsigned char *)malloc(sizeof(unsigned char) * d * 256);
    if (b == NULL) {
        perror("Failed to allocate memory for b");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < 256; i++) {
        int t = F[i];
        for (int j = 0; j < (int)d; j++) {
            b[i * d + j] = t % 2;
            t = (t - b[i * d + j]) / 2;
        }
    }

    Bit2Byte(b, output, sizeof(unsigned char) * d * 32);
    free(b);
}

void ByteDecode(unsigned char *B, size_t d, int *output) {
    int m = 0;
    if (d == 12) {
        m = q;
    } else if (d > 13 || d < 1) {
        perror("Err: bit length incorrect");
        exit(EXIT_FAILURE);
    } else {
        m = exp_int(2, (int)d);
    }

    unsigned char *b = (unsigned char *)malloc(sizeof(unsigned char) * d * n);
    if (b == NULL) {
        perror("Failed to allocate memory for b");
        exit(EXIT_FAILURE);
    }

    Byte2Bit(B, b, sizeof(unsigned char) * d * 32);
    memset(output, 0, sizeof(int) * n);
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < (int)d; j++) {
            output[i] = (output[i] + (b[i * d + j] * exp_int(2, j))) % m;
        }
    }
    free(b);
}

void SampleNTT(unsigned char *B, int *a, size_t input_length) {
    crypto_sha3_ctx ctx;
    unsigned char m[3];
    int j = 0;

    XOF_init(&ctx);
    XOF_absorb(&ctx, B, input_length);

    while (j < n) {
        int d1, d2;
        if (XOF_squeeze(&ctx, m, sizeof(m)) != 0) {
            fprintf(stderr, "SHAKE-128 squeeze failed in SampleNTT\n");
            XOF_clear(&ctx);
            return;
        }

        d1 = (int)m[0] + n * ((int)m[1] % 16);
        d2 = ((int)m[1] / 16) + 16 * (int)m[2];
        if (d1 < q) {
            a[j++] = d1;
        }
        if (d2 < q && j < n) {
            a[j++] = d2;
        }
    }

    XOF_clear(&ctx);
}

void SamplePolyCBD(unsigned char *B, int *f, size_t input_length) {
    int n_ = (int)(input_length / 64);
    if (n_ != 2 && n_ != 3) {
        perror("Input length error SamplePolyCBD");
        exit(EXIT_FAILURE);
    }

    unsigned char *b = (unsigned char *)malloc(sizeof(unsigned char) * input_length * 8);
    if (b == NULL) {
        perror("Failed to allocate memory for b");
        exit(EXIT_FAILURE);
    }

    Byte2Bit(B, b, input_length);
    for (int i = 0; i < 256; i++) {
        int x = 0;
        int y = 0;
        unsigned char *b_p_x = b + (2 * i) * n_;
        unsigned char *b_p_y = b + (2 * i + 1) * n_;
        for (int j = 0; j < n_; j++) {
            x += b_p_x[j];
            y += b_p_y[j];
        }
        f[i] = (x - y + q) % q;
    }
    free(b);
}

void Comp(int *input, int d, int *output, size_t inout_length) {
    int pow2 = exp_int(2, d);
    int half_q = q / 2;
    for (int i = 0; i < (int)inout_length; i++) {
        output[i] = (pow2 * input[i] + half_q) / q;
        output[i] = output[i] % pow2;
    }
}

void Decomp(int *input, int d, int *output, size_t inout_length) {
    int pow2 = exp_int(2, d);
    int half_pow2 = exp_int(2, d - 1);
    for (int i = 0; i < (int)inout_length; i++) {
        output[i] = (q * input[i] + half_pow2) / pow2;
    }
}
