/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "KeyEncapsulation.h"
#include "ML-KEM.h"
#include "parameter.h"

enum { BENCHMARK_SAMPLES = 7, BENCHMARK_ITERATIONS = 100 };

typedef enum {
    BENCH_KEYGEN,
    BENCH_ENCAPS,
    BENCH_DECAPS
} benchmark_operation;

typedef struct {
    const char *name;
    LiberaCAlgID alg;
    size_t public_key_bytes;
    size_t private_key_bytes;
    size_t ciphertext_bytes;
} benchmark_case;

static const benchmark_case BENCHMARK_CASES[] = {
    { "ML-KEM-512", LIBERAC_ALG_ML_KEM_512,
      LIBERAC_ML_KEM_512_PUBLIC_KEY_BYTES,
      LIBERAC_ML_KEM_512_PRIVATE_KEY_BYTES,
      LIBERAC_ML_KEM_512_CIPHERTEXT_BYTES },
    { "ML-KEM-768", LIBERAC_ALG_ML_KEM_768,
      LIBERAC_ML_KEM_768_PUBLIC_KEY_BYTES,
      LIBERAC_ML_KEM_768_PRIVATE_KEY_BYTES,
      LIBERAC_ML_KEM_768_CIPHERTEXT_BYTES },
    { "ML-KEM-1024", LIBERAC_ALG_ML_KEM_1024,
      LIBERAC_ML_KEM_1024_PUBLIC_KEY_BYTES,
      LIBERAC_ML_KEM_1024_PRIVATE_KEY_BYTES,
      LIBERAC_ML_KEM_1024_CIPHERTEXT_BYTES }
};

static uint64_t elapsed_ns(const struct timespec *begin,
                           const struct timespec *end) {
    uint64_t seconds = (uint64_t)(end->tv_sec - begin->tv_sec);
    int64_t nanoseconds = (int64_t)end->tv_nsec - (int64_t)begin->tv_nsec;
    if (nanoseconds < 0) {
        --seconds;
        nanoseconds += 1000000000LL;
    }
    return seconds * UINT64_C(1000000000) + (uint64_t)nanoseconds;
}

static int compare_u64(const void *left, const void *right) {
    uint64_t a = *(const uint64_t *)left;
    uint64_t b = *(const uint64_t *)right;
    return (a > b) - (a < b);
}

static const char *operation_name(benchmark_operation operation) {
    switch (operation) {
        case BENCH_KEYGEN: return "KeyGen";
        case BENCH_ENCAPS: return "Encaps";
        case BENCH_DECAPS: return "Decaps";
        default: return "Unknown";
    }
}

static int prepare_case(const benchmark_case *test_case,
                        uint8_t *public_key,
                        uint8_t *private_key,
                        uint8_t *ciphertext,
                        uint8_t shared_secret[32]) {
    static const uint8_t seed[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };
    static const uint8_t rejection_seed[32] = {
        0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
        0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,
        0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
        0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f
    };
    static const uint8_t message[32] = {
        0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,
        0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,
        0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,
        0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f
    };

    mlkem_active_parameters = mlkem_parameters_for(test_case->alg);
    if (!mlkem_active_parameters) return -1;
    if (ML_KEM_KeyGen_internal(seed, rejection_seed,
                               public_key, private_key) != LIBERAC_SUCCESS)
        return -1;
    if (ML_KEM_Encaps_internal(public_key, message,
                               shared_secret, ciphertext) != LIBERAC_SUCCESS)
        return -1;
    return 0;
}

static int run_once(const benchmark_case *test_case,
                    benchmark_operation operation,
                    uint8_t *public_key,
                    uint8_t *private_key,
                    uint8_t *ciphertext,
                    uint8_t shared_secret[32],
                    uint8_t *checksum) {
    static const uint8_t seed[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };
    static const uint8_t rejection_seed[32] = {
        0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
        0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,
        0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
        0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f
    };
    static const uint8_t message[32] = {
        0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,
        0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,
        0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,
        0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f
    };
    LiberaCError result;

    mlkem_active_parameters = mlkem_parameters_for(test_case->alg);
    if (!mlkem_active_parameters) return -1;

    switch (operation) {
        case BENCH_KEYGEN:
            result = ML_KEM_KeyGen_internal(seed, rejection_seed,
                                            public_key, private_key);
            *checksum ^= public_key[0] ^ private_key[0];
            break;
        case BENCH_ENCAPS:
            result = ML_KEM_Encaps_internal(public_key, message,
                                            shared_secret, ciphertext);
            *checksum ^= shared_secret[0] ^ ciphertext[0];
            break;
        case BENCH_DECAPS:
            result = ML_KEM_Decaps_internal(private_key, ciphertext,
                                            shared_secret);
            *checksum ^= shared_secret[0];
            break;
        default:
            return -1;
    }
    return result == LIBERAC_SUCCESS ? 0 : -1;
}

static int benchmark_operation_case(const benchmark_case *test_case,
                                    benchmark_operation operation) {
    uint8_t public_key[LIBERAC_ML_KEM_1024_PUBLIC_KEY_BYTES];
    uint8_t private_key[LIBERAC_ML_KEM_1024_PRIVATE_KEY_BYTES];
    uint8_t ciphertext[LIBERAC_ML_KEM_1024_CIPHERTEXT_BYTES];
    uint8_t shared_secret[32];
    uint64_t samples[BENCHMARK_SAMPLES];
    uint8_t checksum = 0u;
    int sample;
    int iteration;

    memset(public_key, 0, sizeof(public_key));
    memset(private_key, 0, sizeof(private_key));
    memset(ciphertext, 0, sizeof(ciphertext));
    memset(shared_secret, 0, sizeof(shared_secret));

    if (prepare_case(test_case, public_key, private_key,
                     ciphertext, shared_secret) != 0)
        return -1;

    for (iteration = 0; iteration < 10; ++iteration) {
        if (run_once(test_case, operation, public_key, private_key,
                     ciphertext, shared_secret, &checksum) != 0)
            return -1;
    }

    for (sample = 0; sample < BENCHMARK_SAMPLES; ++sample) {
        struct timespec begin;
        struct timespec end;
        uint64_t total;

        if (timespec_get(&begin, TIME_UTC) != TIME_UTC) return -1;
        for (iteration = 0; iteration < BENCHMARK_ITERATIONS; ++iteration) {
            if (run_once(test_case, operation, public_key, private_key,
                         ciphertext, shared_secret, &checksum) != 0)
                return -1;
        }
        if (timespec_get(&end, TIME_UTC) != TIME_UTC) return -1;
        total = elapsed_ns(&begin, &end);
        samples[sample] = total / (uint64_t)BENCHMARK_ITERATIONS;
    }

    qsort(samples, BENCHMARK_SAMPLES, sizeof(samples[0]), compare_u64);
    printf("%s,%s,%llu,%d,%d,%u\n",
           test_case->name, operation_name(operation),
           (unsigned long long)samples[BENCHMARK_SAMPLES / 2],
           BENCHMARK_ITERATIONS, BENCHMARK_SAMPLES,
           (unsigned int)checksum);
    return 0;
}

int main(void) {
    size_t case_index;
    int operation;

    puts("algorithm,operation,median_ns,iterations,samples,checksum");
    for (case_index = 0u;
         case_index < sizeof(BENCHMARK_CASES) / sizeof(BENCHMARK_CASES[0]);
         ++case_index) {
        for (operation = BENCH_KEYGEN; operation <= BENCH_DECAPS; ++operation) {
            if (benchmark_operation_case(&BENCHMARK_CASES[case_index],
                                         (benchmark_operation)operation) != 0) {
                fprintf(stderr, "benchmark failed for %s/%s\n",
                        BENCHMARK_CASES[case_index].name,
                        operation_name((benchmark_operation)operation));
                return 1;
            }
        }
    }
    return 0;
}
