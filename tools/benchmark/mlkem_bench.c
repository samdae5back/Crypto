/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "KeyEncapsulation.h"
#include "ML-KEM.h"
#include "parameter.h"

static volatile uint8_t benchmark_sink;

static uint64_t now_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        perror("clock_gettime");
        exit(EXIT_FAILURE);
    }
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}

static const char *parameter_name(LiberaCAlgID alg) {
    switch (alg) {
        case LIBERAC_ALG_ML_KEM_512: return "ML-KEM-512";
        case LIBERAC_ALG_ML_KEM_768: return "ML-KEM-768";
        case LIBERAC_ALG_ML_KEM_1024: return "ML-KEM-1024";
        default: return "unknown";
    }
}

static size_t public_key_size(LiberaCAlgID alg) {
    switch (alg) {
        case LIBERAC_ALG_ML_KEM_512: return LIBERAC_ML_KEM_512_PUBLIC_KEY_BYTES;
        case LIBERAC_ALG_ML_KEM_768: return LIBERAC_ML_KEM_768_PUBLIC_KEY_BYTES;
        case LIBERAC_ALG_ML_KEM_1024: return LIBERAC_ML_KEM_1024_PUBLIC_KEY_BYTES;
        default: return 0u;
    }
}

static size_t private_key_size(LiberaCAlgID alg) {
    switch (alg) {
        case LIBERAC_ALG_ML_KEM_512: return LIBERAC_ML_KEM_512_PRIVATE_KEY_BYTES;
        case LIBERAC_ALG_ML_KEM_768: return LIBERAC_ML_KEM_768_PRIVATE_KEY_BYTES;
        case LIBERAC_ALG_ML_KEM_1024: return LIBERAC_ML_KEM_1024_PRIVATE_KEY_BYTES;
        default: return 0u;
    }
}

static size_t ciphertext_size(LiberaCAlgID alg) {
    switch (alg) {
        case LIBERAC_ALG_ML_KEM_512: return LIBERAC_ML_KEM_512_CIPHERTEXT_BYTES;
        case LIBERAC_ALG_ML_KEM_768: return LIBERAC_ML_KEM_768_CIPHERTEXT_BYTES;
        case LIBERAC_ALG_ML_KEM_1024: return LIBERAC_ML_KEM_1024_CIPHERTEXT_BYTES;
        default: return 0u;
    }
}

static unsigned iterations_for(LiberaCAlgID alg, const char *operation) {
    unsigned base;
    switch (alg) {
        case LIBERAC_ALG_ML_KEM_512: base = 500u; break;
        case LIBERAC_ALG_ML_KEM_768: base = 350u; break;
        case LIBERAC_ALG_ML_KEM_1024: base = 250u; break;
        default: return 0u;
    }
    if (strcmp(operation, "decaps") == 0) return base;
    if (strcmp(operation, "encaps") == 0) return base;
    return base;
}

static void initialize_inputs(uint8_t seed[32], uint8_t rejection_seed[32],
                              uint8_t message[32]) {
    size_t i;
    for (i = 0u; i < 32u; ++i) {
        seed[i] = (uint8_t)(0x31u + (unsigned)i * 7u);
        rejection_seed[i] = (uint8_t)(0xa7u - (unsigned)i * 3u);
        message[i] = (uint8_t)(0x5du ^ (unsigned)i * 11u);
    }
}

static void require_success(LiberaCError result, const char *operation) {
    if (result != LIBERAC_SUCCESS) {
        fprintf(stderr, "%s failed: %d\n", operation, (int)result);
        exit(EXIT_FAILURE);
    }
}

static double benchmark_keygen(LiberaCAlgID alg, unsigned iterations,
                               uint8_t *public_key, uint8_t *private_key) {
    uint8_t seed[32];
    uint8_t rejection_seed[32];
    uint8_t message[32];
    uint64_t start;
    uint64_t end;
    unsigned i;

    initialize_inputs(seed, rejection_seed, message);
    (void)message;
    start = now_ns();
    for (i = 0u; i < iterations; ++i) {
        seed[0] = (uint8_t)(0x31u + i);
        rejection_seed[0] = (uint8_t)(0xa7u - i);
        require_success(ML_KEM_KeyGen_internal(seed, rejection_seed,
                                              public_key, private_key),
                        "keygen");
        benchmark_sink ^= public_key[i % public_key_size(alg)];
    }
    end = now_ns();
    return (double)(end - start) / (double)iterations;
}

static double benchmark_encaps(LiberaCAlgID alg, unsigned iterations,
                               const uint8_t *public_key,
                               uint8_t shared_secret[32], uint8_t *ciphertext) {
    uint8_t seed[32];
    uint8_t rejection_seed[32];
    uint8_t message[32];
    uint64_t start;
    uint64_t end;
    unsigned i;

    initialize_inputs(seed, rejection_seed, message);
    (void)seed;
    (void)rejection_seed;
    start = now_ns();
    for (i = 0u; i < iterations; ++i) {
        message[0] = (uint8_t)(0x5du ^ i);
        require_success(ML_KEM_Encaps_internal(public_key, message,
                                              shared_secret, ciphertext),
                        "encaps");
        benchmark_sink ^= ciphertext[i % ciphertext_size(alg)];
    }
    end = now_ns();
    return (double)(end - start) / (double)iterations;
}

static double benchmark_decaps(LiberaCAlgID alg, unsigned iterations,
                               const uint8_t *private_key,
                               const uint8_t *ciphertext,
                               uint8_t shared_secret[32]) {
    uint64_t start;
    uint64_t end;
    unsigned i;

    start = now_ns();
    for (i = 0u; i < iterations; ++i) {
        require_success(ML_KEM_Decaps_internal(private_key, ciphertext,
                                              shared_secret),
                        "decaps");
        benchmark_sink ^= shared_secret[i & 31u];
    }
    end = now_ns();
    return (double)(end - start) / (double)iterations;
}

static void run_parameter_set(const char *implementation, const char *run_id,
                              LiberaCAlgID alg) {
    uint8_t public_key[LIBERAC_ML_KEM_1024_PUBLIC_KEY_BYTES];
    uint8_t private_key[LIBERAC_ML_KEM_1024_PRIVATE_KEY_BYTES];
    uint8_t ciphertext[LIBERAC_ML_KEM_1024_CIPHERTEXT_BYTES];
    uint8_t shared_secret[32];
    uint8_t seed[32];
    uint8_t rejection_seed[32];
    uint8_t message[32];
    unsigned keygen_iterations = iterations_for(alg, "keygen");
    unsigned encaps_iterations = iterations_for(alg, "encaps");
    unsigned decaps_iterations = iterations_for(alg, "decaps");
    double ns_per_op;

    mlkem_active_parameters = mlkem_parameters_for(alg);
    if (mlkem_active_parameters == NULL) {
        fprintf(stderr, "parameter selection failed\n");
        exit(EXIT_FAILURE);
    }

    initialize_inputs(seed, rejection_seed, message);
    require_success(ML_KEM_KeyGen_internal(seed, rejection_seed,
                                          public_key, private_key),
                    "setup keygen");
    require_success(ML_KEM_Encaps_internal(public_key, message,
                                          shared_secret, ciphertext),
                    "setup encaps");
    require_success(ML_KEM_Decaps_internal(private_key, ciphertext,
                                          shared_secret),
                    "setup decaps");

    ns_per_op = benchmark_keygen(alg, keygen_iterations,
                                 public_key, private_key);
    printf("%s,%s,%s,keygen,%u,%.3f\n", implementation, run_id,
           parameter_name(alg), keygen_iterations, ns_per_op);

    initialize_inputs(seed, rejection_seed, message);
    require_success(ML_KEM_KeyGen_internal(seed, rejection_seed,
                                          public_key, private_key),
                    "encaps setup keygen");
    ns_per_op = benchmark_encaps(alg, encaps_iterations, public_key,
                                 shared_secret, ciphertext);
    printf("%s,%s,%s,encaps,%u,%.3f\n", implementation, run_id,
           parameter_name(alg), encaps_iterations, ns_per_op);

    initialize_inputs(seed, rejection_seed, message);
    require_success(ML_KEM_Encaps_internal(public_key, message,
                                          shared_secret, ciphertext),
                    "decaps setup encaps");
    ns_per_op = benchmark_decaps(alg, decaps_iterations, private_key,
                                 ciphertext, shared_secret);
    printf("%s,%s,%s,decaps,%u,%.3f\n", implementation, run_id,
           parameter_name(alg), decaps_iterations, ns_per_op);
}

int main(int argc, char **argv) {
    const char *implementation;
    const char *run_id;

    if (argc != 3) {
        fprintf(stderr, "usage: %s IMPLEMENTATION RUN_ID\n", argv[0]);
        return EXIT_FAILURE;
    }

    implementation = argv[1];
    run_id = argv[2];
    run_parameter_set(implementation, run_id, LIBERAC_ALG_ML_KEM_512);
    run_parameter_set(implementation, run_id, LIBERAC_ALG_ML_KEM_768);
    run_parameter_set(implementation, run_id, LIBERAC_ALG_ML_KEM_1024);

    fprintf(stderr, "benchmark sink: %u\n", (unsigned)benchmark_sink);
    return EXIT_SUCCESS;
}
