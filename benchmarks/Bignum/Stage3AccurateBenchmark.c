#define main liberacrypt_bignum_stage3_original_driver
#include "Stage3Benchmark.c"
#undef main

static int karatsuba_one_shot(LiberaCBignum *out,
                              const LiberaCBignum *a,
                              const LiberaCBignum *b) {
    uint32_t *workspace;
    size_t workspace_words;
    int rc;

    if (!out || !a || !b || a->LENGTH != b->LENGTH ||
        a->LENGTH > (SIZE_MAX - 8u) / 4u)
        return -1;
    workspace_words = 4u * a->LENGTH + 8u;
    if (workspace_words > SIZE_MAX / sizeof(uint32_t))
        return -1;
    workspace = (uint32_t *)malloc(workspace_words * sizeof(uint32_t));
    if (!workspace)
        return -1;
    rc = karatsuba_one_level(out, a, b, workspace, workspace_words);
    free(workspace);
    return rc;
}

static int benchmark_one_shot_case(const Stage3Case *test_case,
                                   size_t iterations) {
    LiberaCBignum out;
    double samples[BENCHMARK_SAMPLES];
    uint32_t checksum = 0u;
    size_t sample, iteration;

    crypto_bignum_init(&out);
    if (karatsuba_one_shot(&out, &test_case->a, &test_case->b) != 0)
        goto fail;
    for (sample = 0u; sample < BENCHMARK_SAMPLES; ++sample) {
        double start = benchmark_cpu_microseconds();
        for (iteration = 0u; iteration < iterations; ++iteration) {
            if (karatsuba_one_shot(&out, &test_case->a,
                                   &test_case->b) != 0)
                goto fail;
            checksum ^= benchmark_checksum(&out) + (uint32_t)iteration;
        }
        samples[sample] = (benchmark_cpu_microseconds() - start) /
                          (double)iterations;
    }
    print_result(test_case->bits, "one-level-karatsuba-oneshot", iterations,
                 samples, checksum);
    crypto_bignum_free(&out);
    return 1;

fail:
    crypto_bignum_free(&out);
    return 0;
}

int main(void) {
    static const size_t bit_sizes[] = {
        512u, 1024u, 1536u, 2048u, 3072u, 4096u, 6144u, 8192u
    };
    static const size_t iteration_counts[] = {
        20000u, 10000u, 6000u, 4000u, 2000u, 1200u, 600u, 350u
    };
    size_t index;

    if (!randomized_validation()) {
        fputs("stage3 differential validation failed\n", stderr);
        return 1;
    }

    puts("stage,operation,bits,path,iterations,median_us_per_op,checksum");
    for (index = 0u; index < sizeof(bit_sizes) / sizeof(bit_sizes[0]); ++index) {
        Stage3Case test_case;
        size_t bits = bit_sizes[index];
        if (!stage3_case_init(&test_case, bits,
                              UINT32_C(0xb7e15162) ^ (uint32_t)bits) ||
            !validate_case(&test_case) ||
            !benchmark_case(&test_case, iteration_counts[index]) ||
            !benchmark_one_shot_case(&test_case, iteration_counts[index])) {
            stage3_case_clear(&test_case);
            fputs("stage3 long-run benchmark failed\n", stderr);
            return 1;
        }
        stage3_case_clear(&test_case);
    }
    return 0;
}
