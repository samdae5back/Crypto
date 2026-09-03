#define main liberacrypt_bignum_stage3_original_driver
#include "Stage3Benchmark.c"
#undef main

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
            !benchmark_case(&test_case, iteration_counts[index])) {
            stage3_case_clear(&test_case);
            fputs("stage3 long-run benchmark failed\n", stderr);
            return 1;
        }
        stage3_case_clear(&test_case);
    }
    return 0;
}
