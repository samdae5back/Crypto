/* Reuse the exact Stage-1 reference/candidate helpers, but run sufficiently
 * many iterations that Windows clock() granularity cannot round fast paths to
 * zero. The original benchmark remains intact as the first-run record. */
#define main liberacrypt_bignum_stage1_original_driver
#include "Benchmark.c"
#undef main

int main(void) {
    static const size_t bit_sizes[] = {2048u, 3072u, 4096u};
    size_t index;

    if (!benchmark_randomized_reduction_validation()) {
        fputs("stage1 randomized reduction differential validation failed\n",
              stderr);
        return 1;
    }

    puts("stage,operation,bits,path,iterations,median_us_per_op,checksum");
    for (index = 0u; index < sizeof(bit_sizes) / sizeof(bit_sizes[0]); ++index) {
        BignumBenchmarkCase test_case;
        size_t bits = bit_sizes[index];
        size_t comparison_iterations = 500u;
        size_t cios_iterations = 10000u;

        if (!benchmark_case_init(&test_case, bits,
                                 UINT32_C(0x9e3779b9) ^ (uint32_t)bits) ||
            !benchmark_validate_mod(&test_case) ||
            !benchmark_validate_montgomery(&test_case) ||
            !benchmark_reduction_paths(&test_case, comparison_iterations) ||
            !benchmark_mod_mul_paths(&test_case, comparison_iterations) ||
            !benchmark_r2_paths(&test_case, comparison_iterations) ||
            !benchmark_cios_paths(&test_case, cios_iterations)) {
            benchmark_case_clear(&test_case);
            fputs("stage1 accurate bignum benchmark validation failed\n",
                  stderr);
            return 1;
        }
        benchmark_case_clear(&test_case);
    }
    return 0;
}
