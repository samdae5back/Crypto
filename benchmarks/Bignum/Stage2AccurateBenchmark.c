/* Reuse the exact Stage-2 validation/reference helpers while increasing timed
 * iteration counts enough for coarse Windows clock() resolution. */
#define main liberacrypt_bignum_stage2_original_driver
#include "Stage2Benchmark.c"
#undef main

int main(void) {
    static const size_t bit_sizes[] = {1024u, 2048u, 3072u, 4096u};
    size_t index;

    if (!randomized_validation()) {
        fputs("stage2 bignum differential validation failed\n", stderr);
        return 1;
    }

    puts("stage,operation,bits,path,iterations,median_us_per_op,checksum");
    for (index = 0u; index < sizeof(bit_sizes) / sizeof(bit_sizes[0]); ++index) {
        Stage2Case test_case;
        size_t bits = bit_sizes[index];
        size_t linear_iterations = 50000u;
        size_t quadratic_iterations = 5000u;

        if (!stage2_case_init(&test_case, bits,
                              UINT32_C(0x517cc1b7) ^ (uint32_t)bits) ||
            !validate_one_case(&test_case) ||
            !benchmark_binary_pair(&test_case, "add", stage1_add,
                                   current_add_adapter, linear_iterations) ||
            !benchmark_binary_pair(&test_case, "sub", stage1_sub,
                                   current_sub_adapter, linear_iterations) ||
            !benchmark_binary_pair(&test_case, "mul", stage1_mul,
                                   current_mul_adapter,
                                   quadratic_iterations) ||
            !benchmark_square_pair(&test_case, quadratic_iterations)) {
            stage2_case_clear(&test_case);
            fputs("stage2 accurate bignum benchmark failed\n", stderr);
            return 1;
        }
        stage2_case_clear(&test_case);
    }
    return 0;
}
