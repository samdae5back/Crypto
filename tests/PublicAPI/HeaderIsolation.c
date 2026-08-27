/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef CRYPTO_TEST_HEADER
#error "CRYPTO_TEST_HEADER must name the public header under test"
#endif

#include CRYPTO_TEST_HEADER

int crypto_test_public_header_is_self_contained(void) {
    return 0;
}
