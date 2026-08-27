/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

/*
 * Multi-level build adapter for the pinned mldsa-native backend.
 * The upstream source is multi-licensed Apache-2.0 OR ISC OR MIT.
 */

#include <stddef.h>

static void crypto_mldsa_zeroize(void *target, size_t length) {
    volatile unsigned char *bytes = (volatile unsigned char *)target;
    while (length-- != 0u) *bytes++ = 0u;
}

/* Keep the bundled backend strictly portable and independent of OS headers. */
#define MLD_CONFIG_NO_ASM
#define MLD_CONFIG_CUSTOM_ZEROIZE
#define mld_zeroize crypto_mldsa_zeroize

#define MLD_CONFIG_MULTILEVEL_WITH_SHARED
#define MLD_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS
#define MLD_CONFIG_PARAMETER_SET 44
#include "mldsa_native.c"
#undef MLD_CONFIG_PARAMETER_SET
#undef MLD_CONFIG_MULTILEVEL_WITH_SHARED

#define MLD_CONFIG_MULTILEVEL_NO_SHARED
#define MLD_CONFIG_PARAMETER_SET 65
#include "mldsa_native.c"
#undef MLD_CONFIG_PARAMETER_SET
#undef MLD_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS

#define MLD_CONFIG_PARAMETER_SET 87
#include "mldsa_native.c"
#undef MLD_CONFIG_PARAMETER_SET
