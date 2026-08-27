/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef CRYPTO_INTERNAL_MLDSA_BACKEND_H
#define CRYPTO_INTERNAL_MLDSA_BACKEND_H

#define MLD_CONFIG_PARAMETER_SET 44
#include "mldsa_native.h"
#undef MLD_CONFIG_PARAMETER_SET
#undef MLD_H

#define MLD_CONFIG_PARAMETER_SET 65
#include "mldsa_native.h"
#undef MLD_CONFIG_PARAMETER_SET
#undef MLD_H

#define MLD_CONFIG_PARAMETER_SET 87
#include "mldsa_native.h"
#undef MLD_CONFIG_PARAMETER_SET
#undef MLD_H

#endif
