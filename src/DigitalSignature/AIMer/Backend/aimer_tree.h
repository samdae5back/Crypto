/* SPDX-License-Identifier: MIT */

#ifndef CRYPTO_AIMER_BACKEND_AIMER_TREE_H
#define CRYPTO_AIMER_BACKEND_AIMER_TREE_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../aimer_params.h"
#include "aimer_hash.h"


void crypto_aimer_expand_tree(uint8_t *nodes, const uint8_t *salt, size_t rep_index,
                 const uint8_t *seed, const crypto_aimer_params *alg);

void crypto_aimer_reveal_all_but(uint8_t *reveal_path, const uint8_t *nodes, size_t cover_index,
                    const crypto_aimer_params *alg);

void crypto_aimer_reconstruct_tree(uint8_t *nodes, const uint8_t *salt,
                      const uint8_t *reveal_path, size_t rep_index,
                      size_t cover_index, const crypto_aimer_params *alg);

#endif /* CRYPTO_AIMER_BACKEND_AIMER_TREE_H */
