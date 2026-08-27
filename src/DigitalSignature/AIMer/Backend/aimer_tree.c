/* SPDX-License-Identifier: MIT */

#include "aimer_tree.h"

static uint8_t *tree_node(uint8_t *nodes, size_t node_index,
                          const crypto_aimer_params *alg)
{
  return nodes + (node_index * alg->seed_bytes);
}

static const uint8_t *tree_node_const(const uint8_t *nodes, size_t node_index,
                                      const crypto_aimer_params *alg)
{
  return nodes + (node_index * alg->seed_bytes);
}

void crypto_aimer_expand_tree(uint8_t *nodes, const uint8_t *salt, size_t rep_index,
                 const uint8_t *seed, const crypto_aimer_params *alg)
{
  size_t node_index;
  uint8_t rep_index_byte = (uint8_t)rep_index;
  crypto_aimer_hash_context ctx;

  memcpy(tree_node(nodes, 0, alg), seed, alg->seed_bytes);
  for (node_index = 1; node_index < alg->parties; node_index++)
  {
    uint8_t node_index_byte = (uint8_t)node_index;

    crypto_aimer_hash_init_prefix(&ctx, alg, CRYPTO_AIMER_HASH_PREFIX_4);
    crypto_aimer_hash_absorb(&ctx, salt, alg->salt_bytes);
    crypto_aimer_hash_absorb(&ctx, &rep_index_byte, sizeof(rep_index_byte));
    crypto_aimer_hash_absorb(&ctx, &node_index_byte, sizeof(node_index_byte));
    crypto_aimer_hash_absorb(&ctx, tree_node_const(nodes, node_index - 1, alg),
                  alg->seed_bytes);
    crypto_aimer_hash_finalize(&ctx, alg);

    crypto_aimer_hash_squeeze(&ctx, tree_node(nodes, (2 * node_index) - 1, alg),
                       alg->seed_bytes << 1, alg);
    crypto_aimer_hash_clear(&ctx);
  }
}

void crypto_aimer_reveal_all_but(uint8_t *reveal_path, const uint8_t *nodes, size_t cover_index,
                    const crypto_aimer_params *alg)
{
  size_t depth;
  size_t index = cover_index + alg->parties;

  for (depth = 0; depth < alg->log_parties; depth++)
  {
    memcpy(reveal_path + (depth * alg->seed_bytes),
           tree_node_const(nodes, (index ^ 1) - 1, alg),
           alg->seed_bytes);
    index >>= 1;
  }
}

void crypto_aimer_reconstruct_tree(uint8_t *nodes, const uint8_t *salt,
                      const uint8_t *reveal_path, size_t rep_index,
                      size_t cover_index, const crypto_aimer_params *alg)
{
  size_t index;
  size_t depth;
  size_t path;
  uint8_t rep_index_byte = (uint8_t)rep_index;
  crypto_aimer_hash_context ctx;

  for (depth = 1; depth < alg->log_parties; depth++)
  {
    path = ((cover_index + alg->parties) >> (alg->log_parties - depth)) ^ 1;
    memcpy(tree_node(nodes, path - 2, alg),
           reveal_path + ((alg->log_parties - depth) * alg->seed_bytes),
           alg->seed_bytes);

    for (index = ((size_t)1 << depth); index < ((size_t)2 << depth); index++)
    {
      uint8_t index_byte = (uint8_t)index;

      crypto_aimer_hash_init_prefix(&ctx, alg, CRYPTO_AIMER_HASH_PREFIX_4);
      crypto_aimer_hash_absorb(&ctx, salt, alg->salt_bytes);
      crypto_aimer_hash_absorb(&ctx, &rep_index_byte, sizeof(rep_index_byte));
      crypto_aimer_hash_absorb(&ctx, &index_byte, sizeof(index_byte));
      crypto_aimer_hash_absorb(&ctx, tree_node_const(nodes, index - 2, alg),
                    alg->seed_bytes);
      crypto_aimer_hash_finalize(&ctx, alg);

      crypto_aimer_hash_squeeze(&ctx, tree_node(nodes, (2 * index) - 2, alg),
                         alg->seed_bytes << 1, alg);
      crypto_aimer_hash_clear(&ctx);
    }
  }

  path = ((cover_index + alg->parties) >> (alg->log_parties - depth)) ^ 1;
  memcpy(tree_node(nodes, path - 2, alg),
         reveal_path + ((alg->log_parties - depth) * alg->seed_bytes),
         alg->seed_bytes);
}
