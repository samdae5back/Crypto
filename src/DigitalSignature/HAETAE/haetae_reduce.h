// SPDX-License-Identifier: MIT

#ifndef _HAETAE_REDUCE_H_
#define _HAETAE_REDUCE_H_

#include "haetae.h"

#define CRYPTO_HAETAE_MONT 14321     // 2^32 % Q
#define CRYPTO_HAETAE_MONT_SQUARED 4214    // 2^64 % Q
#define CRYPTO_HAETAE_Q_INVERSE 940508161 // q^(-1) mod 2^32
#define CRYPTO_HAETAE_Q_RECIPROCAL 66575     // 2^32 / Q for Barrett
#define CRYPTO_HAETAE_DOUBLE_Q_RECIPROCAL 33287    // 2^32 / DQ for Barrett

int crypto_haetae_montgomery_reduce(long long a);

int crypto_haetae_caddq(int a);

int crypto_haetae_freeze(int a);

int crypto_haetae_reduce32_2q(int a);

int crypto_haetae_freeze2q(int a);

#endif /* _HAETAE_REDUCE_H_ */
