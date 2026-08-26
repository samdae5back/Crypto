#ifndef ML_KEM_PARAMETER_H
#define ML_KEM_PARAMETER_H

#include "ALGID.h"

typedef struct {
    AlgID alg;
    int q, n, k, eta1, eta2, du, dv;
} mlkem_parameters;

enum { MLKEM_Q = 3329, MLKEM_N = 256, MLKEM_MAX_K = 4,
       MLKEM_MAX_PUBLIC_KEY_BYTES = 1568,
       MLKEM_MAX_CIPHERTEXT_BYTES = 1568 };

static const mlkem_parameters MLKEM_PARAMETER_SETS[] = {
    { ALG_ML_KEM_512,  3329, 256, 2, 3, 2, 10, 4 },
    { ALG_ML_KEM_768,  3329, 256, 3, 2, 2, 10, 4 },
    { ALG_ML_KEM_1024, 3329, 256, 4, 2, 2, 11, 5 }
};

#if defined(_MSC_VER)
#define MLKEM_THREAD_LOCAL __declspec(thread)
#else
#define MLKEM_THREAD_LOCAL _Thread_local
#endif

extern MLKEM_THREAD_LOCAL const mlkem_parameters *mlkem_active_parameters;
const mlkem_parameters *mlkem_parameters_for(AlgID alg);

#define q MLKEM_Q
#define k (mlkem_active_parameters->k)
#define n_1 (mlkem_active_parameters->eta1)
#define n_2 (mlkem_active_parameters->eta2)
#define d_u (mlkem_active_parameters->du)
#define d_v (mlkem_active_parameters->dv)
#define n MLKEM_N

#endif
