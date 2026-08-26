#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hash.h"
#include "RANDOM.h"
void RBG(unsigned char *seed,size_t len){if(RANDOM_BYTES(seed,len)!=0){fprintf(stderr,"RBG failed: operating-system CSPRNG unavailable\n");exit(EXIT_FAILURE);}}
void sha3_256_hash(const unsigned char *in,size_t n,unsigned char *out){SHA3_256(out,in,n);}
void sha3_512_hash(const unsigned char *in,size_t n,unsigned char *out){SHA3_512(out,in,n);}
void shake_256_hash(const unsigned char *in,size_t n,unsigned char *out,size_t outn){SHAKE256(out,outn,in,n);}
void PRF(size_t n_,unsigned char *s,unsigned char b,unsigned char *out){unsigned char t[33];if(n_!=2&&n_!=3){fprintf(stderr,"PRF: n must be 2 or 3\n");exit(EXIT_FAILURE);}memcpy(t,s,32);t[32]=b;SHAKE256(out,64*n_,t,sizeof(t));}
void H(unsigned char *in,size_t n,unsigned char *out){SHA3_256(out,in,n);}
void J(unsigned char *in,size_t n,unsigned char *out){SHAKE256(out,32,in,n);}
void G(unsigned char *in,size_t n,unsigned char *o1,unsigned char *o2){unsigned char out[64];SHA3_512(out,in,n);memcpy(o1,out,32);memcpy(o2,out+32,32);memset(out,0,sizeof(out));}
void XOF_init(crypto_sha3_ctx *ctx){SHAKE128_INIT(ctx);}
void XOF_absorb(crypto_sha3_ctx *ctx,const unsigned char *in,size_t n){SHA3_UPDATE(ctx,in,n);}
int XOF_squeeze(crypto_sha3_ctx *ctx,unsigned char *out,size_t n){if(!ctx||(!out&&n))return -1;SHA3_SQUEEZE(ctx,out,n);return 0;}
void XOF_clear(crypto_sha3_ctx *ctx){SHA3_CLEAR(ctx);}
