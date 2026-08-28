/*
 * Copyright (C) 2026 Myungjun Kim
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#include "BlockCipher/TripleDES/triple_des_internal.h"
#include "Util/Core/secure_zero.h"

#include <string.h>

static const uint8_t IP[64] = {58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7};
static const uint8_t FP[64] = {40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25};
static const uint8_t PC1[56] = {57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4};
static const uint8_t PC2[48] = {14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32};
static const uint8_t E[48] = {32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1};
static const uint8_t P[32] = {16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25};
static const uint8_t ROT[16] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
static const uint8_t S[8][64] = {
 {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13},
 {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9},
 {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12},
 {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14},
 {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3},
 {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13},
 {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12},
 {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}
};

static uint64_t load64(const uint8_t *p) { uint64_t x=0; size_t i; for(i=0;i<8;i++) x=(x<<8)|p[i]; return x; }
static void store64(uint8_t *p,uint64_t x) { size_t i; for(i=0;i<8;i++) p[7-i]=(uint8_t)(x>>(8*i)); }
static uint64_t perm(uint64_t x,unsigned inbits,const uint8_t *tab,size_t n) { uint64_t y=0; size_t i; for(i=0;i<n;i++) y=(y<<1)|((x>>(inbits-tab[i]))&1u); return y; }
static uint8_t ct_eq6(uint8_t a,uint8_t b) { uint32_t x=(uint32_t)(a^b); x=(x-1u)>>31; return (uint8_t)(0u-x); }
static uint8_t sbox(unsigned box,uint8_t six) { uint8_t row=(uint8_t)(((six&0x20u)>>4)|(six&1u)); uint8_t col=(uint8_t)((six>>1)&15u); uint8_t idx=(uint8_t)(row*16u+col),v=0; unsigned i; for(i=0;i<64;i++) v|=(uint8_t)(S[box][i]&ct_eq6(idx,(uint8_t)i)); return v; }
static uint32_t f(uint32_t r,uint64_t k) { uint64_t x=perm(r,32,E,48)^k; uint32_t y=0; unsigned i; for(i=0;i<8;i++) y=(y<<4)|sbox(i,(uint8_t)((x>>(42u-6u*i))&63u)); return (uint32_t)perm(y,32,P,32); }
static void schedule(const uint8_t key[8],uint64_t k[16]) { uint64_t p=perm(load64(key),64,PC1,56); uint32_t c=(uint32_t)(p>>28),d=(uint32_t)(p&0xfffffff); unsigned i; for(i=0;i<16;i++){c=((c<<ROT[i])|(c>>(28-ROT[i])))&0xfffffff;d=((d<<ROT[i])|(d>>(28-ROT[i])))&0xfffffff;k[i]=perm(((uint64_t)c<<28)|d,56,PC2,48);} }
static uint64_t des(uint64_t block,const uint64_t k[16],int enc) { uint64_t x=perm(block,64,IP,64); uint32_t l=(uint32_t)(x>>32),r=(uint32_t)x,t; unsigned i; for(i=0;i<16;i++){t=r;r=l^f(r,k[enc?i:15u-i]);l=t;} return perm(((uint64_t)r<<32)|l,64,FP,64); }
static uint64_t tdes(uint64_t b,const uint64_t k[3][16],int enc) { if(enc){b=des(b,k[0],1);b=des(b,k[1],0);return des(b,k[2],1);} b=des(b,k[2],0);b=des(b,k[1],1);return des(b,k[0],0); }

LiberaCError crypto_tdes_ede3_crypt(uint8_t *out,size_t cap,const uint8_t *in,size_t len,const uint8_t *key,size_t keylen,const uint8_t *iv,size_t ivlen,CryptoTdesMode mode,int enc) {
    uint64_t keys[3][16], chain=0, block, result; size_t off;
    if (key == NULL || keylen != LIBERAC_TDES_EDE3_KEY_BYTES) return LIBERAC_ERROR_INVALID_KEY;
    if ((out == NULL || in == NULL) && len != 0u) return LIBERAC_ERROR_INVALID_ARGUMENT;
    if (cap < len) return LIBERAC_ERROR_BUFFER_TOO_SMALL;
    if ((len & 7u) != 0u) return LIBERAC_ERROR_INVALID_ARGUMENT;
    if (mode == CRYPTO_TDES_MODE_ECB) { if (iv != NULL || ivlen != 0u) return LIBERAC_ERROR_INVALID_ARGUMENT; }
    else if (mode == CRYPTO_TDES_MODE_CBC) { if (iv == NULL || ivlen != 8u) return LIBERAC_ERROR_INVALID_ARGUMENT; chain=load64(iv); }
    else return LIBERAC_ERROR_INVALID_ALG_ID;
    schedule(key,keys[0]); schedule(key+8,keys[1]); schedule(key+16,keys[2]);
    for(off=0;off<len;off+=8){ block=load64(in+off); if(enc&&mode==CRYPTO_TDES_MODE_CBC) block^=chain; result=tdes(block,keys,enc); if(!enc&&mode==CRYPTO_TDES_MODE_CBC){result^=chain;chain=block;} else if(enc&&mode==CRYPTO_TDES_MODE_CBC) chain=result; store64(out+off,result); }
    crypto_zeroize(keys,sizeof(keys)); block=result=chain=0; return LIBERAC_SUCCESS;
}
