#include "NTT.h"
#include "ntt_internal.h"

uint32_t ntt_mod_pow(uint32_t a, uint64_t e, uint32_t q){uint64_t r=1,x=a%q;while(e){if(e&1u)r=(r*x)%q;x=(x*x)%q;e>>=1;}return (uint32_t)r;}
static uint32_t inv(uint32_t a,uint32_t q){return ntt_mod_pow(a,(uint64_t)q-2u,q);}
static int pow2(size_t n){return n&&!(n&(n-1u));}
static void bitrev(uint32_t *a,size_t n){size_t i,j=0;for(i=1;i<n;++i){size_t bit=n>>1;for(;j&bit;bit>>=1)j^=bit;j^=bit;if(i<j){uint32_t t=a[i];a[i]=a[j];a[j]=t;}}}
int CRYPTO_NTT_PLAN_INIT(NTT_PLAN *p,size_t n,uint32_t q,uint32_t primitive){uint32_t root;if(!p||!pow2(n)||q<3u||((uint64_t)q-1u)%n)return -1;root=ntt_mod_pow(primitive,((uint64_t)q-1u)/n,q);if(ntt_mod_pow(root,n,q)!=1u||(n>1u&&ntt_mod_pow(root,n/2u,q)==1u))return -1;p->N=n;p->MODULUS=q;p->ROOT=root;p->ROOT_INV=inv(root,q);p->N_INV=inv((uint32_t)(n%q),q);return 0;}
static int transform(const NTT_PLAN *p,uint32_t *a,uint32_t root){size_t len;if(!p||!a)return -1;bitrev(a,p->N);for(len=2;len<=p->N;len<<=1){uint32_t wl=ntt_mod_pow(root,p->N/len,p->MODULUS);size_t i;for(i=0;i<p->N;i+=len){uint32_t w=1;size_t j;for(j=0;j<len/2;++j){uint32_t u=a[i+j]%p->MODULUS;uint32_t v=(uint32_t)(((uint64_t)a[i+j+len/2]*w)%p->MODULUS);a[i+j]=(u+v>=p->MODULUS)?u+v-p->MODULUS:u+v;a[i+j+len/2]=(u>=v)?u-v:u+p->MODULUS-v;w=(uint32_t)(((uint64_t)w*wl)%p->MODULUS);}}if(len==p->N)break;}return 0;}
int CRYPTO_NTT_FORWARD(const NTT_PLAN *p,uint32_t *a){return transform(p,a,p->ROOT);}
int CRYPTO_NTT_INVERSE(const NTT_PLAN *p,uint32_t *a){size_t i;if(transform(p,a,p->ROOT_INV))return -1;for(i=0;i<p->N;++i)a[i]=(uint32_t)(((uint64_t)a[i]*p->N_INV)%p->MODULUS);return 0;}
