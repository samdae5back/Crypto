#ifndef NTTcal_H
#define NTTcal_H

const int* GenZeta(void);
int bit_rev(int x);
void NTT(int* f, int* g, const int* zetas);
void NTT_inv(int* f, int* g, const int* zetas);
void Multiply_basic(int a0, int a1, int b0, int b1, int* c0, int* c1, int r);
void Multiply_NTT(int* f, int* g, int* h, const int* zetas);

#endif // NTTcal_H
