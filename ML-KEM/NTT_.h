#ifndef NTTcal_H
#define NTTcal_H

int* GenZeta();
int bit_rev(int x);
void NTT(int* f, int* g, int* zeta);
void NTT_inv(int* f, int* g, int* zeta);
void Multiply_basic(int a0, int a1, int b0, int b1, int* c0, int* c1, int r);
void Multiply_NTT(int* f, int* g, int* h, int* zeta);

#endif // NTTcal_H