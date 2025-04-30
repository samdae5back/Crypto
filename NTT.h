#pragma once
#ifndef NTT_H
#define NTT_H

int bit_rev(int x);
void NTT(int* f, int* g, int* zeta, int q);
void NTT_inv(int* f, int* g, int* zeta, int q);
void Multiply_basic(int a0, int a1, int b0, int b1, int* c0, int* c1, int r, int q);
void Multiply_NTT(int* f, int* g, int* h, int* zeta, int q);

#endif // NTT_H