#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "NTT_.h"
#include "parameter.h"

int* GenZeta() {
    //256-th primity root of unity 배열에 저장 (128개)
    int* zeta = (int*)malloc(sizeof(int) * n);
    if (zeta == NULL) {
        perror("Failed to allocate memory for zeta"); // 오류 메시지 출력
        exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
    }
    zeta[0] = 1;
    for (int i = 1;i < n;i++) {
        zeta[i] = zeta[i - 1] * 17 % q;
    }
    return zeta;
}

//비트 반전 함수
int bit_rev(int x) {
    int t[7] = { 0 };
    for (int i = 0; i < 7; i++) {
        t[i] = x % 2;
        x /= 2;
    }
    int r = 0;
    int j = 1;
    for (int i = 0; i < 7;i++) {
        r = r + t[6 - i] * j;
        j *= 2;
    }
    return r;
}

void NTT(int* f, int* g, int* zeta) {//input, output, zeta
    memcpy(g, f, n * sizeof(int));
    int i = 1;
    int t = 0;
    for (int len = n / 2;len >= 2;len = len / 2) {
        for (int start = 0;start < n;start = start + (2 * len)) {
            int z = zeta[bit_rev(i)];
            i++;
            for (int j = start;j < start + len;j++) {
                t = (z * g[j + len]) % q;
                g[j + len] = (g[j] - t) % q;
                g[j] = (g[j] + t) % q;
            }
        }
    }
    for (int i = 0;i < n;i++) {
        g[i] = g[i] % q;
        while (g[i] < 0) {
            g[i] = g[i] + q;
        }
    }
    return;
}


void NTT_inv(int* f, int* g, int* zeta) {
    memcpy(g, f, n * sizeof(int));
    int i = 127;
    for (int len = 2;len <= 128;len = len * 2) {
        for (int start = 0;start < n;start = start + (2 * len)) {
            int z = zeta[bit_rev(i)];
            i--;
            for (int j = start;j < start + len;j++) {
                int t = g[j];
                g[j] = (t +g[j + len]) % q;
                g[j + len] = (z * (g[j + len] - t)) % q;
            }
        }
    }
    for (int i = 0;i < n;i++) {
        g[i] = (g[i] * 3303) % q;
        while (g[i] < 0) {
            g[i] = g[i] + q;
        }
    }
    return;
}

void Multiply_basic(int a0, int a1, int  b0, int b1, int* c0, int* c1, int r) {
    *c0 = (a0 * b0 + (a1 * b1 % q) * r) % q;
    *c1 = (a0 * b1 + a1 * b0) % q;
    return;
}

void Multiply_NTT(int* f, int* g, int* h, int* zeta) {
    for (int i = 0;i < 128;i++) {
        Multiply_basic(f[2 * i], f[2 * i + 1], g[2 * i], g[2 * i + 1], &h[2 * i], &h[2 * i + 1], zeta[(2 * bit_rev(i)) + 1]);
    }
    return;
}

