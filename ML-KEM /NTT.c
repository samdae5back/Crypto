#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "NTT.h"

//비트 반전 함수
int bit_rev(int x) {
    int t[7];
    for (int i = 0; i < 7; i++) {
        t[i] = x % 2;
        //printf("%d", t[i]);
        x /= 2;
    }

    int r = 0;
    int n = 1;
    for (int i = 0; i < 7;i++) {
        r = r + t[6 - i] * n;
        n *= 2;
    }
    //printf("\n%d\n", r);
    return r;
}


void NTT(int *f, int *g, int *zeta, int q) {
    for (int i = 0;i < 256;i++) {
        g[i] = f[i];
    }
    int i = 1;
    int t = 0;
    for (int len = 128;len >= 2;len= len/2) {
        for (int start = 0;start < 256;start = start + (2 * len)) {
            int z = zeta[bit_rev(i)];
            i++;
                for (int j = start;j < start + len;j++) {
                    t = (z * g[j + len]) % q;
                    g[j + len] = (g[j] - t) % q;
                    g[j] = (g[j] + t) % q;
                }
        }
    }
    for (int i = 0;i < 256;i++) {
        g[i] = g[i] % q;
        while (g[i] < 0) {
            g[i] = g[i] + q;
        }
    }
    return;
}

void NTT_inv(int* f, int* g, int* zeta, int q) {
    for (int i = 0;i < 256;i++) {
        g[i] = f[i];
    }
    int i = 127;
    for (int len = 2;len <= 128;len = len * 2) {
        for (int start = 0;start < 256;start = start + (2 * len)) {
            int z = zeta[bit_rev(i)];
            i--;
            for (int j = start;j < start + len;j++) {
                int t = g[j];
                g[j] = (t +g[j + len]) % q;
                g[j + len] = (z * (g[j + len] - t)) % q;
            }
        }
    }
    for (int i = 0;i < 256;i++) {
        g[i] = (g[i] * 3303) % q;
        while (g[i] < 0) {
            g[i] = g[i] + q;
        }
    }
    return;
}

void Multiply_basic(int a0, int a1, int  b0, int b1, int* c0, int* c1, int r, int q) {
    *c0 = (a0 * b0 + (a1 * b1 % q) * r) % q;
    *c1 = (a0 * b1 + a1 * b0) % q;
    return;
}

void Multiply_NTT(int* f, int* g, int* h, int* zeta, int q) {
    for (int i = 0;i < 128;i++) {
        Multiply_basic(f[2 * i], f[2 * i + 1], g[2 * i], g[2 * i + 1], &h[2 * i], &h[2 * i + 1], zeta[(2 * bit_rev(i)) + 1], q);
        /*
        printf("\n");
        printf("(f_e, f_o, g_e, g_o, r) = (%d, %d, %d, %d, %d)", f[2 * i], f[2 * i + 1], g[2 * i], g[2 * i + 1], zeta[(2 * bit_rev(i)) + 1]);
        printf("\n");
        printf("(h_e, h_o) = (%d, %d)", h[2 * i], h[2 * i + 1]);
        printf("\n");
        */
    }
    return;
}

/*
int main() {
    int q = 3329;//q = (2^8) * 13 + 1 

    //256-th primity root of unity 배열에 저장 (128개)
    int* zeta = (int*)malloc(sizeof(int) * 256);
    if (zeta == NULL) {
        perror("Failed to allocate memory for zeta"); // 오류 메시지 출력
        exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
    }
    printf("Memory allocated successfully at: %p\n", zeta);
    zeta[0] = 1;
    for (int i = 1;i < 256;i++) {
        zeta[i] = zeta[i - 1] * 17 % q;
    }

    //함수열 생성 f,g,h --> NTT --> f_,g_h_
    //fg(x)=f(x)*g(x)
    int* f = (int*)malloc(sizeof(int) * 256);
    int* f_ = (int*)malloc(sizeof(int) * 256);
    int* g = (int*)malloc(sizeof(int) * 256);
    int* g_ = (int*)malloc(sizeof(int) * 256);
    int* h = (int*)malloc(sizeof(int) * 256);
    int* h_ = (int*)malloc(sizeof(int) * 256);
    int* fg = (int*)malloc(sizeof(int) * 256);
    if (f == NULL) {
        perror("Failed to allocate memory for f"); // 오류 메시지 출력
        exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
    }
    printf("Memory allocated successfully at: %p\n", f);
    if (f_ == NULL) {
        perror("Failed to allocate memory for f_"); // 오류 메시지 출력
        exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
    }
    printf("Memory allocated successfully at: %p\n", f_);
    if (g == NULL) {
        perror("Failed to allocate memory for g"); // 오류 메시지 출력
        exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
    }
    printf("Memory allocated successfully at: %p\n", g);
    if (g_ == NULL) {
        perror("Failed to allocate memory for g_"); // 오류 메시지 출력
        exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
    }
    printf("Memory allocated successfully at: %p\n", g_);
    if (h == NULL) {
        perror("Failed to allocate memory for h_"); // 오류 메시지 출력
        exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
    }
    printf("Memory allocated successfully at: %p\n", h);
    if (h_ == NULL) {
        perror("Failed to allocate memory for h_"); // 오류 메시지 출력
        exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
    }
    printf("Memory allocated successfully at: %p\n", h_);
    if (fg == NULL) {
        perror("Failed to allocate memory for fg"); // 오류 메시지 출력
        exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
    }
    printf("Memory allocated successfully at: %p\n", fg);

    //f, g에 랜덤 값 입력
    srand(time(NULL));
    for (int i = 0;i < 256;i++) {
        f[i] = rand() % q;
    }
    for (int i = 0;i < 256;i++) {
        g[i] = rand() % q;
    }


    //NTT연산을 통해 f_, g_생성, NTT곱을 통해 h_구하고 NTT_inverse 통해 h 계산
    NTT(f, f_, zeta, q);
    NTT(g, g_, zeta, q);

    Multiply_NTT(f_, g_, h_, zeta, q);

    NTT_inv(h_, h, zeta, q);

    // NTT관련 각 함수 출력
    printf("f = ");
    printf("\n");
    for (int i = 0;i < 256;i++) {
        printf("%d ", f[i]);
    }
    printf("\n");
    printf("f_ = ");
    printf("\n");
    for (int i = 0;i < 256;i++) {
        printf("%d ", f_[i]);
    }
    printf("\n");
    printf("g = ");
    printf("\n");
    for (int i = 0;i < 256;i++) {
        printf("%d ", g[i]);
    }
    printf("\n");
    printf("g_ = ");
    printf("\n");
    for (int i = 0;i < 256;i++) {
        printf("%d ", g_[i]);
    }
    printf("\n");
    printf("h = ");
    printf("\n");
    for (int i = 0;i < 256;i++) {
        printf("%d ", h[i]);
    }
    printf("\n");
    printf("h_ = ");
    printf("\n");
    for (int i = 0;i < 256;i++) {
        printf("%d ", h_[i]);
    }
    printf("\n");


    //f(x)*g(x)계산을 위해 512길이의 f_512, g_512 생성
    int* f_512 = (int*)malloc(sizeof(int) * 512);
    int* g_512 = (int*)malloc(sizeof(int) * 512);
    if (f_512 == NULL) {
        perror("Failed to allocate memory for f512"); // 오류 메시지 출력
        exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
    }
    printf("Memory allocated successfully at: %p\n", f_512);
    if (g_512 == NULL) {
        perror("Failed to allocate memory for g512"); // 오류 메시지 출력
        exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
    }
    printf("Memory allocated successfully at: %p\n", g_512);


    //0~255항까지는 f, g와 동일한 값 입력, 그 이외에는 0입력
    for (int i = 0;i < 256;i++) {
        f_512[i] = f[i];
        g_512[i] = g[i];
    }
    for (int i = 256;i < 512;i++) {
        f_512[i] = 0;
        g_512[i] = 0;
    }

    //계산값 저장 위해 512길이의 fg_512 생성
    int* fg_512 = (int*)malloc(sizeof(int) * 512);
    if (fg_512 == NULL) {
        perror("Failed to allocate memory for fg512"); // 오류 메시지 출력
        exit(EXIT_FAILURE);// 메모리 할당 실패 시 더 이상 진행 불가, 프로그램 종료 또는 오류 처리
    }
    printf("Memory allocated successfully at: %p\n", fg_512);


    //값 0으로 초기화
    for (int i = 0;i < 512;i++) {
        fg_512[i] = 0;
    }

    //f(x)*g(x) 계산
    for (int i = 0;i < 512;i++) {
        for (int j = 0;j < i + 1;j++) {
            fg_512[i] = (fg_512[i] + (f_512[j] * g_512[i - j])) % q;
        }
    }

    // 각 함수 출력
    printf("f_512 = ");
    printf("\n");
    for (int i = 0;i < 512;i++) {
        printf("%d ", f_512[i]);
    }
    printf("\n");
    printf("g_512 = ");
    printf("\n");
    for (int i = 0;i < 512;i++) {
        printf("%d ", g_512[i]);
    }
    printf("\n");
    printf("fg_512 = ");
    printf("\n");
    for (int i = 0;i < 512;i++) {
        printf("%d ", fg_512[i]);
    }
    printf("\n");


    //fg_512(x) modulo x^512+1 계산
    for (int i = 0;i < 256;i++) {
        fg[i] = (fg_512[i] - fg_512[i + 256] + q) % q;
    }

    //f(x)*g(x)출력
    printf("f*g=\n{");
    for (int i = 0;i < 256;i++) {
        printf("%d ", fg[i]);
    }
    printf("}\n");


    int p = 0;
    for (int i = 0;i < 256;i++) {
        if (fg[i] != h[i]) {
            printf("\n{");
            printf("multiply failed\n");
            printf("\n{");
            p = 1;
            break;
        }
    }
    if (p == 0) {
        printf("\n{");
        printf("Multiply succeed\n");
        printf("\n{");
    }

    //h, h_ 출력
    printf("h=\n{");
    for (int i = 0;i < 256;i++) {
        printf("%d ", h[i]);
    }
    printf("}\n");
    printf("h_=\n{");
    for (int i = 0;i < 256;i++) {
        printf("%d ", h_[i]);
    }
    printf("}\n");
    int i = 0;
    printf("pointer of h_[%d]%p ", i, &h_[i]);


    
    NTT(f, g, zeta, q);
    NTT_inv(g, h, zeta, q);



    for (int i = 0;i < 256;i++) {
        if (f[i] != h[i]) {
            printf("NTT failed\n");
            break;
        }
    }
    printf("NTT succeed\n");

    printf("f=\n{");
    for (int i = 0;i < 256;i++) {
        printf("%d ",f[i]);
    }
    printf("}\n");

    printf("g=\n{");
    for (int i = 0;i < 256;i++) {
        printf("%d ", g[i]);
    }
    printf("}\n");

    printf("h=\n{");
    for (int i = 0;i < 256;i++) {
        printf("%d ",h[i]);
    }
    printf("}\n");
    







}
*/

    
