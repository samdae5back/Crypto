#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <limits.h>

//비트 반전 함수
int bit_rev(int x) {
    int t[7];
    for (int i = 0; i < 7; i++) {
        t[i] = x % 2;
        printf("%d", t[i]);
        x /= 2;
    }

    int r = 0;
    int n = 1;
    for (int i = 0; i < 7;i++) {
        r = r + t[6 - i] * n;
        n *= 2;
    }
    printf("\n%d", r);
    return r;
}

//Modulo 거듭제곱 함수.
int mod_exp(int x, int exp, int mod) {
    int r = 1;
    while (exp > 0) {
        if (exp % 2 == 1) {
            r = (r * x) % mod;
        }
        x = x * x % mod;
        exp /= 2;
    }
    return r;
}

void NTT(int (*f)[512], int (*g)[512]) {

    return;
}


int main() {

    //q = (2^8) * 13 + 1 
    int q = 3329;

    //256-th primity root of unity 배열에 저장 (128개)
    /*int zeta[128] = {0,};
    zeta[0] = 17;
    printf("\n%d", zeta[0]);
    for (int i = 0;i < 127;i++) {
        zeta[i + 1] = zeta[i] * 17 % q;
        printf("\n%d", zeta[i+1]);
    }
    */
    int(a)[512] = { 1, };
    int(b)[512]={ 2, };
 

    NTT(&a, &b);
    

    

    return 0;


}