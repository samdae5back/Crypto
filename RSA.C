#include <stdio.h>
#include <stdlib.h>
#include <time.h>

//Modulo 거듭제곱 함수.
int mod_exp(int x, int exp, int mod){
    int r =1;
    while (exp > 0){
        if (exp % 2 == 1){
            r = (r * x) % mod;
        }
        x = x * x % mod;
        exp /= 2;
    }
    return r;
}

//소수 판정 알고리즘. 2~13까지의 소수로 나눠본 후에, Millar-Rabin test k 회 반복
int prime_check(int n, int k){
    if (n == 2) return 1;
    else if (n % 2 == 0) return 0;
    else if (n % 3 == 0) return 0;
    else if (n % 5 == 0) return 0;
    else if (n % 7 == 0) return 0;
    else if (n % 11 == 0) return 0;
    else if (n % 13 == 0) return 0;

    int d = n-1;
    int s = 0;
    while (d % 2 == 0){
        d /= 2;
        s++;
    }//n-1 = d*2^s형태로 표현
    for (int i=0; i < k; i++){
        int r = 0;
        int a = rand() % (n-3) +2; //2에서 n-1까지 랜덤선택
        int x = mod_exp(a,d,n);
        if (x == 1 || x == n-1){
            r = 1;
            continue;
        } 
        for (int j=0; j < s; j++){
            x = x * x % n;
            if (x == n -1){
                r = 1;
                break;
            }
        }
        if (r == 0){
            return 0;}
    }
    return 1;
}

//소수 생성 알고리즘
//2^(k1) ~ 2^lk 사이의 소수 랜덤하게 출력, N는 prime test 반복 횟수
int Gen_p(int k,int N){
    int prime;
    do{prime = (rand() % (1 << (k - 1))) | (1 << (k - 1)) | 1;}
    while (!prime_check(prime,N));
    return prime;
}

//유클리드 호제법
int GCD(int a, int b){
    if(b == 0){
        return a;
    }
    return GCD (b, a % b);
}

//확장 유클리드 호제법
void Euclid(int a, int b, int * x, int * y){
    if(b == 0){
        *x = 1;
        *y = 0;
        return;
    }
    int x_, y_;
    Euclid(b, a % b, &x_, &y_);

    *x = y_;
    *y = x_ - (a/b) * y_;
}

//Modulo 역원
int inverse(int a, int N){
    int t, inv_a;
    Euclid(a, N, &inv_a, &t);
    if (inv_a < 0){
        inv_a = inv_a + N;
    }
return inv_a;
}


//Key generation 알고리즘
//k: security parameter 
void KeyGen(int k, int * pk, int * N, int * sk){
    int p = Gen_p(k, 20);
    int q = Gen_p(k, 20);
    int phi_n = (p-1) * (q-1);
    //(p-1)(q-1)과 서로소인 e 선택
    int e;
    do{e = rand() % (phi_n-2) + 2;
    }while(GCD(e, phi_n) != 1);
    //e의 modular역원 계산
    int d = inverse(e, phi_n);
    * pk = e;
    * N = p * q;
    * sk = d;
}

//Ecryption 알고리즘
int Enc(int m, int pk, int N){
    int c = mod_exp(m, pk, N);
    return c;
}

//Decryption 알고리즘
int Dec(int c, int sk, int N){
    int m_ = mod_exp(c, sk, N);
        return m_;
}

//k=8, 14비트 이내의 평문 랜덤선택 후에 RSA암호화 진행, 복호후에 원래평문과 맞는지 확인
int main(){
    srand(time(NULL));
    int k, pk, sk, N;
    k=8;
    int m = rand() % (1 << (2*k-2));//평문 선택
    printf("Platintext =  %d\n",m);

    KeyGen(k, &pk, &N, &sk);//키생성
    printf("Public key =  %d\n",pk);
    printf("Secret key =  %d\n",sk);
    printf("Modular base =  %d\n",N);

    int c = Enc(m, pk, N);//암호화
    printf("Cyphertext =  %d\n",c);

    int m_ = Dec(c, sk, N);
    printf("Decrypted text =  %d\n",m_);

    if(m == m_){
        printf("Success\n");
    }
    else{
        printf("Fail\n");
    }


    return 0;
}