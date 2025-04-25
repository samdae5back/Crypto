#include <stdio.h>
#include <stdlib.h>
#include <time.h>

//modular 거듭제곱 함수.
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
    while (prime_check(prime,N) == 0 );
    return prime;
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

//Sophie Germain 소수 찾기
int Gen_p_sg(int k, int N){
    int p;
    do{p = Gen_p(k, N);}
    while (!prime_check(2*p + 1, 20));
    return p;
}

//modulo (2p+1)의 원시근 찾기 (입력값이 p임에 주의)
//2p+1이 소수면 phi(2p+1)=2p. 따라서, g가 원시근이 아니면 g^p=1 or g^2=1
int primitive_root(int p){
    int g;
    do{g = rand() % (2*p + 1);}
    while (mod_exp(g, 2, (2*p + 1)) != 1 && mod_exp(g, p, (2*p + 1)) != 1);
    return g;
}

//Key generation 알고리즘
void KeyGen(int k, int * pk_P, int * pk_h, int * pk_g, int * sk_x){
    int p, P, g;
    p = Gen_p_sg(k, 20);
    P = 2 * p +1;
    g = primitive_root(p);

    //0 ~ P-1 중에 하나 랜덤선택
    int x = rand() % P;
    int h = mod_exp(g, x, P);

    *pk_P = P;
    *pk_h = h;
    *pk_g = g;
    *sk_x = x;
}

//Encryption 알고리즘
void Enc(int m, int pk_P, int pk_h, int pk_g, int * c_1, int * c_2){
    //0 ~ P-1 중에 하나 랜덤선택
    int y = rand() % pk_P;

    *c_1 = mod_exp(pk_g, y, pk_P);
    *c_2 = mod_exp(pk_h, y, pk_P) * m % pk_P;
}

//Decryption 알고리즘
int Dec(int c_1, int c_2, int sk_x, int pk_P){
    int t = mod_exp(c_1, sk_x, pk_P);
    t = inverse(t, pk_P); 
    int m_ = (t * c_2) % pk_P;
    return m_;
}

int main(){
    int p;
    p= Gen_p_sg(8, 20);
    printf("%d\n",p);

    int g;
    g = primitive_root(p);
    printf("%d\n",g);

    srand(time(NULL));
    int k;
    k=8;//parapeter 선택

    int pk_P, pk_h, pk_g, sk_x;

    KeyGen(k, &pk_P, &pk_h, &pk_g, &sk_x);//키생성
    printf("Public key =  (P, h, g) = (%d,%d,%d)\n",pk_P, pk_h, pk_g);
    printf("Secret key =  %d\n",sk_x);

    int m = rand() % pk_P;//평문 선택
    printf("Platintext =  %d\n",m);

    int c_1, c_2;

    Enc(m, pk_P, pk_h, pk_g, &c_1, &c_2);//암호화
    printf("Cyphertext =  (c_1, c_2) = (%d,%d)\n",c_1, c_2);

    int m_ ;

    m_ = Dec(c_1, c_2, sk_x, pk_P);
    printf("Decrypted text =  %d\n",m_);

    if(m == m_){
        printf("Success\n");
    }
    else{
        printf("Fail\n");
    }

    return 0;
}