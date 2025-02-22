//
// Created by z0d on 2019/12/10.
//

#include <cassert>
#include <iostream>
#include <cstring>
#include <ctime>
#include "rsa.hpp"

using std::cout;
using std::endl;
using std::string;
using std::vector;

RSAKeyGen::RSAKeyGen(long p, long q) {
    assert(is_prime(p));
    assert(is_prime(q));
    n = p * q;
    m = (p - 1) * (q - 1);
}


long RSAKeyGen::gcd(long a, long b) {
    if (b == 0)
        return a;
    return gcd(b, a % b);
}


long RSAKeyGen::ex_gcd(long a, long b, long &x, long &y) {
    if (b == 0) {
        x = 1;
        y = 0;
        return a;
    }
    long r = ex_gcd(b, a % b, x, y);
    long temp = y;
    y = x - (a / b) * y;
    x = temp;
    return r;
}


bool RSAKeyGen::is_prime(long n) {
    if (n == 1)
        return false;
    if (n == 2)
        return true;
    for (long i = 2; i * i <= n; i++) {
        if (n % i == 0)
            return false;
    }
    return true;
}


RSAPubKey RSAKeyGen::generate_pub_key(bool fix, long pos) {
    e = m - 1;
    if (!fix) {
        // ss
        srand(time(nullptr));
        pos = rand() % (long) (m / 2);
    }
    for (long i = pos; i < m - 1; i++) {
        if (gcd(m, i) == 1) {
            e = i;
            break;
        }
    }
    return {n, e};
}


RSAPriKey RSAKeyGen::generate_pri_key() {
    long y;
    ex_gcd(e, m, d, y);
    if (d < 0) {
        d = d + m;
    }
    return {n, d};
}


RSAKey RSAKeyGen::generate_key(bool fix, long pos) {
    RSAPubKey pub = generate_pub_key(fix, pos);
    RSAPriKey pri = generate_pri_key();
    return {pub, pri};
}


long pow_mod(long a, long e, long n) {
    long x = 1;
    for (long i = 0; i < e; i++) {
        x = (x * a) % n;
    }
    return x;
}

long encrypt(RSAPubKey key, long value) {
    return pow_mod(value, key.get_e(), key.get_n());
}

long decrypt(RSAPriKey key, long value) {
    return pow_mod(value, key.get_d(), key.get_n());
}

vector<long> encrypt(RSAPubKey key, const string &value) {
    vector<long> code = vector<long>();
    for (char i : value) {
        code.push_back(encrypt(key, i));
    }
    return code;
}

string decrypt(RSAPriKey key, const vector<long> &code) {
    char *c_arr = (char *) malloc(code.size() + 1);
    memset(c_arr, '\0', code.size() + 1);
    char *j = c_arr;
    for (long i:code) {
        *(j++) = (char) decrypt(key, i);
    }
    return string(c_arr);
}

void encrypt(RSAPubKey key, const char *value, long *code, long len) {
    for (int i = 0; i < len; i++) {
        code[i] = encrypt(key, value[i]);
    }
}

void decrypt(RSAPriKey key, const long *code, char *value, long len) {
    for (int i = 0; i < len; i++) {
        value[i] = (char) decrypt(key, code[i]);
    }
}
