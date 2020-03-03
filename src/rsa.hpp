//
// Created by z0d on 2019/12/10.
//

#ifndef PARALEL_RSA_MPI_MASTER_RSA_HPP
#define PARALEL_RSA_MPI_MASTER_RSA_HPP

#include <string>
#include <vector>
#include <iostream>

using std::string;
using std::vector;

/**
 * rsa公钥
 */
class RSAPubKey {
private:
    long n;
    long e;
public:
    RSAPubKey(long n, long e) : n(n), e(e) {};

    long get_n() const {
        return n;
    }

    long get_e() const {
        return e;
    }

    friend std::ostream &operator<<(std::ostream &os, const RSAPubKey &k) {
        os << "pri key: (" << k.get_n() << ", " << k.get_e() << ")";
        return os;
    }
};


struct RSAPriKey {
private:
    long n;
    long d;
public:
    RSAPriKey(long n, long d) : n(n), d(d) {};

    long get_n() const {
        return n;
    };

    long get_d() const {
        return d;
    };

    friend std::ostream &operator<<(std::ostream &os, const RSAPriKey &k) {
        os << "pub key: (" << k.get_n() << ", " << k.get_d() << ")";
        return os;
    }
};


class RSAKey {
private:
    RSAPubKey pub_key;
    RSAPriKey pri_key;
public:
    RSAKey(RSAPubKey pub, RSAPriKey pri) : pub_key(pub), pri_key(pri) {};

    const RSAPubKey &get_pub_key() const {
        return pub_key;
    }

    const RSAPriKey &get_pri_key() const {
        return pri_key;
    }

    friend std::ostream &operator<<(std::ostream &os, const RSAKey &key) {
        os << "==========rsa key: ==========" << std::endl;
        os << "pub_key: " << key.pub_key << std::endl;
        os << "pri_key: " << key.pri_key << std::endl;
        os << "=============================" << std::endl;
        return os;
    }
};


class RSAKeyGen {
private:
    long n = 0, m = 0, e = 0, d = 0;
    static long gcd(long a, long b);
    static long ex_gcd(long a, long b, long &x, long &y);
    static bool is_prime(long n);
    RSAPubKey generate_pub_key(bool fix = false, long pos = 0);
    RSAPriKey generate_pri_key();

public:
    RSAKeyGen(long p, long q);

    RSAKey generate_key(bool fix = false, long pos = 0);
};

long pow_mod(long a, long e, long n);


long encrypt(RSAPubKey key, long value);


long decrypt(RSAPriKey key, long code);

vector<long> encrypt(RSAPubKey key, const string &value);


string decrypt(RSAPriKey key, const vector<long> &code);


void encrypt(RSAPubKey key, const char *value, long *code, long len);


void decrypt(RSAPriKey key, const long *code, char *value, long len);

#endif //PARALEL_RSA_MPI_MASTER_RSA_HPP
