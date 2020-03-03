//
// Created by z0d on2020/03/01.
//
#include "rsa.hpp"
#include <iostream>
#include <vector>

int main() {
    RSAKey key = RSAKeyGen(727, 937).generate_key();
    std::cout << key;
    string s = "RSA (Rivest–Shamir–Adleman) is one of the first public-key cryptosystems and is widely used for secure data transmission.";
    std::cout << "origin: " << s << std::endl;

    vector<long> a = encrypt(key.get_pub_key(), s);
    std::cout << "encrypt: ";
    for (long i:a) {
        std::cout << std::hex << i << " ";
    }
    std::cout << std::endl;

    string b = decrypt(key.get_pri_key(), a);
    std::cout << "decrypt: ";
    std::cout << b << std::endl;
}