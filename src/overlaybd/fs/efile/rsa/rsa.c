/*
   RSA - 
   Copyright (C) 2011-present, Yann Collet.
   BSD 2-Clause License (http://www.opensource.org/licenses/bsd-license.php)
   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are
   met:
       * Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
       * Redistributions in binary form must reproduce the above
   copyright notice, this list of conditions and the following disclaimer
   in the documentation and/or other materials provided with the
   distribution.
   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
   You can contact the author at :
    - RSA homepage : 
    - RSA source repository : 
*/
#include "rsa.h"

#define RSA_MAX_INPUT_SIZE        0x7E000000   /* 2 113 929 216 bytes */

int RSA_cryptBound(int isize) {

    if ((unsigned)isize > (unsigned)RSA_MAX_INPUT_SIZE) {
        return 0;
    }
    else {
        return ((isize) + ((isize)/255) + 16);
    }
}

i16_t mod_exp(i16_t a, i16_t b, i16_t m) {

    /* Set the result to 1 */
    i16_t ans = 1;

    /* Bring the value of base withing the modulo range */
    a = a % m;

    /* Stop if the value of base is 0 */
    if (a == 0) {

        return 0;
    }

    while (b > 0) {
        /* If b is even, then update the answer */
        if (b & 1) {
            ans = (ans * a) % m;
        }

        /* Update the exponent */
        b = b >> 1;

        /* Update the multiplier */
        a = (a * a) % m;
    }

    return ans;
}

int RSA_encrypt(KeyHandle hk, const i8_t *plaintext, i16_t *ciphertext, int inputSize, int maxOutputSize) {
    RsaKey *kRsa = (RsaKey *)hk;
    unsigned int e = 6239;//kRsa->e;
    unsigned int n = 34393;//kRsa->n;
    int len = 0;

    /* Encrypt the plaintext message block by block */
    for (int i = 0; i < inputSize; i++) {
        ciphertext[i] = mod_exp((i16_t)plaintext[i], e, n);
        len++;
    }
    maxOutputSize = len;

    return len;
}

int RSA_decrypt(KeyHandle hk, i8_t *plaintext, const i16_t *ciphertext, int inputSize, int maxOutputSize) {
    RsaKey *kRsa = (RsaKey *)hk;
    unsigned int d = 3119;//kRsa->d;
    unsigned int n = 34393;//kRsa->n;
    int len = 0;

    /* Decrpyt the ciphertext message block by block */
    for (int i = 0; i < inputSize; i++) {
        plaintext[i] = (i8_t)mod_exp(ciphertext[i], d, n);
        len++;
    }
    maxOutputSize = len;

    return len;
}


bool _is_coprime(int a, int b) {

    if (!b) {
        return a == 1;
    }

    return _is_coprime(b, a % b);
}

/**
 * @brief Finds the multiplicative inverses of the two numbers
 *
 * @param a
 * @param b
 * @param x
 * @param y
 */
void _extended_euclid(int a, int b, int *x, int *y) {

    /* If second number is zero */
    if (!a) {
        *x = 0;
        *y = 1;
        return;
    }

    int _x, _y;

    /* Find the coefficients recursively */
    _extended_euclid(b % a, a, &_x, &_y);

    /* Update the coefficients */
    *x = _y - (b / a) * _x;
    *y = _x;
}

/**
 * @brief Returns the multiplicative inverse of a under base m
 *
 * @param a
 * @param m
 * @return int
 */
int _mod_inv(int a, int m) {

    int inv_a, inv_m;

    /* Compute the coefficients using extended euclidean algorithm */
    _extended_euclid(a, m, &inv_a, &inv_m);

    /* If the inverse is negative convert it to positive under m */
    if (inv_a < 0) {
        inv_a = (m + inv_a) % m;
    }

    return inv_a;
}

/**
 * @brief Generate two 8-bit prime numbers
 *
 * @param p
 * @param q
 */
void _gen_prime_nbs(i8_t *p_p, i8_t *p_q) {

    /* Array of all 8 bit prime numbers */
    static i8_t _prime_nbs[] = {
            2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43,
            47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103,
            107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163,
            167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227,
            229, 233, 239, 241, 251
        };

    /* Select the first prime number randomly */
    int p_idx = rand() % (sizeof(_prime_nbs)/sizeof(i8_t));

    /* Select the second prime number randomly */
    int q_idx = rand() % (sizeof(_prime_nbs)/sizeof(i8_t));

    /* Check for their validity */
    while (((i16_t)_prime_nbs[p_idx] * (i16_t)_prime_nbs[q_idx]) < 256u) {

        if (_prime_nbs[p_idx] < _prime_nbs[q_idx]) {
            p_idx++;
        } else {
            q_idx++;
        }
    }

    /* Set the output */
    *p_p = _prime_nbs[p_idx];
    *p_q = _prime_nbs[q_idx];
}

/**
 * @brief Generate the public-private key components to be used for the RSA
 *        algorithm
 *
 * @param p_e
 * @param p_d
 * @param p_n
 */
void rsa_key_gen(i16_t *p_e, i16_t *p_d, i16_t *p_n) {

    i8_t p, q;
    i16_t n, phi_n;
    i16_t e, d;

    /* Set the seed for random numbers */
    srand(getpid());

    /* Generate two prime numbers */
    _gen_prime_nbs(&p, &q);

    /* Find the value of n */
    n = (i16_t)p * (i16_t)q;

    /* Find the value of totient(n) */
    phi_n = (i16_t)(p - 1) * (i16_t)(q - 1);

    /* Find a number between 1..totient(n) which is coprime with totient(n) */
    e = rand() % (phi_n - 2) + 2;
    /* Update e till it becomes coprime */
    if (!_is_coprime(e, phi_n)) {

        i16_t _e = e;

        do {
            /* Check the next number */
            _e = (_e == (phi_n - 1)) ? 2 : (_e + 1);
        } while ((_e != e) && !_is_coprime(_e, phi_n));

        e = _e;
    }

    /* Find d which is multiplicative inverse of e under modulo totient(n) */
    d = _mod_inv(e, phi_n);

    /* Set the output */
    *p_e = e;
    *p_d = d;
    *p_n = n;
}

int RSA_generateKeyPair(i16_t *p_e, i16_t *p_d, i16_t *p_n) {
    rsa_key_gen(p_e, p_e, p_e);
    return 0;
}

int RSA_loadKey(CpaCyRsaPublicKey publicKey, Cpa8U *SWK, KeyHandle hk) {
    return 0;
}
