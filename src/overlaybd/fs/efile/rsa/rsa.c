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

int RSA_encrypt(KeyHandle *hk, const i8_t *plaintext, i16_t *ciphertext, int inputSize, int maxOutputSize) {
    unsigned int e = 6239;
    unsigned int n = 34393;
    int len = 0;

    /* Encrypt the plaintext message block by block */
    for (int i = 0; i < inputSize; i++) {
        ciphertext[i] = mod_exp((i16_t)plaintext[i], e, n);
        len++;
    }
    maxOutputSize = len;

    return len;
}

int RSA_decrypt(KeyHandle *hk, i8_t *plaintext, const i16_t *ciphertext, int inputSize, int maxOutputSize) {
    unsigned int d = 3119;
    unsigned int n = 34393;
    int len = 0;

    /* Decrpyt the ciphertext message block by block */
    for (int i = 0; i < inputSize; i++) {
        plaintext[i] = (i8_t)mod_exp(ciphertext[i], d, n);
        len++;
    }
    maxOutputSize = len;

    return len;
}

int RSA_generateKeyPair() {
    return 0;
}

int RSA_loadKey(CpaCyRsaPublicKey publicKey, Cpa8U *SWK, KeyHandle *hk) {
    return 0;
}