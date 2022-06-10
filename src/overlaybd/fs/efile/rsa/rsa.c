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

int RSA_encrypt(const char *source, char *dest, int inputSize, int maxOutputSize) {
    return 0;
}

int RSA_decrypt(const char *source, char *dest, int inputSize, int maxOutputSize) {
    return 0;
}

int RSA_generateKeyPair() {
    return 0;
}

int RSA_loadKey(CpaCyRsaPublicKey publicKey, Cpa8U *SWK, KeyHandle *hk) {
    return 0;
}