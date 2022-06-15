/*
 *  RSA - 
 *  Header File
 *  Copyright (C) 2011-present, Yann Collet.

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
#if defined (__cplusplus)
extern "C" {
#endif

#ifndef RSA_H_2983827168210
#define RSA_H_2983827168210

#include <stdint.h>

typedef unsigned char Cpa8U;
typedef unsigned long int Cpa32U;
typedef unsigned long int KeyHandle;
typedef void * CpaInstanceHandle;



/* Unsigned 64 bit integer */
typedef uint64_t i64_t;

/* Unsigned 32 bit integer */
typedef uint32_t i32_t;

/* Unsigned 16 bit integer */
typedef uint16_t i16_t;

/* Unsigned 8 bit integer */
typedef uint8_t  i8_t;

typedef struct _CpaFlatBuffer {
    Cpa32U dataLenInBytes;
    /**< Data length specified in bytes.
     * When used as an input parameter to a function, the length specifies
     * the current length of the buffer.
     * When used as an output parameter to a function, the length passed in
     * specifies the maximum length of the buffer on return (i.e. the allocated
     * length).  The implementation will not write past this length.  On return,
     * the length is always unchanged. */
  Cpa8U *pData;
    /**< The data pointer is a virtual address, however the actual data pointed
     * to is required to be in contiguous physical memory unless the field
     requiresPhysicallyContiguousMemory in CpaInstanceInfo2 is false. */
} CpaFlatBuffer;

typedef struct _CpaCyRsaPublicKey {
    CpaFlatBuffer modulusN;
    /**< The modulus (n).
     * For key generation operations, the client MUST allocate the memory
     * for this parameter; its value is generated.
     * For encrypt operations this parameter is an input. */
    CpaFlatBuffer publicExponentE;
    /**< The public exponent (e).
     * For key generation operations, this field is unused.  It is NOT
     * generated by the interface; it is the responsibility of the client
     * to set this to the same value as the corresponding parameter on
     * the CpaCyRsaKeyGenOpData structure before using the key for
     * encryption.
     * For encrypt operations this parameter is an input. */
} CpaCyRsaPublicKey;

typedef enum CpaCyKptWrappingKeyType_t {
    CPA_CY_KPT_WRAPPING_KEY_TYPE_AES256_GCM = 0
} CpaCyKptWrappingKeyType;

typedef struct CpaCyLoadKey_t {
    CpaFlatBuffer             eSWK;
    /**< Encrypted SWK */
    CpaCyKptWrappingKeyType   wrappingAlgorithm;
    /**< Symmetric wrapping algorithm*/
} CpaCyLoadKey;

int RSA_cryptBound(int isize);
int RSA_encrypt(KeyHandle *hk, const i8_t *plaintext, i16_t *ciphertext, int inputSize, int maxOutputSize);
int RSA_decrypt(KeyHandle *hk, i8_t *plaintext, const i16_t *ciphertext, int inputSize, int maxOutputSize);

int RSA_generateKeyPair();
int RSA_loadKey(CpaCyRsaPublicKey publicKey, Cpa8U *SWK, KeyHandle *hk);



#endif /* RSA_H_2983827168210 */


#if defined (__cplusplus)
}
#endif