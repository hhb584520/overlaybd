/* Includes, for Power! */
#include "rsa.h" // This is all that is required to expose the prototypes for basic compression and decompression.
#include <stdio.h>  // For printf()
#include <string.h> // For memcmp()
#include <stdlib.h> // For exit()

#define MAX_MSG_SZ (8u)

/*
 * main
 */
int main(int argc, char *argv[]) {
    i16_t e = 6239;
    i16_t d = 3119;
    i16_t n = 34393;
    KeyHandle *hk = NULL;
    i8_t original_plaintext[MAX_MSG_SZ]="LSMTLSMT";
    i8_t decrypt_plaintext[MAX_MSG_SZ];
    i16_t ciphertext[MAX_MSG_SZ];
    i64_t msg_sz = MAX_MSG_SZ;

    /* Get the values of keys */
    for (int i = 0; i < msg_sz; i++) {
        printf("%u", original_plaintext[i]);
    }
    printf("\n");

    /* Encrypt the message */
    RSA_encrypt(hk, original_plaintext, ciphertext, msg_sz, msg_sz);

    for (int i = 0; i < msg_sz; i++) {
        printf("%u", ciphertext[i]);
    }
    printf("\n");

    /* Decrypt the message */
    RSA_decrypt(hk, decrypt_plaintext, ciphertext, msg_sz, msg_sz);

    /* Print the plaintext */
    for (int i = 0; i < msg_sz; i++) {
        printf("%u", decrypt_plaintext[i]);
    }
    printf("\n");
}