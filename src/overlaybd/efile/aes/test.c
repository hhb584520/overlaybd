/* Includes, for Power! */
#include "aes.h" // This is all that is required to expose the prototypes for basic compression and decompression.
#include <stdio.h>  // For printf()
#include <string.h> // For memcmp()
#include <stdlib.h> // For exit()

#define MAX_MSG_SZ (16u)

/*
 * main
 */
int main(int argc, char *argv[]) {
    KeyHandle hk = NULL;
    CpaCyAesPublicKey publicKey;
    char SWK[17] = "5678123490897809";
    AesKey aes;

    i8_t original_plaintext[MAX_MSG_SZ]="LSMTLSMTLSMTLSMT";
    i8_t decrypt_plaintext[MAX_MSG_SZ];
    i8_t ciphertext[MAX_MSG_SZ];
    i64_t msg_sz = MAX_MSG_SZ;

    printf("cipher text 1\n");
    aes.skey = SWK;
    AES_loadKey(publicKey, &aes, &hk);
    printf("cipher text 2\n");

    /* Get the values of keys */
    printf("original plain text:\n");
    for (int i = 0; i < msg_sz; i++) {
        printf("%u", original_plaintext[i]);
    }
    printf("\n");

    /* Encrypt the message */
    AES_encrypt(hk, original_plaintext, ciphertext, msg_sz, msg_sz);

    printf("cipher text\n");
    for (int i = 0; i < msg_sz; i++) {
        printf("%u", ciphertext[i]);
    }
    printf("\n");

    /* Decrypt the message */
    AES_decrypt(hk, ciphertext, decrypt_plaintext, msg_sz, msg_sz);

    /* Print the plaintext */
    printf("decrypt plain text\n");
    for (int i = 0; i < msg_sz; i++) {
        printf("%u", decrypt_plaintext[i]);
    }
    printf("\n");
}