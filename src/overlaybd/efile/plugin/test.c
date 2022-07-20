// g++ -o test software.cpp test.c
#include "software.h" // This is all that is required to expose the prototypes for basic compression and decompression.
#include <stdio.h>  // For printf()
#include <string.h> // For memcmp()
#include <stdlib.h> // For exit()

#define MAX_MSG_SZ (16u)

/*
 * main
 */
int main(int argc, char *argv[]) {

    EFile::ISoftware *m_software = nullptr;
    char prk[17] = "5678123490897809";

    EFile::SoftwareOptions sopt;
    
    sopt.prk = prk;  // private key
    sopt.type = EFile::SoftwareOptions::AES;
    EFile::SoftwareArgs software_args(sopt);
    m_software = create_software(&software_args);

    KeyHandle hk = NULL;

    i8_t original_plaintext[MAX_MSG_SZ]="LSMTLSMTLSMTLSM";
    i8_t decrypt_plaintext[MAX_MSG_SZ];
    i8_t ciphertext[MAX_MSG_SZ];
    i64_t msg_sz = MAX_MSG_SZ;

    printf("cipher text 1\n");
    m_software->loadKey(prk, &hk);
    printf("cipher text 2\n");

    /* Get the values of keys */
    printf("original plain text:\n");
    for (int i = 0; i < msg_sz; i++) {
        printf("%u", original_plaintext[i]);
    }
    printf("\n");

    /* Encrypt the message */
    m_software->encrypt(hk, original_plaintext, msg_sz, ciphertext, msg_sz);

    printf("cipher text\n");
    for (int i = 0; i < msg_sz; i++) {
        printf("%u", ciphertext[i]);
    }
    printf("\n");

    /* Decrypt the message */
    m_software->decrypt(hk, ciphertext, msg_sz, decrypt_plaintext, msg_sz);

    /* Print the plaintext */
    printf("decrypt plain text\n");
    for (int i = 0; i < msg_sz; i++) {
        printf("%u", decrypt_plaintext[i]);
    }
    printf("\n");
}
