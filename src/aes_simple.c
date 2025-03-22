#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include "utils.h"

void aes_encrypt(const char *input, const char *key, char *output) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return;

    int len = strlen(input);
    int pad_len = len + (16 - len % 16) % 16; // Taille de bloc AES = 16
    unsigned char padded[pad_len];
    memcpy(padded, input, len);
    for (int i = len; i < pad_len; i++) padded[i] = pad_len - len; // PKCS5 padding

    int outlen, finallen;
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char *)key, NULL)) { // Pas d'IV pour l'instant
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    if (1 != EVP_EncryptUpdate(ctx, (unsigned char *)output, &outlen, padded, pad_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    if (1 != EVP_EncryptFinal_ex(ctx, (unsigned char *)output + outlen, &finallen)) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    output[outlen + finallen] = '\0';
    EVP_CIPHER_CTX_free(ctx);
}

void aes_decrypt(const char *input, const char *key, char *output) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return;

    int len = strlen(input);
    int outlen, finallen;

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char *)key, NULL)) { // Pas d'IV pour l'instant
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    if (1 != EVP_DecryptUpdate(ctx, (unsigned char *)output, &outlen, (unsigned char *)input, len)) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    if (1 != EVP_DecryptFinal_ex(ctx, (unsigned char *)output + outlen, &finallen)) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    output[outlen + finallen] = '\0';
    EVP_CIPHER_CTX_free(ctx);
}