#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <string.h>
#include "rc4.h"

static void handle_errors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

unsigned char *rc4_encrypt_decrypt(const unsigned char *input, int input_len, const unsigned char *key, int key_len, int *out_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return NULL;

    unsigned char *output = malloc(input_len);
    if (!output) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    int outlen, finallen;
    if (1 != EVP_EncryptInit_ex(ctx, EVP_rc4(), NULL, key, NULL)) {
        handle_errors();
    }

    if (1 != EVP_CIPHER_CTX_set_key_length(ctx, key_len)) {
        free(output);
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }

    if (1 != EVP_EncryptUpdate(ctx, output, &outlen, input, input_len)) {
        free(output);
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }

    if (1 != EVP_EncryptFinal_ex(ctx, output + outlen, &finallen)) {
        free(output);
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }

    *out_len = outlen + finallen;
    EVP_CIPHER_CTX_free(ctx);
    return output;
}

void rc4_free_result(unsigned char *result) {
    if (result) {
        free(result);
    }
}
