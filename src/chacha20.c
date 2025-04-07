#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <string.h>
#include "chacha20.h"

static void handle_errors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

ChaCha20_Result *chacha20_encrypt(const unsigned char *input, int input_len, const unsigned char *key) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    ChaCha20_Result *result = malloc(sizeof(ChaCha20_Result));
    if (!ctx || !result) goto error;

    if (RAND_bytes(result->nonce, CHACHA20_NONCE_SIZE) != 1) goto error;

    result->data = malloc(input_len);
    if (!result->data) goto error;

    int outlen, finallen;
    if (1 != EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, key, result->nonce)) 
        handle_errors();
    if (1 != EVP_EncryptUpdate(ctx, result->data, &outlen, input, input_len)) 
        handle_errors();
    if (1 != EVP_EncryptFinal_ex(ctx, result->data + outlen, &finallen)) 
        handle_errors();

    result->data_len = outlen + finallen;
    EVP_CIPHER_CTX_free(ctx);
    return result;

error:
    if (result) {
        free(result->data);
        free(result);
    }
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return NULL;
}

ChaCha20_Result *chacha20_decrypt(const unsigned char *input, int input_len, const unsigned char *key, const unsigned char *nonce) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    ChaCha20_Result *result = malloc(sizeof(ChaCha20_Result));
    if (!ctx || !result) goto error;

    memcpy(result->nonce, nonce, CHACHA20_NONCE_SIZE);
    result->data = malloc(input_len);
    if (!result->data) goto error;

    int outlen, finallen;
    if (1 != EVP_DecryptInit_ex(ctx, EVP_chacha20(), NULL, key, nonce)) 
        handle_errors();
    if (1 != EVP_DecryptUpdate(ctx, result->data, &outlen, input, input_len)) 
        handle_errors();
    if (1 != EVP_DecryptFinal_ex(ctx, result->data + outlen, &finallen)) 
        handle_errors();

    result->data_len = outlen + finallen;
    EVP_CIPHER_CTX_free(ctx);
    return result;

error:
    if (result) {
        free(result->data);
        free(result);
    }
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return NULL;
}

void chacha20_free_result(ChaCha20_Result *result) {
    if (result) {
        free(result->data);
        free(result);
    }
}
