#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <string.h>
#include <stdlib.h>
#include "aes_improved.h"

static void handle_errors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

AES_Result *aes_encrypt_cbc(const unsigned char *input, int input_len, const unsigned char *key) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return NULL;

    AES_Result *result = malloc(sizeof(AES_Result));
    if (!result) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    if (RAND_bytes(result->iv, AES_IV_SIZE) != 1) {
        free(result);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    int outlen, finallen;
    int pad_len = input_len + (AES_IV_SIZE - input_len % AES_IV_SIZE) % AES_IV_SIZE;
    result->data = malloc(pad_len);
    if (!result->data) {
        free(result);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, result->iv))
        handle_errors();

    if (1 != EVP_EncryptUpdate(ctx, result->data, &outlen, input, input_len))
        handle_errors();

    if (1 != EVP_EncryptFinal_ex(ctx, result->data + outlen, &finallen))
        handle_errors();

    result->data_len = outlen + finallen;
    EVP_CIPHER_CTX_free(ctx);
    return result;
}

AES_Result *aes_decrypt_cbc(const unsigned char *input, int input_len, const unsigned char *key, const unsigned char *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return NULL;

    AES_Result *result = malloc(sizeof(AES_Result));
    if (!result) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    result->data = malloc(input_len);
    if (!result->data) {
        free(result);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    memcpy(result->iv, iv, AES_IV_SIZE);

    int outlen, finallen;
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handle_errors();

    if (1 != EVP_DecryptUpdate(ctx, result->data, &outlen, input, input_len))
        handle_errors();

    if (1 != EVP_DecryptFinal_ex(ctx, result->data + outlen, &finallen))
        handle_errors();

    result->data_len = outlen + finallen;
    EVP_CIPHER_CTX_free(ctx);
    return result;
}

AES_Result *aes_encrypt_gcm(const unsigned char *input, int input_len, const unsigned char *key, const unsigned char *aad, int aad_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return NULL;

    AES_Result *result = malloc(sizeof(AES_Result));
    if (!result) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    if (RAND_bytes(result->iv, AES_IV_SIZE) != 1) {
        free(result);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    result->data = malloc(input_len + AES_IV_SIZE);
    if (!result->data) {
        free(result);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    int outlen, finallen;
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handle_errors();

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_IV_SIZE, NULL))
        handle_errors();

    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, result->iv))
        handle_errors();

    if (aad && 1 != EVP_EncryptUpdate(ctx, NULL, &outlen, aad, aad_len))
        handle_errors();

    if (1 != EVP_EncryptUpdate(ctx, result->data, &outlen, input, input_len))
        handle_errors();

    if (1 != EVP_EncryptFinal_ex(ctx, result->data + outlen, &finallen))
        handle_errors();

    result->data_len = outlen + finallen;

    unsigned char tag[16];
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
        handle_errors();

    memcpy(result->data + result->data_len, tag, 16);
    result->data_len += 16;

    EVP_CIPHER_CTX_free(ctx);
    return result;
}

AES_Result *aes_decrypt_gcm(const unsigned char *input, int input_len, const unsigned char *key, const unsigned char *iv,
                           const unsigned char *aad, int aad_len, const unsigned char *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return NULL;

    AES_Result *result = malloc(sizeof(AES_Result));
    if (!result) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    result->data = malloc(input_len);
    if (!result->data) {
        free(result);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    memcpy(result->iv, iv, AES_IV_SIZE);

    int outlen, finallen;
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handle_errors();

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_IV_SIZE, NULL))
        handle_errors();

    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        handle_errors();

    if (aad && 1 != EVP_DecryptUpdate(ctx, NULL, &outlen, aad, aad_len))
        handle_errors();

    if (1 != EVP_DecryptUpdate(ctx, result->data, &outlen, input, input_len - 16))
        handle_errors();

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag))
        handle_errors();

    int ret = EVP_DecryptFinal_ex(ctx, result->data + outlen, &finallen);
    if (ret <= 0) {
        free(result->data);
        free(result);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    result->data_len = outlen + finallen;
    EVP_CIPHER_CTX_free(ctx);
    return result;
}

void aes_free_result(AES_Result *result) {
    if (result) {
        free(result->data);
        free(result);
    }
}
