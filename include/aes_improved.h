#ifndef AES_IMPROVED_H
#define AES_IMPROVED_H

#define AES_KEY_SIZE 32
#define AES_IV_SIZE 16

typedef struct {
    unsigned char *data;
    int data_len;
    unsigned char iv[AES_IV_SIZE];
} AES_Result;

AES_Result *aes_encrypt_cbc(const unsigned char *input, int input_len, const unsigned char *key);
AES_Result *aes_decrypt_cbc(const unsigned char *input, int input_len, const unsigned char *key, const unsigned char *iv);
AES_Result *aes_encrypt_gcm(const unsigned char *input, int input_len, const unsigned char *key, const unsigned char *aad, int aad_len);
AES_Result *aes_decrypt_gcm(const unsigned char *input, int input_len, const unsigned char *key, const unsigned char *iv, const unsigned char *aad, int aad_len, const unsigned char *tag);
void aes_free_result(AES_Result *result);

#endif
