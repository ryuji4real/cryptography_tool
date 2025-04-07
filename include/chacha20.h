#ifndef CHACHA20_H
#define CHACHA20_H

#define CHACHA20_KEY_SIZE 32 
#define CHACHA20_NONCE_SIZE 12

typedef struct {
    unsigned char *data;
    int data_len;
    unsigned char nonce[CHACHA20_NONCE_SIZE];
} ChaCha20_Result;

ChaCha20_Result *chacha20_encrypt(const unsigned char *input, int input_len, const unsigned char *key);
ChaCha20_Result *chacha20_decrypt(const unsigned char *input, int input_len, const unsigned char *key, const unsigned char *nonce);
void chacha20_free_result(ChaCha20_Result *result);

#endif
