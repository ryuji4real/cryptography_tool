#ifndef AES_SIMPLE_H
#define AES_SIMPLE_H

void aes_encrypt(const char *input, const char *key, char *output);
void aes_decrypt(const char *input, const char *key, char *output);

#endif