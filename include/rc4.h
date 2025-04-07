#ifndef RC4_H
#define RC4_H

unsigned char *rc4_encrypt_decrypt(const unsigned char *input, int input_len, const unsigned char *key, int key_len, int *out_len);
void rc4_free_result(unsigned char *result);

#endif
