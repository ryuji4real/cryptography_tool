#include <string.h>
#include "base64.h"

static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void base64_encode(const char *input, char *output) {
    int i;
    int input_len = strlen(input);
    int output_len = 0;

    for (i = 0; i < input_len; i += 3) {
        unsigned char b1 = input[i];
        unsigned char b2 = (i + 1 < input_len) ? input[i + 1] : 0;
        unsigned char b3 = (i + 2 < input_len) ? input[i + 2] : 0;

        output[output_len++] = base64_table[(b1 >> 2) & 0x3F];
        output[output_len++] = base64_table[((b1 & 0x03) << 4) | ((b2 >> 4) & 0x0F)];
        output[output_len++] = (i + 1 < input_len) ? base64_table[((b2 & 0x0F) << 2) | ((b3 >> 6) & 0x03)] : '=';
        output[output_len++] = (i + 2 < input_len) ? base64_table[b3 & 0x3F] : '=';
    }
    output[output_len] = '\0';
}

void base64_decode(const char *input, char *output) {
    int i;
    int input_len = strlen(input);
    int output_len = 0;

    for (i = 0; i < input_len; i += 4) {
        unsigned char b1 = strchr(base64_table, input[i]) - base64_table;
        unsigned char b2 = strchr(base64_table, input[i + 1]) - base64_table;
        unsigned char b3 = (input[i + 2] == '=') ? 0 : (strchr(base64_table, input[i + 2]) - base64_table);
        unsigned char b4 = (input[i + 3] == '=') ? 0 : (strchr(base64_table, input[i + 3]) - base64_table);

        output[output_len++] = (b1 << 2) | (b2 >> 4);
        if (input[i + 2] != '=') output[output_len++] = ((b2 & 0x0F) << 4) | (b3 >> 2);
        if (input[i + 3] != '=') output[output_len++] = ((b3 & 0x03) << 6) | b4;
    }
    output[output_len] = '\0';
}