#include <ctype.h>
#include <string.h>
#include "vigenere.h"

void chiffrement_vigenere(char *texte, const char *cle) {
    int cle_len = strlen(cle);
    int j = 0;
    for (int i = 0; texte[i]; i++) {
        if (isalpha(texte[i])) {
            char base = isupper(texte[i]) ? 'A' : 'a';
            int shift = toupper(cle[j % cle_len]) - 'A';
            texte[i] = base + (texte[i] - base + shift) % 26;
            j++;
        }
    }
}

void dechiffrement_vigenere(char *texte, const char *cle) {
    int cle_len = strlen(cle);
    int j = 0;
    for (int i = 0; texte[i]; i++) {
        if (isalpha(texte[i])) {
            char base = isupper(texte[i]) ? 'A' : 'a';
            int shift = toupper(cle[j % cle_len]) - 'A';
            texte[i] = base + (texte[i] - base - shift + 26) % 26;
            j++;
        }
    }
}