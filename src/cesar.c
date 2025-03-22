#include <ctype.h>
#include "cesar.h"

void chiffrement_cesar(char *texte, int cle) {
    for (int i = 0; texte[i]; i++) {
        if (isalpha(texte[i])) {
            char base = isupper(texte[i]) ? 'A' : 'a';
            texte[i] = base + (texte[i] - base + cle) % 26;
        }
    }
}

void dechiffrement_cesar(char *texte, int cle) {
    for (int i = 0; texte[i]; i++) {
        if (isalpha(texte[i])) {
            char base = isupper(texte[i]) ? 'A' : 'a';
            texte[i] = base + (texte[i] - base - cle + 26) % 26;
        }
    }
}