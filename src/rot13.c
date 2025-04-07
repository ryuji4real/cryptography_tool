#include <ctype.h>
#include "rot13.h"

void chiffrement_rot13(char *texte) {
    for (int i = 0; texte[i]; i++) {
        if (isalpha(texte[i])) {
            char base = isupper(texte[i]) ? 'A' : 'a';
            texte[i] = base + (texte[i] - base + 13) % 26;
        }
    }
}

void dechiffrement_rot13(char *texte) {
    chiffrement_rot13(texte);
}
