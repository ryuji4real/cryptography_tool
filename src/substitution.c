#include <ctype.h>
#include "substitution.h"

void chiffrement_substitution(char *texte, const char *cle) {
    for (int i = 0; texte[i]; i++) {
        if (isalpha(texte[i])) {
            int idx = toupper(texte[i]) - 'A';
            texte[i] = isupper(texte[i]) ? toupper(cle[idx]) : tolower(cle[idx]);
        }
    }
}

void dechiffrement_substitution(char *texte, const char *cle) {
    char inverse[26];
    for (int i = 0; i < 26; i++) {
        inverse[toupper(cle[i]) - 'A'] = 'A' + i;
    }
    for (int i = 0; texte[i]; i++) {
        if (isalpha(texte[i])) {
            int idx = toupper(texte[i]) - 'A';
            texte[i] = isupper(texte[i]) ? inverse[idx] : tolower(inverse[idx]);
        }
    }
}