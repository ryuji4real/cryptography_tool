#include "xor.h"

void chiffrement_xor(char *texte, char cle) {
    for (int i = 0; texte[i]; i++) {
        texte[i] ^= cle;
    }
}

void dechiffrement_xor(char *texte, char cle) {
    chiffrement_xor(texte, cle); 
}