#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "monoalphabetique.h"

const char *codes[] = {
    "1", "B", "X", "33", "3", "44", "55", "66", "8", "77",
    "88", "99", "00", "N", "9", "0", "11", "4", "22", "5",
    "7", "V", "W", "X", "6", "2"
};

const char alphabetClair[] = "abcdefghijklmnopqrstuvwxyz";

const char *lettreToCode(char lettre) {
    if (!isalpha(lettre)) return "";
    int idx = tolower(lettre) - 'a';
    return codes[idx];
}

char codeToLettre(const char *code) {
    for (int i = 0; i < 26; i++) {
        if (strcmp(code, codes[i]) == 0) {
            return 'a' + i;
        }
    }
    return '\0';
}

char chiffrerLettre(char lettre, const char *alphabet_chiffre) {
    if (!isalpha(lettre)) return lettre;
    int idx = tolower(lettre) - 'a';
    return alphabet_chiffre[idx];
}

char dechiffrerLettre(char lettre, const char *alphabet_chiffre) {
    if (!isalpha(lettre)) return lettre;
    for (int i = 0; i < 26; i++) {
        if (tolower(lettre) == tolower(alphabet_chiffre[i])) {
            return alphabetClair[i];
        }
    }
    return lettre;
}

void chiffrement_monoalphabetique(char *message, const char *alphabet_chiffre) {
    char temp[512] = {0};
    int pos = 0;
    int premierMot = 1;

    for (int i = 0; message[i]; i++) {
        if (isspace(message[i])) {
            if (!premierMot) {
                temp[pos++] = ':';
            }
            premierMot = 0;
        } else if (isalpha(message[i])) {
            char lettreChiffree = chiffrerLettre(message[i], alphabet_chiffre);
            const char *code = lettreToCode(lettreChiffree);
            if (!premierMot && i > 0 && isalpha(message[i-1])) {
                temp[pos++] = ',';
            }
            strcpy(&temp[pos], code);
            pos += strlen(code);
            premierMot = 0;
        } else if (message[i] == '!') {
            temp[pos++] = '!';
        } else if (message[i] == '?') {
            temp[pos++] = '?';
        } else if (message[i] == '.') {
            temp[pos++] = '.';
        }
    }
    temp[pos] = '\0';
    strcpy(message, temp);
}

void dechiffrement_monoalphabetique(const char *message, char *resultat, const char *alphabet_chiffre) {
    char temp[512] = {0};
    int pos = 0;
    char code[10] = {0};
    int code_pos = 0;

    for (int i = 0; message[i]; i++) {
        if (message[i] == ':') {
            if (code_pos > 0) {
                code[code_pos] = '\0';
                char lettreClair = codeToLettre(code);
                if (lettreClair != '\0') {
                    temp[pos++] = lettreClair;
                }
                code_pos = 0;
                memset(code, 0, sizeof(code));
            }
            temp[pos++] = ' ';
        } else if (message[i] == ',') {
            code[code_pos] = '\0';
            char lettreClair = codeToLettre(code);
            if (lettreClair != '\0') {
                temp[pos++] = lettreClair;
            }
            code_pos = 0;
            memset(code, 0, sizeof(code));
        } else if (message[i] == '!' || message[i] == '?' || message[i] == '.') {
            if (code_pos > 0) {
                code[code_pos] = '\0';
                char lettreClair = codeToLettre(code);
                if (lettreClair != '\0') {
                    temp[pos++] = lettreClair;
                }
                code_pos = 0;
                memset(code, 0, sizeof(code));
            }
            temp[pos++] = message[i];
        } else {
            code[code_pos++] = message[i];
        }
    }

    if (code_pos > 0) {
        code[code_pos] = '\0';
        char lettreClair = codeToLettre(code);
        if (lettreClair != '\0') {
            temp[pos++] = lettreClair;
        }
    }

    temp[pos] = '\0';
    strcpy(resultat, temp);
}
