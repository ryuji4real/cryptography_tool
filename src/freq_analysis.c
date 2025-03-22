#include <stdio.h>
#include <ctype.h>
#include "freq_analysis.h"

void frequency_analysis(const char *texte) {
    int freq[26] = {0};
    int total = 0;

    for (int i = 0; texte[i]; i++) {
        if (isalpha(texte[i])) {
            freq[toupper(texte[i]) - 'A']++;
            total++;
        }
    }

    printf("Analyse de frequence:\n");
    for (int i = 0; i < 26; i++) {
        if (freq[i] > 0) {
            printf("%c: %d (%.2f%%)\n", 'A' + i, freq[i], (float)freq[i] / total * 100);
        }
    }
}