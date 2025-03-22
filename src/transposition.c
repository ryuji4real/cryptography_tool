#include <string.h>
#include "transposition.h"

void transposition_encrypt(char *texte, int cols) {
    int len = strlen(texte);
    int rows = (len + cols - 1) / cols;
    char grid[rows][cols];
    memset(grid, ' ', rows * cols);

    for (int i = 0; i < len; i++) {
        grid[i / cols][i % cols] = texte[i];
    }

    int k = 0;
    for (int j = 0; j < cols; j++) {
        for (int i = 0; i < rows; i++) {
            if (grid[i][j] != ' ') texte[k++] = grid[i][j];
        }
    }
    texte[k] = '\0';
}

void transposition_decrypt(char *texte, int cols) {
    int len = strlen(texte);
    int rows = (len + cols - 1) / cols;
    char grid[rows][cols];
    memset(grid, ' ', rows * cols);

    int k = 0;
    for (int j = 0; j < cols; j++) {
        for (int i = 0; i < rows; i++) {
            if (k < len) grid[i][j] = texte[k++];
        }
    }

    k = 0;
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < cols; j++) {
            if (k < len) texte[k++] = grid[i][j];
        }
    }
    texte[k] = '\0';
}