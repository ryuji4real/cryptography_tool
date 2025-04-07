CC = gcc
CFLAGS = -Wall -Wextra -g -std=c11
SRC_DIR = src
INCLUDE_DIR = include
OBJ_DIR = obj
BIN_DIR = bin

SRC = $(SRC_DIR)/main.c $(SRC_DIR)/cesar.c $(SRC_DIR)/vigenere.c $(SRC_DIR)/xor.c $(SRC_DIR)/utils.c $(SRC_DIR)/rot13.c $(SRC_DIR)/base64.c $(SRC_DIR)/substitution.c $(SRC_DIR)/aes_improved.c $(SRC_DIR)/freq_analysis.c $(SRC_DIR)/transposition.c $(SRC_DIR)/monoalphabetique.c $(SRC_DIR)/rc4.c $(SRC_DIR)/chacha20.c
OBJ = $(SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
EXEC = $(BIN_DIR)/program
LIBS = -ladvapi32 -lssl -lcrypto -lz

all: $(EXEC) directories

$(OBJ_DIR) $(BIN_DIR):
	-mkdir $(OBJ_DIR) 2>nul || exit 0
	-mkdir $(BIN_DIR) 2>nul || exit 0

directories:
	-mkdir $(BIN_DIR)\input_files 2>nul || exit 0
	-mkdir $(BIN_DIR)\keys 2>nul || exit 0
	-mkdir $(BIN_DIR)\output 2>nul || exit 0

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -c $< -o $@

$(EXEC): $(OBJ) | $(BIN_DIR)
	$(CC) $(OBJ) -o $(EXEC) $(LIBS)

clean:
	-rmdir /S /Q $(OBJ_DIR) $(BIN_DIR) 2>nul || exit 0

rebuild: clean all

.PHONY: all clean rebuild directories
