#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>
#ifdef _WIN32
#include <windows.h>
#endif
#include "cesar.h"
#include "xor.h"
#include "vigenere.h"
#include "rot13.h"
#include "base64.h"
#include "substitution.h"
#include "aes_improved.h"
#include "chacha20.h"
#include "rc4.h"
#include "freq_analysis.h"
#include "transposition.h"
#include "monoalphabetique.h"
#include "utils.h"

#define GREEN 10
#define RED 12
#define WHITE 7

int get_valid_int_input(const char *prompt);
char get_valid_char_input(const char *prompt);
int is_valid_substitution_key(const char *key);
void get_valid_string_input(const char *prompt, char *input, int max_len, int (*validator)(const char *));
void save_encrypted_message(const char *message, int choix);
void afficher_menu(const Config *config);
void afficher_aide(const Config *config);
void run_tests();

#ifdef _WIN32
void set_color(int color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}
#else
void set_color(int color) {}
#endif

int get_valid_int_input(const char *prompt) {
    int input;
    while (1) {
        printf("%s", prompt);
        if (scanf("%d", &input) == 1) {
            while (getchar() != '\n');
            return input;
        } else {
            set_color(RED);
            printf("Invalid input. Please enter a number.\n");
            set_color(WHITE);
            while (getchar() != '\n');
        }
    }
}

char get_valid_char_input(const char *prompt) {
    char input;
    while (1) {
        printf("%s", prompt);
        if (scanf(" %c", &input) == 1) {
            while (getchar() != '\n');
            return input;
        } else {
            set_color(RED);
            printf("Invalid input. Please enter a character.\n");
            set_color(WHITE);
            while (getchar() != '\n');
        }
    }
}

int is_valid_substitution_key(const char *key) {
    if (strlen(key) != 26) return 0;
    int used[26] = {0};
    for (int i = 0; i < 26; i++) {
        if (!isalpha(key[i])) return 0;
        int idx = toupper(key[i]) - 'A';
        if (used[idx]) return 0;
        used[idx] = 1;
    }
    return 1;
}

void get_valid_string_input(const char *prompt, char *input, int max_len, int (*validator)(const char *)) {
    do {
        printf("%s", prompt);
        fgets(input, max_len, stdin);
        input[strcspn(input, "\n")] = 0;
        if (validator && !validator(input)) {
            set_color(RED);
            printf("Invalid input. Try again.\n");
            set_color(WHITE);
        } else {
            break;
        }
    } while (1);
}

void save_encrypted_message(const char *message, int choix) {
    char filename[MAX_MSG];
    snprintf(filename, MAX_MSG, "bin%soutput%soutput_%d.txt", SLASH, SLASH, choix);
#ifdef _WIN32
    system("mkdir bin\\output 2>nul");
#else
    mkdir("bin/output", 0755);
#endif

    FILE *check = fopen(filename, "r");
    if (check) {
        fclose(check);
        char overwrite = get_valid_char_input("File already exists. Overwrite? (y/n): ");
        if (overwrite != 'y' && overwrite != 'Y') return;
    }

    FILE *file = fopen(filename, "w");
    if (file) {
        fprintf(file, "Message (choice %d): %s\n", choix, message);
        fclose(file);
        set_color(GREEN);
        printf("Saved to %s\n", filename);
        set_color(WHITE);
    } else {
        set_color(RED);
        printf("Error writing file.\n");
        set_color(WHITE);
    }
}

void afficher_menu(const Config *config) {
    const char *lang = config->language;
    printf("\n=== %s ===\n", strcmp(lang, "fr") == 0 ? "Outil de Chiffrement/Dechiffrement" : "Encryption/Decryption Tool");
    printf("1 - %s Cesar\n", strcmp(lang, "fr") == 0 ? "Chiffrer avec" : "Encrypt with");
    printf("2 - %s Cesar\n", strcmp(lang, "fr") == 0 ? "Dechiffrer avec" : "Decrypt with");
    printf("3 - %s XOR\n", strcmp(lang, "fr") == 0 ? "Chiffrer avec" : "Encrypt with");
    printf("4 - %s XOR\n", strcmp(lang, "fr") == 0 ? "Dechiffrer avec" : "Decrypt with");
    printf("5 - %s Vigenere\n", strcmp(lang, "fr") == 0 ? "Chiffrer avec" : "Encrypt with");
    printf("6 - %s Vigenere\n", strcmp(lang, "fr") == 0 ? "Dechiffrer avec" : "Decrypt with");
    printf("7 - %s ROT13\n", strcmp(lang, "fr") == 0 ? "Chiffrer avec" : "Encrypt with");
    printf("8 - %s ROT13\n", strcmp(lang, "fr") == 0 ? "Dechiffrer avec" : "Decrypt with");
    printf("9 - %s Base64\n", strcmp(lang, "fr") == 0 ? "Encoder en" : "Encode to");
    printf("10 - %s Base64\n", strcmp(lang, "fr") == 0 ? "Decoder en" : "Decode from");
    printf("11 - %s Substitution\n", strcmp(lang, "fr") == 0 ? "Chiffrer avec" : "Encrypt with");
    printf("12 - %s Substitution\n", strcmp(lang, "fr") == 0 ? "Dechiffrer avec" : "Decrypt with");
    printf("13 - %s\n", strcmp(lang, "fr") == 0 ? "Chiffrer un fichier" : "Encrypt a file");
    printf("14 - %s\n", strcmp(lang, "fr") == 0 ? "Dechiffrer un fichier" : "Decrypt a file");
    printf("15 - %s\n", strcmp(lang, "fr") == 0 ? "Generer une cle aleatoire" : "Generate a random key");
    printf("16 - %s AES\n", strcmp(lang, "fr") == 0 ? "Chiffrer avec" : "Encrypt with");
    printf("17 - %s AES\n", strcmp(lang, "fr") == 0 ? "Dechiffrer avec" : "Decrypt with");
    printf("18 - %s\n", strcmp(lang, "fr") == 0 ? "Analyser la frequence" : "Analyze frequency");
    printf("19 - %s\n", strcmp(lang, "fr") == 0 ? "Chiffrer par transposition" : "Encrypt by transposition");
    printf("20 - %s\n", strcmp(lang, "fr") == 0 ? "Dechiffrer par transposition" : "Decrypt by transposition");
    printf("21 - %s\n", strcmp(lang, "fr") == 0 ? "Chiffrer en batch" : "Batch encrypt");
    printf("22 - %s\n", strcmp(lang, "fr") == 0 ? "Voir l'historique" : "View history");
    printf("23 - %s\n", strcmp(lang, "fr") == 0 ? "Aide" : "Help");
    printf("24 - %s Cesar\n", strcmp(lang, "fr") == 0 ? "Deviner cle" : "Guess Cesar key");
    printf("25 - %s Cesar\n", strcmp(lang, "fr") == 0 ? "Forcer cle" : "Brute force Cesar");
    printf("26 - %s\n", strcmp(lang, "fr") == 0 ? "Detecter algorithme" : "Detect algorithm");
    printf("27 - %s\n", strcmp(lang, "fr") == 0 ? "Calculer SHA-256" : "Compute SHA-256");
    printf("28 - %s\n", strcmp(lang, "fr") == 0 ? "Configurer" : "Configure");
    printf("29 - %s\n", strcmp(lang, "fr") == 0 ? "Tester" : "Test");
    printf("30 - %s Monoalphabetique\n", strcmp(lang, "fr") == 0 ? "Chiffrer avec" : "Encrypt with");
    printf("31 - %s Monoalphabetique\n", strcmp(lang, "fr") == 0 ? "Dechiffrer avec" : "Decrypt with");
    printf("32 - %s ChaCha20\n", strcmp(lang, "fr") == 0 ? "Chiffrer avec" : "Encrypt with");
    printf("33 - %s ChaCha20\n", strcmp(lang, "fr") == 0 ? "Dechiffrer avec" : "Decrypt with");
    printf("34 - %s RC4\n", strcmp(lang, "fr") == 0 ? "Chiffrer/Dechiffrer avec" : "Encrypt/Decrypt with");
    printf("0 - %s\n", strcmp(lang, "fr") == 0 ? "Quitter" : "Quit");
    printf("%s: ", strcmp(lang, "fr") == 0 ? "Choix" : "Choice");
}

void afficher_aide(const Config *config) {
    const char *lang = config->language;
    printf("\n=== %s ===\n", strcmp(lang, "fr") == 0 ? "Aide" : "Help");
    printf("1. Cesar: %s\n", strcmp(lang, "fr") == 0 ? "Decale chaque lettre (cle: entier positif)" : "Shifts each letter (key: positive integer)");
    printf("2. XOR: %s\n", strcmp(lang, "fr") == 0 ? "OU exclusif avec un caractere (cle: 1 caractere)" : "XOR with a character (key: 1 character)");
    printf("3. Vigenere: %s\n", strcmp(lang, "fr") == 0 ? "Chiffrement polyalphabetique (cle: mot)" : "Polyalphabetic cipher (key: word)");
    printf("4. ROT13: %s\n", strcmp(lang, "fr") == 0 ? "Decalage fixe de 13, sans cle" : "Fixed shift of 13, no key");
    printf("5. Base64: %s\n", strcmp(lang, "fr") == 0 ? "Encodage binaire en texte, sans cle" : "Binary to text encoding, no key");
    printf("6. Substitution: %s\n", strcmp(lang, "fr") == 0 ? "Remplace chaque lettre (cle: alphabet 26 lettres)" : "Replaces each letter (key: 26-letter alphabet)");
    printf("7. AES: %s\n", strcmp(lang, "fr") == 0 ? "Chiffrement par bloc (cle: 32 caracteres)" : "Block cipher (key: 32 characters)");
    printf("8. Transposition: %s\n", strcmp(lang, "fr") == 0 ? "Reorganise les lettres (cle: nombre de colonnes)" : "Rearranges letters (key: column count)");
    printf("9. Monoalphabetique: %s\n", strcmp(lang, "fr") == 0 ? "Remplace chaque lettre avec un codage personnalise (cle: alphabet 26 lettres)" : "Replaces each letter with custom encoding (key: 26-letter alphabet)");
    printf("10. ChaCha20: %s\n", strcmp(lang, "fr") == 0 ? "Chiffrement par flux (cle: 32 caracteres)" : "Stream cipher (key: 32 characters)");
    printf("11. RC4: %s\n", strcmp(lang, "fr") == 0 ? "Chiffrement par flux (cle: longueur variable)" : "Stream cipher (key: variable length)");
    printf("12. %s: %s\n", strcmp(lang, "fr") == 0 ? "Fichiers" : "Files", strcmp(lang, "fr") == 0 ? "Chemin absolu ou dans input_files" : "Absolute path or in input_files");
}

void run_tests() {
    printf("Running tests...\n");
    char test[MAX_MSG] = "HELLO";
    chiffrement_cesar(test, 3);
    if (strcmp(test, "KHOOR") == 0) printf("Cesar encrypt: OK\n"); else printf("Cesar encrypt: FAIL\n");
    dechiffrement_cesar(test, 3);
    if (strcmp(test, "HELLO") == 0) printf("Cesar decrypt: OK\n"); else printf("Cesar decrypt: FAIL\n");
}

int main(int argc, char *argv[]) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
    setlocale(LC_ALL, "");
    Config config;
    load_config(&config);
    load_history();
    log_action("Program started");

    if (argc > 1) {
        if (strcmp(argv[1], "--encrypt") == 0 && argc >= 7) {
            char *algo = argv[2];
            char *key = argv[4];
            char *input = argv[6];
            if (strcmp(algo, "cesar") == 0) {
                chiffrement_cesar(input, atoi(key));
                printf("Result: %s\n", input);
                log_action("Cesar encrypt via CLI");
            } else if (strcmp(algo, "aes") == 0) {
                AES_Result *result = aes_encrypt_gcm((unsigned char *)input, strlen(input), (unsigned char *)key, NULL, 0);
                if (!result) {
                    printf("AES encryption failed.\n");
                    return 1;
                }
                printf("Result (hex): ");
                for (int i = 0; i < result->data_len; i++) printf("%02x", result->data[i]);
                printf("\nIV (hex): ");
                for (int i = 0; i < AES_IV_SIZE; i++) printf("%02x", result->iv[i]);
                printf("\n");
                aes_free_result(result);
                log_action("AES-GCM encrypt via CLI");
            }
            return 0;
        }
        printf("Usage: %s --encrypt <algo> --key <key> --input <text>\n", argv[0]);
        return 1;
    }

    char message[MAX_MSG], output[MAX_MSG * 2];
    char cle_str[MAX_MSG];
    char input_file[MAX_MSG], output_file[MAX_MSG];
    int choix;

    while (1) {
        afficher_menu(&config);
        choix = get_valid_int_input("");

        if (choix == 0) {
            set_color(GREEN);
            printf("%s!\n", strcmp(config.language, "fr") == 0 ? "Au revoir" : "Goodbye");
            set_color(WHITE);
            log_action("Program exited");
            break;
        }

        if ((choix >= 1 && choix <= 12) || (choix >= 16 && choix <= 20) || (choix >= 30 && choix <= 34)) {
            get_valid_string_input("Enter your message: ", message, MAX_MSG, NULL);
            normaliser_texte(message);
            printf("Normalized message: %s (Hash: %u)\n", message, simple_hash(message));
        }

        char again = 'n';
        do {
            switch (choix) {
                case 1:
                    int cle_cesar = get_valid_int_input("Enter key (positive integer): ");
                    if (cle_cesar <= 0) {
                        set_color(RED);
                        printf("Error: Key must be positive.\n");
                        set_color(WHITE);
                        break;
                    }
                    chiffrement_cesar(message, cle_cesar);
                    printf("Encrypted: %s\n", message);
                    add_to_history("Cesar encrypt", message);
                    break;
                case 2:
                    cle_cesar = get_valid_int_input("Enter key (positive integer): ");
                    if (cle_cesar <= 0) {
                        set_color(RED);
                        printf("Error: Key must be positive.\n");
                        set_color(WHITE);
                        break;
                    }
                    dechiffrement_cesar(message, cle_cesar);
                    printf("Decrypted: %s\n", message);
                    add_to_history("Cesar decrypt", message);
                    break;
                case 3:
                    char cle_xor = get_valid_char_input("Enter key (character): ");
                    chiffrement_xor(message, cle_xor);
                    printf("Encrypted: %s\n", message);
                    add_to_history("XOR encrypt", message);
                    break;
                case 4:
                    cle_xor = get_valid_char_input("Enter key (character): ");
                    dechiffrement_xor(message, cle_xor);
                    printf("Decrypted: %s\n", message);
                    add_to_history("XOR decrypt", message);
                    break;
                case 5:
                    get_valid_string_input("Enter key (non-empty word): ", cle_str, MAX_MSG, NULL);
                    if (strlen(cle_str) == 0) {
                        set_color(RED);
                        printf("Error: Key cannot be empty.\n");
                        set_color(WHITE);
                        break;
                    }
                    chiffrement_vigenere(message, cle_str);
                    printf("Encrypted: %s\n", message);
                    add_to_history("Vigenere encrypt", message);
                    break;
                case 6:
                    get_valid_string_input("Enter key (non-empty word): ", cle_str, MAX_MSG, NULL);
                    if (strlen(cle_str) == 0) {
                        set_color(RED);
                        printf("Error: Key cannot be empty.\n");
                        set_color(WHITE);
                        break;
                    }
                    dechiffrement_vigenere(message, cle_str);
                    printf("Decrypted: %s\n", message);
                    add_to_history("Vigenere decrypt", message);
                    break;
                case 7:
                    chiffrement_rot13(message);
                    printf("Encrypted: %s\n", message);
                    add_to_history("ROT13 encrypt", message);
                    break;
                case 8:
                    dechiffrement_rot13(message);
                    printf("Decrypted: %s\n", message);
                    add_to_history("ROT13 decrypt", message);
                    break;
                case 9:
                    base64_encode(message, output);
                    printf("Encoded: %s\n", output);
                    add_to_history("Base64 encode", output);
                    break;
                case 10:
                    base64_decode(message, output);
                    printf("Decoded: %s\n", output);
                    add_to_history("Base64 decode", output);
                    break;
                case 11:
                    get_valid_string_input("Enter alphabet (26 unique letters): ", cle_str, MAX_MSG, is_valid_substitution_key);
                    chiffrement_substitution(message, cle_str);
                    printf("Encrypted: %s\n", message);
                    add_to_history("Substitution encrypt", message);
                    break;
                case 12:
                    get_valid_string_input("Enter alphabet (26 unique letters): ", cle_str, MAX_MSG, is_valid_substitution_key);
                    dechiffrement_substitution(message, cle_str);
                    printf("Decrypted: %s\n", message);
                    add_to_history("Substitution decrypt", message);
                    break;
                case 13:
                    list_files(config.default_input_dir);
                    get_valid_string_input("Enter input file (full path or name in input_files): ", input_file, MAX_MSG, NULL);
                    get_valid_string_input("Enter output file: ", output_file, MAX_MSG, NULL);
                    int algo = get_valid_int_input("Algo (1: Cesar, 3: XOR, 5: Vigenere): ");
                    get_valid_string_input("Enter key: ", cle_str, MAX_MSG, NULL);
                    encrypt_file(input_file, output_file, algo, cle_str);
                    add_to_history("File encrypt", output_file);
                    break;
                case 14:
                    list_files(config.default_input_dir);
                    get_valid_string_input("Enter input file (full path or name in input_files): ", input_file, MAX_MSG, NULL);
                    get_valid_string_input("Enter output file: ", output_file, MAX_MSG, NULL);
                    algo = get_valid_int_input("Algo (2: Cesar, 4: XOR, 6: Vigenere): ");
                    get_valid_string_input("Enter key: ", cle_str, MAX_MSG, NULL);
                    decrypt_file(input_file, output_file, algo, cle_str);
                    add_to_history("File decrypt", output_file);
                    break;
                case 15:
                    int key_len = get_valid_int_input("Enter key length (positive, 32 for secure): ");
                    if (key_len <= 0) {
                        set_color(RED);
                        printf("Error: Length must be positive.\n");
                        set_color(WHITE);
                        break;
                    }
                    char type[20];
                    get_valid_string_input("Type (letters, numbers, mixed, secure): ", type, 20, NULL);
                    generate_custom_key(cle_str, key_len, type);
                    printf("Generated key: %s\n", cle_str);
                    add_to_history("Key generation", cle_str);
                    break;
                case 16: {
                    get_valid_string_input("Enter key (32 chars for AES): ", cle_str, MAX_MSG, NULL);
                    if (strlen(cle_str) != AES_KEY_SIZE) {
                        set_color(RED);
                        printf("Error: Key must be 32 characters.\n");
                        set_color(WHITE);
                        break;
                    }
                    AES_Result *result = aes_encrypt_gcm((unsigned char *)message, strlen(message), (unsigned char *)cle_str, NULL, 0);
                    if (!result) {
                        set_color(RED);
                        printf("Encryption failed.\n");
                        set_color(WHITE);
                        break;
                    }
                    printf("Encrypted (hex): ");
                    for (int i = 0; i < result->data_len; i++) printf("%02x", result->data[i]);
                    printf("\nIV (hex): ");
                    for (int i = 0; i < AES_IV_SIZE; i++) printf("%02x", result->iv[i]);
                    printf("\n");
                    aes_free_result(result);
                    add_to_history("AES-GCM encrypt", "Encrypted data");
                    break;
                }
                case 17: {
                    get_valid_string_input("Enter key (32 chars for AES): ", cle_str, MAX_MSG, NULL);
                    if (strlen(cle_str) != AES_KEY_SIZE) {
                        set_color(RED);
                        printf("Error: Key must be 32 characters.\n");
                        set_color(WHITE);
                        break;
                    }
                    unsigned char iv[AES_IV_SIZE];
                    get_valid_string_input("Enter IV (32 hex chars): ", output, 33, NULL);
                    if (strlen(output) != 32) {
                        set_color(RED);
                        printf("Error: IV must be 32 hex characters.\n");
                        set_color(WHITE);
                        break;
                    }
                    hex_to_bytes(output, iv, AES_IV_SIZE);
                    unsigned char *ciphertext = malloc(strlen(message) / 2);
                    int cipher_len = hex_to_bytes(message, ciphertext, strlen(message) / 2);
                    AES_Result *result = aes_decrypt_gcm(ciphertext, cipher_len - 16, (unsigned char *)cle_str, iv, NULL, 0, ciphertext + cipher_len - 16);
                    free(ciphertext);
                    if (!result) {
                        set_color(RED);
                        printf("Decryption or authentication failed.\n");
                        set_color(WHITE);
                        break;
                    }
                    printf("Decrypted: %s\n", result->data);
                    aes_free_result(result);
                    add_to_history("AES-GCM decrypt", "Decrypted data");
                    break;
                }
                case 18:
                    get_valid_string_input("Enter encrypted text: ", message, MAX_MSG, NULL);
                    frequency_analysis(message);
                    add_to_history("Frequency analysis", "Result displayed");
                    break;
                case 19:
                    int cols = get_valid_int_input("Enter column count (positive): ");
                    if (cols <= 0) {
                        set_color(RED);
                        printf("Error: Count must be positive.\n");
                        set_color(WHITE);
                        break;
                    }
                    transposition_encrypt(message, cols);
                    printf("Encrypted: %s\n", message);
                    add_to_history("Transposition encrypt", message);
                    break;
                case 20:
                    cols = get_valid_int_input("Enter column count (positive): ");
                    if (cols <= 0) {
                        set_color(RED);
                        printf("Error: Count must be positive.\n");
                        set_color(WHITE);
                        break;
                    }
                    transposition_decrypt(message, cols);
                    printf("Decrypted: %s\n", message);
                    add_to_history("Transposition decrypt", message);
                    break;
                case 21:
                    get_valid_string_input("Enter algo (1: Cesar, 3: XOR, 5: Vigenere): ", cle_str, MAX_MSG, NULL);
                    get_valid_string_input("Enter key: ", output, MAX_MSG, NULL);
                    int threads = get_valid_int_input("Enter max threads: ");
                    batch_encrypt(cle_str, output, threads > 0 ? threads : config.max_threads);
                    add_to_history("Batch encrypt", "Files processed");
                    break;
                case 22:
                    show_history();
                    break;
                case 23:
                    afficher_aide(&config);
                    break;
                case 24:
                    get_valid_string_input("Enter encrypted text: ", message, MAX_MSG, NULL);
                    int guessed_key = guess_cesar_key(message);
                    printf("Probable Cesar key: %d\n", guessed_key);
                    add_to_history("Cesar key guess", "Result displayed");
                    break;
                case 25:
                    get_valid_string_input("Enter encrypted text: ", message, MAX_MSG, NULL);
                    brute_force_cesar(message);
                    add_to_history("Cesar brute force", "Results displayed");
                    break;
                case 26:
                    get_valid_string_input("Enter encrypted text: ", message, MAX_MSG, NULL);
                    int detected = detect_algorithm(message);
                    printf("Detected algorithm: %d (0=unknown, 1=Cesar, 9=Base64)\n", detected);
                    add_to_history("Algorithm detection", "Result displayed");
                    break;
                case 27:
                    get_valid_string_input("Enter text: ", message, MAX_MSG, NULL);
                    char hash[65];
                    compute_sha256(message, hash);
                    printf("SHA-256: %s\n", hash);
                    add_to_history("SHA-256 computed", hash);
                    break;
                case 28:
                    get_valid_string_input("Enter language (fr/en): ", config.language, 10, NULL);
                    get_valid_string_input("Enter default input directory: ", config.default_input_dir, MAX_MSG, NULL);
                    config.max_threads = get_valid_int_input("Enter max threads: ");
                    save_config(&config);
                    set_color(GREEN);
                    printf("Configuration saved.\n");
                    set_color(WHITE);
                    break;
                case 29:
                    run_tests();
                    break;
                case 30:
                    get_valid_string_input("Enter alphabet (26 unique letters): ", cle_str, MAX_MSG, is_valid_substitution_key);
                    chiffrement_monoalphabetique(message, cle_str);
                    printf("Encrypted: %s\n", message);
                    add_to_history("Monoalphabetique encrypt", message);
                    break;
                case 31:
                    get_valid_string_input("Enter alphabet (26 unique letters): ", cle_str, MAX_MSG, is_valid_substitution_key);
                    dechiffrement_monoalphabetique(message, output, cle_str);
                    printf("Decrypted: %s\n", output);
                    add_to_history("Monoalphabetique decrypt", output);
                    break;
                case 32: {
                    get_valid_string_input("Enter key (32 chars for ChaCha20): ", cle_str, MAX_MSG, NULL);
                    if (strlen(cle_str) != CHACHA20_KEY_SIZE) {
                        set_color(RED);
                        printf("Error: Key must be 32 characters.\n");
                        set_color(WHITE);
                        break;
                    }
                    ChaCha20_Result *result = chacha20_encrypt((unsigned char *)message, strlen(message), (unsigned char *)cle_str);
                    if (!result) {
                        set_color(RED);
                        printf("Encryption failed.\n");
                        set_color(WHITE);
                        break;
                    }
                    printf("Encrypted (hex): ");
                    for (int i = 0; i < result->data_len; i++) printf("%02x", result->data[i]);
                    printf("\nNonce (hex): ");
                    for (int i = 0; i < CHACHA20_NONCE_SIZE; i++) printf("%02x", result->nonce[i]);
                    printf("\n");
                    chacha20_free_result(result);
                    add_to_history("ChaCha20 encrypt", "Encrypted data");
                    break;
                }
                case 33: {
                    get_valid_string_input("Enter key (32 chars for ChaCha20): ", cle_str, MAX_MSG, NULL);
                    if (strlen(cle_str) != CHACHA20_KEY_SIZE) {
                        set_color(RED);
                        printf("Error: Key must be 32 characters.\n");
                        set_color(WHITE);
                        break;
                    }
                    unsigned char nonce[CHACHA20_NONCE_SIZE];
                    get_valid_string_input("Enter nonce (24 hex chars): ", output, 25, NULL);
                    if (strlen(output) != 24) {
                        set_color(RED);
                        printf("Error: Nonce must be 24 hex characters.\n");
                        set_color(WHITE);
                        break;
                    }
                    hex_to_bytes(output, nonce, CHACHA20_NONCE_SIZE);
                    unsigned char *ciphertext = malloc(strlen(message) / 2);
                    int cipher_len = hex_to_bytes(message, ciphertext, strlen(message) / 2);
                    ChaCha20_Result *result = chacha20_decrypt(ciphertext, cipher_len, (unsigned char *)cle_str, nonce);
                    free(ciphertext);
                    if (!result) {
                        set_color(RED);
                        printf("Decryption failed.\n");
                        set_color(WHITE);
                        break;
                    }
                    printf("Decrypted: %s\n", result->data);
                    chacha20_free_result(result);
                    add_to_history("ChaCha20 decrypt", "Decrypted data");
                    break;
                }
                case 34: {
                    get_valid_string_input("Enter key (any length for RC4): ", cle_str, MAX_MSG, NULL);
                    int out_len;
                    unsigned char *result = rc4_encrypt_decrypt((unsigned char *)message, strlen(message), (unsigned char *)cle_str, strlen(cle_str), &out_len);
                    if (!result) {
                        set_color(RED);
                        printf("Encryption/Decryption failed.\n");
                        set_color(WHITE);
                        break;
                    }
                    printf("Result (hex): ");
                    for (int i = 0; i < out_len; i++) printf("%02x", result[i]);
                    printf("\n");
                    rc4_free_result(result);
                    add_to_history("RC4 encrypt/decrypt", "Processed data");
                    break;
                }
                default:
                    set_color(RED);
                    printf("Invalid choice.\n");
                    set_color(WHITE);
                    continue;
            }

            if ((choix >= 1 && choix <= 12) || (choix >= 16 && choix <= 20) || (choix >= 30 && choix <= 34)) {
                again = get_valid_char_input("Apply another algo? (y/n): ");
                if (again == 'y' || again == 'Y') {
                    choix = get_valid_int_input("New algo (1-34): ");
                }
            } else {
                again = 'n';
            }
        } while (again == 'y' || again == 'Y');

        if ((choix >= 1 && choix <= 12) || (choix >= 16 && choix <= 20) || (choix >= 30 && choix <= 34)) {
            char save = get_valid_char_input("Save? (y/n): ");
            if (save == 'y' || save == 'Y') {
                save_encrypted_message(choix <= 10 || choix == 31 ? output : message, choix);
            }
        }
        if (choix == 13 || choix == 14) {
            char save = get_valid_char_input("Save file? (y/n): ");
            if (save == 'y' || save == 'Y') {
                save_encrypted_message(output_file, choix);
            }
        }
    }
    return 0;
}
