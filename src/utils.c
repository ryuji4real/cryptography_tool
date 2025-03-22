#include "utils.h"
#include "cesar.h"
#include "xor.h"
#include "vigenere.h"
#include "freq_analysis.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <zlib.h>
#include <openssl/sha.h>
#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <sys/stat.h>
#include <dirent.h>
#include <pthread.h>
#endif

HistoryEntry history[MAX_HISTORY];
int history_count = 0;

void load_config(Config *config) {
    FILE *file = fopen("bin" SLASH "config.ini", "r");
    if (!file) {
        strcpy(config->language, "fr");
        strcpy(config->default_input_dir, "bin" SLASH "input_files");
        config->max_threads = 4;
        return;
    }
    fscanf(file, "language=%s\n", config->language);
    fscanf(file, "input_dir=%s\n", config->default_input_dir);
    fscanf(file, "max_threads=%d\n", &config->max_threads);
    fclose(file);
}

void save_config(const Config *config) {
    FILE *file = fopen("bin" SLASH "config.ini", "w");
    if (file) {
        fprintf(file, "language=%s\ninput_dir=%s\nmax_threads=%d\n", 
                config->language, config->default_input_dir, config->max_threads);
        fclose(file);
    }
}

void normaliser_texte(char *texte) {
    for (int i = 0; texte[i]; i++) {
        unsigned char c = texte[i];
        if (c == 0xE9 || c == 0xE8 || c == 0xEA || c == 0xEB) texte[i] = 'e';
        else if (c == 0xC9 || c == 0xC8 || c == 0xCA || c == 0xCB) texte[i] = 'E';
        else if (c == 0xE0 || c == 0xE1 || c == 0xE2 || c == 0xE3) texte[i] = 'a';
        else if (c == 0xC0 || c == 0xC1 || c == 0xC2 || c == 0xC3) texte[i] = 'A';
        else if (c == 0xEE || c == 0xEF || c == 0xEC || c == 0xED) texte[i] = 'i';
        else if (c == 0xF4 || c == 0xF6 || c == 0xF2 || c == 0xF3) texte[i] = 'o';
        else if (c == 0xF9 || c == 0xFA || c == 0xFB || c == 0xFC) texte[i] = 'u';
    }
}

void compress_and_encrypt(const char *input_file, const char *output_file, int algo, const char *cle) {
    FILE *in = fopen(input_file, "rb");
    if (!in) {
        printf("Erreur : fichier introuvable (%s)\n", input_file);
        return;
    }

    z_stream strm = {0};
    deflateInit(&strm, Z_DEFAULT_COMPRESSION);
    FILE *temp = tmpfile();
    char buffer[BUFFER_SIZE];
    size_t bytes;
    while ((bytes = fread(buffer, 1, BUFFER_SIZE, in)) > 0) {
        strm.next_in = (Bytef *)buffer;
        strm.avail_in = bytes;
        do {
            strm.next_out = (Bytef *)buffer;
            strm.avail_out = BUFFER_SIZE;
            deflate(&strm, Z_NO_FLUSH);
            fwrite(buffer, 1, BUFFER_SIZE - strm.avail_out, temp);
        } while (strm.avail_out == 0);
    }
    deflate(&strm, Z_FINISH);
    deflateEnd(&strm);
    fclose(in);

    rewind(temp);
    FILE *out = fopen(output_file, "wb");
    while ((bytes = fread(buffer, 1, BUFFER_SIZE, temp)) > 0) {
        switch (algo) {
            case 1: chiffrement_cesar(buffer, atoi(cle)); break;
            case 3: chiffrement_xor(buffer, cle[0]); break;
            case 5: chiffrement_vigenere(buffer, cle); break;
        }
        fwrite(buffer, 1, bytes, out);
    }
    fclose(temp);
    fclose(out);
    printf("Fichier compresse et chiffre\n");
}

void decrypt_and_decompress(const char *input_file, const char *output_file, int algo, const char *cle) {
    FILE *in = fopen(input_file, "rb");
    if (!in) {
        printf("Erreur : fichier introuvable (%s)\n", input_file);
        return;
    }

    FILE *temp = tmpfile();
    char buffer[BUFFER_SIZE];
    size_t bytes;
    while ((bytes = fread(buffer, 1, BUFFER_SIZE, in)) > 0) {
        switch (algo) {
            case 2: dechiffrement_cesar(buffer, atoi(cle)); break;
            case 4: dechiffrement_xor(buffer, cle[0]); break;
            case 6: dechiffrement_vigenere(buffer, cle); break;
        }
        fwrite(buffer, 1, bytes, temp);
    }
    fclose(in);

    rewind(temp);
    z_stream strm = {0};
    inflateInit(&strm);
    FILE *out = fopen(output_file, "wb");
    while ((bytes = fread(buffer, 1, BUFFER_SIZE, temp)) > 0) {
        strm.next_in = (Bytef *)buffer;
        strm.avail_in = bytes;
        do {
            strm.next_out = (Bytef *)buffer;
            strm.avail_out = BUFFER_SIZE;
            inflate(&strm, Z_NO_FLUSH);
            fwrite(buffer, 1, BUFFER_SIZE - strm.avail_out, out);
        } while (strm.avail_out == 0);
    }
    inflateEnd(&strm);
    fclose(temp);
    fclose(out);
    printf("Fichier dechiffre et decompresse\n");
}

void encrypt_file(const char *input_file, const char *output_file, int algo, const char *cle) {
    compress_and_encrypt(input_file, output_file, algo, cle);
}

void decrypt_file(const char *input_file, const char *output_file, int algo, const char *cle) {
    decrypt_and_decompress(input_file, output_file, algo, cle);
}

unsigned int simple_hash(const char *str) {
    unsigned int hash = 0;
    for (int i = 0; str[i]; i++) hash = (hash * 31) + str[i];
    return hash;
}

void generate_custom_key(char *key, int len, const char *type) {
    char filename[MAX_MSG];
    snprintf(filename, MAX_MSG, "bin%skeys%skey_%d_%s.txt", SLASH, SLASH, len, type);
#ifdef _WIN32
    system("mkdir bin\\keys 2>nul");
#else
    mkdir("bin/keys", 0755);
#endif

    FILE *check = fopen(filename, "r");
    if (check) {
        fclose(check);
        printf("Fichier %s existe deja.\n", filename);
        return;
    }

    if (strcmp(type, "secure") == 0) {
        len = AES_KEY_SIZE;
#ifdef _WIN32
        HCRYPTPROV hCryptProv;
        if (CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
            CryptGenRandom(hCryptProv, len, (BYTE *)key);
            CryptReleaseContext(hCryptProv, 0);
        }
#else
        FILE *f = fopen("/dev/urandom", "r");
        fread(key, 1, len, f);
        fclose(f);
#endif
        for (int i = 0; i < len; i++) key[i] = (unsigned char)key[i] % 95 + 32;
    } else {
#ifdef _WIN32
        HCRYPTPROV hCryptProv;
        if (CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
            CryptGenRandom(hCryptProv, len, (BYTE *)key);
            CryptReleaseContext(hCryptProv, 0);
        }
#else
        FILE *f = fopen("/dev/urandom", "r");
        fread(key, 1, len, f);
        fclose(f);
#endif
        for (int i = 0; i < len; i++) {
            if (strcmp(type, "letters") == 0) key[i] = 'A' + (unsigned char)key[i] % 26;
            else if (strcmp(type, "numbers") == 0) key[i] = '0' + (unsigned char)key[i] % 10;
            else key[i] = (unsigned char)key[i] % 95 + 32;
        }
    }
    key[len] = '\0';
    printf("Cle generee : %s\n", key);

    FILE *file = fopen(filename, "w");
    if (file) {
        fprintf(file, "Cle (%s) : %s\n", type, key);
        fclose(file);
        printf("Cle sauvegardee dans %s\n", filename);
    }
}

typedef struct {
    char input[MAX_MSG];
    char output[MAX_MSG];
    int algo;
    char cle[MAX_MSG];
} BatchArgs;

#ifdef _WIN32
DWORD WINAPI batch_thread(LPVOID arg) {
    BatchArgs *args = (BatchArgs *)arg;
    encrypt_file(args->input, args->output, args->algo, args->cle);
    free(args);
    return 0;
}
#endif

void batch_encrypt(const char *algo_str, const char *cle, int max_threads) {
    int algo = atoi(algo_str);
#ifdef _WIN32
    WIN32_FIND_DATA fd;
    HANDLE hFind = FindFirstFile("bin\\input_files\\*.*", &fd);
    HANDLE *threads = malloc(max_threads * sizeof(HANDLE));
    int thread_count = 0;

    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                BatchArgs *args = malloc(sizeof(BatchArgs));
                snprintf(args->input, MAX_MSG, "bin\\input_files\\%s", fd.cFileName);
                snprintf(args->output, MAX_MSG, "bin\\output\\%s_enc", fd.cFileName);
                args->algo = algo;
                strncpy(args->cle, cle, MAX_MSG);
                threads[thread_count] = CreateThread(NULL, 0, batch_thread, args, 0, NULL);
                thread_count++;
                if (thread_count >= max_threads) {
                    WaitForMultipleObjects(thread_count, threads, TRUE, INFINITE);
                    for (int i = 0; i < thread_count; i++) CloseHandle(threads[i]);
                    thread_count = 0;
                }
            }
        } while (FindNextFile(hFind, &fd));
        FindClose(hFind);
        if (thread_count > 0) {
            WaitForMultipleObjects(thread_count, threads, TRUE, INFINITE);
            for (int i = 0; i < thread_count; i++) CloseHandle(threads[i]);
        }
        free(threads);
    }
#else
    DIR *dir = opendir("bin/input_files");
    struct dirent *entry;
    if (dir) {
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_type == DT_REG) {
                char input[MAX_MSG], output[MAX_MSG];
                snprintf(input, MAX_MSG, "bin/input_files/%s", entry->d_name);
                snprintf(output, MAX_MSG, "bin/output/%s_enc", entry->d_name);
                encrypt_file(input, output, algo, cle);
            }
        }
        closedir(dir);
    }
#endif
}

void add_to_history(const char *action, const char *result) {
    if (history_count < MAX_HISTORY) {
        strncpy(history[history_count].action, action, 50);
        strncpy(history[history_count].result, result, MAX_MSG);
        history_count++;
    } else {
        for (int i = 1; i < MAX_HISTORY; i++) history[i - 1] = history[i];
        strncpy(history[MAX_HISTORY - 1].action, action, 50);
        strncpy(history[MAX_HISTORY - 1].result, result, MAX_MSG);
    }
    save_history();
    log_action(action);
}

void load_history() {
    FILE *file = fopen("bin" SLASH "history.txt", "r");
    if (!file) return;
    char line[512];
    history_count = 0;
    while (fgets(line, sizeof(line), file) && history_count < MAX_HISTORY) {
        char *colon = strchr(line, ':');
        if (colon) {
            *colon = '\0';
            strncpy(history[history_count].action, line, 50);
            strncpy(history[history_count].result, colon + 2, MAX_MSG);
            history[history_count].result[strcspn(history[history_count].result, "\n")] = 0;
            history_count++;
        }
    }
    fclose(file);
}

void save_history() {
    FILE *file = fopen("bin" SLASH "history.txt", "w");
    if (file) {
        for (int i = 0; i < history_count; i++) {
            fprintf(file, "%s: %s\n", history[i].action, history[i].result);
        }
        fclose(file);
    }
}

void show_history() {
    printf("\nHistorique des actions :\n");
    for (int i = 0; i < history_count; i++) {
        printf("%d. %s : %s\n", i + 1, history[i].action, history[i].result);
    }
}

int guess_cesar_key(const char *ciphertext) {
    int freq[26] = {0}, total = 0, max_freq = 0, max_letter = 0;
    for (int i = 0; ciphertext[i]; i++) {
        if (isalpha(ciphertext[i])) {
            freq[toupper(ciphertext[i]) - 'A']++;
            total++;
        }
    }
    for (int i = 0; i < 26; i++) {
        if (freq[i] > max_freq) {
            max_freq = freq[i];
            max_letter = i;
        }
    }
    return (max_letter - ('E' - 'A') + 26) % 26;
}

void brute_force_cesar(const char *ciphertext) {
    char temp[MAX_MSG];
    for (int key = 1; key <= 25; key++) {
        strcpy(temp, ciphertext);
        dechiffrement_cesar(temp, key);
        printf("Cle %d : %s\n", key, temp);
    }
}

int detect_algorithm(const char *ciphertext) {
    size_t len = strlen(ciphertext);
    if (len % 4 == 0 && strspn(ciphertext, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=") == len) return 9; // Base64
    int freq[26] = {0};
    for (int i = 0; ciphertext[i]; i++) if (isalpha(ciphertext[i])) freq[toupper(ciphertext[i]) - 'A']++;
    int max_freq = 0;
    for (int i = 0; i < 26; i++) if (freq[i] > max_freq) max_freq = freq[i];
    if (max_freq > len / 5) return 1; // César probable
    return 0; // Inconnu
}

void list_files(const char *dir) {
    printf("Fichiers dans %s :\n", dir);
#ifdef _WIN32
    WIN32_FIND_DATA fd;
    char pattern[MAX_MSG];
    snprintf(pattern, MAX_MSG, "%s\\*.*", dir);
    HANDLE hFind = FindFirstFile(pattern, &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                printf("- %s\n", fd.cFileName);
            }
        } while (FindNextFile(hFind, &fd));
        FindClose(hFind);
    }
#else
    DIR *d = opendir(dir);
    struct dirent *entry;
    if (d) {
        while ((entry = readdir(d)) != NULL) {
            if (entry->d_type == DT_REG) printf("- %s\n", entry->d_name);
        }
        closedir(d);
    }
#endif
}

void log_action(const char *action) {
    FILE *log = fopen("bin" SLASH "log.txt", "a");
    if (log) {
        time_t now = time(NULL);
        fprintf(log, "[%s] %s\n", ctime(&now), action);
        fclose(log);
    }
}

void compute_sha256(const char *input, char *output) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)input, strlen(input), hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[SHA256_DIGEST_LENGTH * 2] = '\0';
}