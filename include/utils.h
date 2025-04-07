#ifndef UTILS_H
#define UTILS_H

#define MAX_MSG 512
#define MAX_HISTORY 10
#define BUFFER_SIZE 4096
#define AES_KEY_SIZE 32 

#ifdef _WIN32
#define SLASH "\\"
#else
#define SLASH "/"
#endif

typedef struct {
    char action[50];
    char result[MAX_MSG];
} HistoryEntry;

typedef struct {
    char language[10];
    char default_input_dir[MAX_MSG];
    int max_threads;
} Config;

void load_config(Config *config);
void save_config(const Config *config);
void normaliser_texte(char *texte);
void encrypt_file(const char *input_file, const char *output_file, int algo, const char *cle);
void decrypt_file(const char *input_file, const char *output_file, int algo, const char *cle);
unsigned int simple_hash(const char *str);
void generate_custom_key(char *key, int len, const char *type);
void batch_encrypt(const char *algo, const char *cle, int threads);
void add_to_history(const char *action, const char *result);
void load_history();
void save_history();
void show_history();
int guess_cesar_key(const char *ciphertext);
void brute_force_cesar(const char *ciphertext);
int detect_algorithm(const char *ciphertext);
void list_files(const char *dir);
void log_action(const char *action);
void compress_and_encrypt(const char *input_file, const char *output_file, int algo, const char *cle);
void decrypt_and_decompress(const char *input_file, const char *output_file, int algo, const char *cle);
void compute_sha256(const char *input, char *output);
int hex_to_bytes(const char *hex, unsigned char *bytes, int max_len);

#endif
