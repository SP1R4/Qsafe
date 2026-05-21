#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <stddef.h>
#include <stdint.h>
#include <oqs/oqs.h>

#define AES_KEY_SIZE 32
#define AES_GCM_NONCE_SIZE 12
#define AES_GCM_TAG_SIZE 16
#define AES_BLOCK_SIZE 16
#define KDF_SALT_SIZE 16
#define BUFFER_SIZE 4096
#define MAX_PATH_LENGTH 1024
#define DEFAULT_SECRET_KEY_FILE "secret_key.bin"

/* On-disk magic for Qsafe v3 files. The v3 format switched the KEM to
 * ML-KEM-1024 (FIPS 203) and the key-file format to scrypt + salt, so it is
 * intentionally incompatible with the older "CRYPTOv2" files. */
#define VERSION_HEADER "QSAFE003"
#define VERSION_HEADER_SIZE 8

typedef enum {
    CRYPTO_SUCCESS = 0,
    CRYPTO_ERR_FILE_IO = 1,
    CRYPTO_ERR_MEMORY = 2,
    CRYPTO_ERR_CRYPTO = 3,
    CRYPTO_ERR_INVALID_INPUT = 4,
    CRYPTO_ERR_INTEGRITY = 5
} crypto_error_t;

typedef struct {
    int verbose;
    int force_overwrite;
    const char *secret_key_file;
    const char *passphrase;
} crypto_config_t;

void crypto_handle_errors(void);
void crypto_print_progress_bar(size_t current, size_t total);

/* HKDF-SHA256: derive a 32-byte AES key from a high-entropy KEM shared secret. */
crypto_error_t crypto_derive_aes_key(const unsigned char *shared_secret, size_t secret_len, unsigned char *aes_key);

/* scrypt: derive a 32-byte key-wrapping key from a user passphrase + random salt.
 * Unlike HKDF this is deliberately slow/memory-hard to resist passphrase guessing. */
crypto_error_t crypto_derive_key_from_passphrase(const char *passphrase, const unsigned char *salt, unsigned char *out_key);

crypto_error_t crypto_save_secret_key(const char *filename, const unsigned char *secret_key, size_t length, const crypto_config_t *config);
unsigned char *crypto_load_secret_key(const char *filename, size_t *length, const crypto_config_t *config);
crypto_error_t crypto_encrypt_file(const char *input_filename, const char *output_filename, OQS_KEM *kem, unsigned char *aes_key, unsigned char *public_key, unsigned char *secret_key, const crypto_config_t *config);
crypto_error_t crypto_decrypt_file(const char *input_filename, const char *output_filename, OQS_KEM *kem, unsigned char *aes_key, unsigned char *public_key, unsigned char *secret_key, const crypto_config_t *config);
crypto_error_t crypto_process_directory(const char *dir_path, const char *output_dir, const char *operation, OQS_KEM *kem, unsigned char *aes_key, unsigned char *public_key, unsigned char *secret_key, const crypto_config_t *config);

#endif
