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
#define PUBLIC_KEY_SUFFIX ".pub"

/* On-disk magic for Qsafe v4 files.
 *
 * v4 changes versus v3:
 *   - True public-key workflow: keys are generated once with `keygen`; encrypt
 *     uses only the public key, decrypt only the (passphrase-wrapped) secret key.
 *   - The AES-GCM nonce moved to the front of the file so decryption can stream
 *     straight from a pipe (no seek-to-end required); the tag is recovered by
 *     holding back the final 16 bytes of the stream.
 *   - A fixed-size, encrypted+authenticated metadata block (original name, mode,
 *     mtime) is prepended to the plaintext so decrypt can restore the file.
 *
 * v4 is intentionally incompatible with older QSAFE003 / CRYPTOv2 files. */
#define VERSION_HEADER "QSAFE004"
#define VERSION_HEADER_SIZE 8

/* Fixed-size metadata block prepended to the plaintext before encryption.
 * Layout (little-endian, total QSAFE_META_SIZE bytes):
 *   u8   flags        (bit 0: metadata present)
 *   u8   reserved
 *   u16  name_len     (<= QSAFE_MAX_NAME)
 *   u8   name[256]    (name_len valid bytes; remainder zero)
 *   u32  mode         (st_mode & 0777)
 *   u64  mtime        (seconds since epoch) */
#define QSAFE_MAX_NAME 255
#define QSAFE_META_NAME_FIELD 256
#define QSAFE_META_SIZE (1 + 1 + 2 + QSAFE_META_NAME_FIELD + 4 + 8) /* 272 */

#define QSAFE_META_FLAG_PRESENT 0x01

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
    const char *public_key_file;
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

/* Public keys are stored in the clear (raw bytes); no passphrase is involved. */
crypto_error_t crypto_save_public_key(const char *filename, const unsigned char *public_key, size_t length, const crypto_config_t *config);
unsigned char *crypto_load_public_key(const char *filename, size_t expected_length, const crypto_config_t *config);

crypto_error_t crypto_encrypt_file(const char *input_filename, const char *output_filename, OQS_KEM *kem, unsigned char *aes_key, unsigned char *public_key, unsigned char *secret_key, const crypto_config_t *config);
crypto_error_t crypto_decrypt_file(const char *input_filename, const char *output_filename, OQS_KEM *kem, unsigned char *aes_key, unsigned char *public_key, unsigned char *secret_key, const crypto_config_t *config);
crypto_error_t crypto_process_directory(const char *dir_path, const char *output_dir, const char *operation, OQS_KEM *kem, unsigned char *aes_key, unsigned char *public_key, unsigned char *secret_key, const crypto_config_t *config);

#endif
