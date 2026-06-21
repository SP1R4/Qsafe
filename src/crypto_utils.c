#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <dirent.h>
#include <sys/stat.h>
#include <utime.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <oqs/oqs.h>
#include "crypto_utils.h"

/* Domain-separation label mixed into the HKDF expansion so the AES key derived
 * from a KEM shared secret is bound to this specific use. */
#define HKDF_INFO_LABEL "qsafe-v3-aes-key"

void crypto_handle_errors(void) {
    ERR_print_errors_fp(stderr);
}

/* Progress is drawn on stderr so it never corrupts ciphertext/plaintext that
 * may be streamed to stdout. */
void crypto_print_progress_bar(size_t current, size_t total) {
    if (total == 0) {
        return;
    }

    const int bar_width = 50;
    double progress = (double)current / (double)total;
    if (progress > 1.0) {
        progress = 1.0;
    }
    int pos = (int)(bar_width * progress);

    fprintf(stderr, "[");
    for (int i = 0; i < bar_width; ++i) {
        if (i < pos) fprintf(stderr, "=");
        else if (i == pos) fprintf(stderr, ">");
        else fprintf(stderr, " ");
    }
    fprintf(stderr, "] %d%%\r", (int)(progress * 100));
    fflush(stderr);
}

/* --- little-endian (de)serialization for the metadata block --- */

static void store_u16(unsigned char *p, uint16_t v) {
    p[0] = (unsigned char)(v & 0xff);
    p[1] = (unsigned char)((v >> 8) & 0xff);
}
static void store_u32(unsigned char *p, uint32_t v) {
    for (int i = 0; i < 4; i++) p[i] = (unsigned char)((v >> (8 * i)) & 0xff);
}
static void store_u64(unsigned char *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (unsigned char)((v >> (8 * i)) & 0xff);
}
static uint16_t load_u16(const unsigned char *p) {
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}
static uint32_t load_u32(const unsigned char *p) {
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) v |= (uint32_t)p[i] << (8 * i);
    return v;
}
static uint64_t load_u64(const unsigned char *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t)p[i] << (8 * i);
    return v;
}

/* Returns a pointer to the final path component (defends against a stored name
 * that contains directory separators). */
static const char *path_basename(const char *path) {
    const char *base = path;
    for (const char *c = path; *c; c++) {
        if (*c == '/') base = c + 1;
    }
    return base;
}

crypto_error_t crypto_derive_aes_key(const unsigned char *shared_secret, size_t secret_len, unsigned char *aes_key) {
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) {
        crypto_handle_errors();
        return CRYPTO_ERR_CRYPTO;
    }

    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!kctx) {
        crypto_handle_errors();
        return CRYPTO_ERR_CRYPTO;
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)shared_secret, secret_len),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)HKDF_INFO_LABEL, strlen(HKDF_INFO_LABEL)),
        OSSL_PARAM_construct_end()
    };

    crypto_error_t ret = CRYPTO_SUCCESS;
    if (EVP_KDF_derive(kctx, aes_key, AES_KEY_SIZE, params) != 1) {
        crypto_handle_errors();
        ret = CRYPTO_ERR_CRYPTO;
    }

    EVP_KDF_CTX_free(kctx);
    return ret;
}

crypto_error_t crypto_derive_key_from_passphrase(const char *passphrase, const unsigned char *salt, unsigned char *out_key) {
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "SCRYPT", NULL);
    if (!kdf) {
        crypto_handle_errors();
        return CRYPTO_ERR_CRYPTO;
    }

    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!kctx) {
        crypto_handle_errors();
        return CRYPTO_ERR_CRYPTO;
    }

    /* scrypt cost parameters: N=2^15, r=8, p=1 -> ~32 MiB of memory per guess.
     * maxmem_bytes is raised above the OpenSSL default so this N is permitted. */
    uint64_t n = 1ULL << 15;
    uint32_t r = 8;
    uint32_t p = 1;
    uint64_t maxmem = 1ULL << 30;

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, (void *)passphrase, strlen(passphrase)),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt, KDF_SALT_SIZE),
        OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_N, &n),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_SCRYPT_R, &r),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_SCRYPT_P, &p),
        OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_MAXMEM, &maxmem),
        OSSL_PARAM_construct_end()
    };

    crypto_error_t ret = CRYPTO_SUCCESS;
    if (EVP_KDF_derive(kctx, out_key, AES_KEY_SIZE, params) != 1) {
        crypto_handle_errors();
        ret = CRYPTO_ERR_CRYPTO;
    }

    EVP_KDF_CTX_free(kctx);
    return ret;
}

/* Returns 1 if the output file may be written, 0 if the user declined.
 * With --force, when writing to stdout, or when the path does not exist yet,
 * this always returns 1. */
static int crypto_should_write(const char *path, const crypto_config_t *config) {
    if (config->force_overwrite || strcmp(path, "-") == 0) {
        return 1;
    }

    struct stat st;
    if (stat(path, &st) != 0) {
        return 1; /* does not exist */
    }

    fprintf(stderr, "Output file '%s' already exists. Overwrite? [y/N]: ", path);
    fflush(stderr);

    int c = getchar();
    int answer = (c == 'y' || c == 'Y');
    while (c != '\n' && c != EOF) {
        c = getchar();
    }
    return answer;
}

crypto_error_t crypto_save_secret_key(const char *filename, const unsigned char *secret_key, size_t length, const crypto_config_t *config) {
    if (!config->passphrase) {
        fprintf(stderr, "Error: Passphrase required for secret key encryption\n");
        return CRYPTO_ERR_INVALID_INPUT;
    }

    crypto_error_t ret = CRYPTO_ERR_CRYPTO;
    unsigned char nonce[AES_GCM_NONCE_SIZE];
    unsigned char salt[KDF_SALT_SIZE];
    unsigned char tag[AES_GCM_TAG_SIZE];
    unsigned char key[AES_KEY_SIZE];
    unsigned char *ciphertext = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    FILE *file = NULL;

    ciphertext = malloc(length);
    if (!ciphertext) {
        ret = CRYPTO_ERR_MEMORY;
        goto cleanup;
    }

    if (RAND_bytes(nonce, AES_GCM_NONCE_SIZE) != 1 ||
        RAND_bytes(salt, KDF_SALT_SIZE) != 1) {
        fprintf(stderr, "Error: Failed to generate random salt/nonce\n");
        goto cleanup;
    }

    if (crypto_derive_key_from_passphrase(config->passphrase, salt, key) != CRYPTO_SUCCESS) {
        goto cleanup;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        goto cleanup;
    }

    int len;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1 ||
        EVP_EncryptUpdate(ctx, ciphertext, &len, secret_key, (int)length) != 1 ||
        EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE, tag) != 1) {
        crypto_handle_errors();
        goto cleanup;
    }

    if (!crypto_should_write(filename, config)) {
        fprintf(stderr, "Aborted: not overwriting %s\n", filename);
        ret = CRYPTO_ERR_FILE_IO;
        goto cleanup;
    }

    file = fopen(filename, "wb");
    if (!file) {
        perror("Error opening key file");
        ret = CRYPTO_ERR_FILE_IO;
        goto cleanup;
    }

    if (fwrite(nonce, 1, AES_GCM_NONCE_SIZE, file) != AES_GCM_NONCE_SIZE ||
        fwrite(salt, 1, KDF_SALT_SIZE, file) != KDF_SALT_SIZE ||
        fwrite(ciphertext, 1, length, file) != length ||
        fwrite(tag, 1, AES_GCM_TAG_SIZE, file) != AES_GCM_TAG_SIZE) {
        perror("Error writing key file");
        ret = CRYPTO_ERR_FILE_IO;
        goto cleanup;
    }

    /* Secret key material: restrict permissions to the owner. */
    fflush(file);
    chmod(filename, 0600);

    ret = CRYPTO_SUCCESS;

cleanup:
    if (file) fclose(file);
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (ciphertext) {
        OPENSSL_cleanse(ciphertext, length);
        free(ciphertext);
    }
    OPENSSL_cleanse(key, sizeof(key));
    return ret;
}

unsigned char *crypto_load_secret_key(const char *filename, size_t *length, const crypto_config_t *config) {
    if (!config->passphrase) {
        fprintf(stderr, "Error: Passphrase required for secret key decryption\n");
        return NULL;
    }

    unsigned char nonce[AES_GCM_NONCE_SIZE];
    unsigned char salt[KDF_SALT_SIZE];
    unsigned char tag[AES_GCM_TAG_SIZE];
    unsigned char key[AES_KEY_SIZE];
    unsigned char *ciphertext = NULL;
    unsigned char *plaintext = NULL;
    unsigned char *result = NULL;
    EVP_CIPHER_CTX *ctx = NULL;

    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening key file");
        return NULL;
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return NULL;
    }
    long file_size = ftell(file);
    rewind(file);

    size_t overhead = AES_GCM_NONCE_SIZE + KDF_SALT_SIZE + AES_GCM_TAG_SIZE;
    if (file_size < 0 || (size_t)file_size <= overhead) {
        fprintf(stderr, "Error: Invalid key file format\n");
        fclose(file);
        return NULL;
    }

    *length = (size_t)file_size - overhead;
    ciphertext = malloc(*length);
    plaintext = malloc(*length);
    if (!ciphertext || !plaintext) {
        fclose(file);
        goto cleanup;
    }

    if (fread(nonce, 1, AES_GCM_NONCE_SIZE, file) != AES_GCM_NONCE_SIZE ||
        fread(salt, 1, KDF_SALT_SIZE, file) != KDF_SALT_SIZE ||
        fread(ciphertext, 1, *length, file) != *length ||
        fread(tag, 1, AES_GCM_TAG_SIZE, file) != AES_GCM_TAG_SIZE) {
        fprintf(stderr, "Error: Failed to read key file\n");
        fclose(file);
        goto cleanup;
    }
    fclose(file);

    if (crypto_derive_key_from_passphrase(config->passphrase, salt, key) != CRYPTO_SUCCESS) {
        goto cleanup;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        goto cleanup;
    }

    int len;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1 ||
        EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, (int)*length) != 1) {
        crypto_handle_errors();
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE, tag) != 1 ||
        EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        fprintf(stderr, "Error: Secret key decryption failed (invalid passphrase or corrupted key)\n");
        goto cleanup;
    }

    result = plaintext;
    plaintext = NULL; /* ownership transferred to caller */

cleanup:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (ciphertext) free(ciphertext);
    if (plaintext) {
        OPENSSL_cleanse(plaintext, *length);
        free(plaintext);
    }
    OPENSSL_cleanse(key, sizeof(key));
    return result;
}

crypto_error_t crypto_save_public_key(const char *filename, const unsigned char *public_key, size_t length, const crypto_config_t *config) {
    if (!crypto_should_write(filename, config)) {
        fprintf(stderr, "Aborted: not overwriting %s\n", filename);
        return CRYPTO_ERR_FILE_IO;
    }

    FILE *file = fopen(filename, "wb");
    if (!file) {
        perror("Error opening public key file");
        return CRYPTO_ERR_FILE_IO;
    }

    crypto_error_t ret = CRYPTO_SUCCESS;
    if (fwrite(public_key, 1, length, file) != length) {
        perror("Error writing public key file");
        ret = CRYPTO_ERR_FILE_IO;
    }
    fclose(file);
    return ret;
}

unsigned char *crypto_load_public_key(const char *filename, size_t expected_length, const crypto_config_t *config) {
    (void)config;

    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening public key file");
        return NULL;
    }

    unsigned char *buf = malloc(expected_length);
    if (!buf) {
        fclose(file);
        return NULL;
    }

    size_t got = fread(buf, 1, expected_length, file);
    /* Reject anything that is not exactly the expected size (one extra byte
     * means the file is longer than a valid public key). */
    int extra = (fgetc(file) != EOF);
    fclose(file);

    if (got != expected_length || extra) {
        fprintf(stderr, "Error: Invalid public key file (expected %zu bytes)\n", expected_length);
        free(buf);
        return NULL;
    }
    return buf;
}

/* --- stream open/close helpers (with '-' meaning stdin/stdout) --- */

static int is_stream_arg(const char *path) {
    return strcmp(path, "-") == 0;
}

static FILE *open_input(const char *path) {
    if (is_stream_arg(path)) return stdin;
    return fopen(path, "rb");
}

static FILE *open_output(const char *path) {
    if (is_stream_arg(path)) return stdout;
    return fopen(path, "wb");
}

static void close_stream(FILE *f) {
    if (f && f != stdin && f != stdout) fclose(f);
}

crypto_error_t crypto_encrypt_file(const char *input_filename, const char *output_filename, OQS_KEM *kem, unsigned char *aes_key, unsigned char *public_key, unsigned char *secret_key, const crypto_config_t *config) {
    (void)secret_key; /* not needed for encryption */

    crypto_error_t ret = CRYPTO_ERR_CRYPTO;
    uint8_t *ciphertext_kem = NULL;
    uint8_t *shared_secret = NULL;
    unsigned char *in_buffer = NULL;
    unsigned char *out_buffer = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    FILE *in_file = NULL;
    FILE *out_file = NULL;
    int output_created = 0;
    int from_stdin = is_stream_arg(input_filename);
    unsigned char nonce[AES_GCM_NONCE_SIZE];
    unsigned char tag[AES_GCM_TAG_SIZE];
    unsigned char meta[QSAFE_META_SIZE];

    in_file = open_input(input_filename);
    if (!in_file) {
        perror("Error opening input file");
        return CRYPTO_ERR_FILE_IO;
    }

    /* Build the metadata block. For real files we capture the original name,
     * permission bits, and mtime; for stdin there is nothing to capture. */
    memset(meta, 0, sizeof(meta));
    size_t file_size = 0;
    int have_size = 0;
    if (!from_stdin) {
        struct stat st;
        if (stat(input_filename, &st) == 0) {
            file_size = (size_t)st.st_size;
            have_size = 1;

            const char *base = path_basename(input_filename);
            size_t name_len = strlen(base);
            if (name_len > QSAFE_MAX_NAME) name_len = QSAFE_MAX_NAME;

            meta[0] = QSAFE_META_FLAG_PRESENT;
            store_u16(meta + 2, (uint16_t)name_len);
            memcpy(meta + 4, base, name_len);
            store_u32(meta + 4 + QSAFE_META_NAME_FIELD, (uint32_t)(st.st_mode & 0777));
            store_u64(meta + 4 + QSAFE_META_NAME_FIELD + 4, (uint64_t)st.st_mtime);
        }
    }

    if (RAND_bytes(nonce, AES_GCM_NONCE_SIZE) != 1) {
        fprintf(stderr, "Error: Failed to generate random nonce\n");
        goto cleanup;
    }

    ciphertext_kem = malloc(kem->length_ciphertext);
    shared_secret = malloc(kem->length_shared_secret);
    in_buffer = malloc(BUFFER_SIZE);
    out_buffer = malloc(BUFFER_SIZE + AES_BLOCK_SIZE);
    if (!ciphertext_kem || !shared_secret || !in_buffer || !out_buffer) {
        fprintf(stderr, "Error: Failed to allocate memory\n");
        ret = CRYPTO_ERR_MEMORY;
        goto cleanup;
    }

    if (OQS_KEM_encaps(kem, ciphertext_kem, shared_secret, public_key) != OQS_SUCCESS) {
        fprintf(stderr, "Error: ML-KEM encapsulation failed\n");
        goto cleanup;
    }

    if (crypto_derive_aes_key(shared_secret, kem->length_shared_secret, aes_key) != CRYPTO_SUCCESS) {
        fprintf(stderr, "Error: Failed to derive AES key\n");
        goto cleanup;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        crypto_handle_errors();
        goto cleanup;
    }

    int len;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, aes_key, nonce) != 1) {
        crypto_handle_errors();
        goto cleanup;
    }

    /* Authenticate header + nonce + KEM ciphertext as additional data so any of
     * them being swapped is rejected by the GCM tag. */
    if (EVP_EncryptUpdate(ctx, NULL, &len, (const unsigned char *)VERSION_HEADER, VERSION_HEADER_SIZE) != 1 ||
        EVP_EncryptUpdate(ctx, NULL, &len, nonce, AES_GCM_NONCE_SIZE) != 1 ||
        EVP_EncryptUpdate(ctx, NULL, &len, ciphertext_kem, (int)kem->length_ciphertext) != 1) {
        crypto_handle_errors();
        goto cleanup;
    }

    if (!crypto_should_write(output_filename, config)) {
        fprintf(stderr, "Skipped %s\n", output_filename);
        ret = CRYPTO_SUCCESS;
        goto cleanup;
    }

    out_file = open_output(output_filename);
    if (!out_file) {
        perror("Error opening output file");
        ret = CRYPTO_ERR_FILE_IO;
        goto cleanup;
    }
    output_created = !is_stream_arg(output_filename);

    /* File header: magic | nonce | KEM ciphertext. */
    if (fwrite(VERSION_HEADER, 1, VERSION_HEADER_SIZE, out_file) != VERSION_HEADER_SIZE ||
        fwrite(nonce, 1, AES_GCM_NONCE_SIZE, out_file) != AES_GCM_NONCE_SIZE ||
        fwrite(ciphertext_kem, 1, kem->length_ciphertext, out_file) != kem->length_ciphertext) {
        fprintf(stderr, "Error: Failed to write file header\n");
        ret = CRYPTO_ERR_FILE_IO;
        goto cleanup;
    }

    /* The metadata block is the first plaintext encrypted into the stream. */
    if (EVP_EncryptUpdate(ctx, out_buffer, &len, meta, QSAFE_META_SIZE) != 1) {
        fprintf(stderr, "Error: AES-GCM encryption failed\n");
        crypto_handle_errors();
        goto cleanup;
    }
    if (len > 0 && fwrite(out_buffer, 1, len, out_file) != (size_t)len) {
        fprintf(stderr, "Error: Failed to write to output file\n");
        ret = CRYPTO_ERR_FILE_IO;
        goto cleanup;
    }

    size_t total_processed = 0;
    size_t last_report = 0;
    while (1) {
        size_t bytes_read = fread(in_buffer, 1, BUFFER_SIZE, in_file);
        if (bytes_read == 0) {
            if (ferror(in_file)) {
                fprintf(stderr, "Error: Failed to read input file\n");
                ret = CRYPTO_ERR_FILE_IO;
                goto cleanup;
            }
            break;
        }

        if (EVP_EncryptUpdate(ctx, out_buffer, &len, in_buffer, (int)bytes_read) != 1) {
            fprintf(stderr, "Error: AES-GCM encryption failed\n");
            crypto_handle_errors();
            goto cleanup;
        }

        if (len > 0 && fwrite(out_buffer, 1, len, out_file) != (size_t)len) {
            fprintf(stderr, "Error: Failed to write to output file\n");
            ret = CRYPTO_ERR_FILE_IO;
            goto cleanup;
        }

        total_processed += bytes_read;
        if (have_size && (total_processed - last_report >= (1u << 20) || total_processed == file_size)) {
            crypto_print_progress_bar(total_processed, file_size);
            last_report = total_processed;
        }
    }

    if (EVP_EncryptFinal_ex(ctx, out_buffer, &len) != 1) {
        fprintf(stderr, "Error: AES-GCM encryption finalization failed\n");
        crypto_handle_errors();
        goto cleanup;
    }
    if (len > 0 && fwrite(out_buffer, 1, len, out_file) != (size_t)len) {
        fprintf(stderr, "Error: Failed to write final chunk\n");
        ret = CRYPTO_ERR_FILE_IO;
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE, tag) != 1) {
        fprintf(stderr, "Error: Failed to get GCM tag\n");
        crypto_handle_errors();
        goto cleanup;
    }

    /* The tag is the trailing 16 bytes of the stream. */
    if (fwrite(tag, 1, AES_GCM_TAG_SIZE, out_file) != AES_GCM_TAG_SIZE) {
        fprintf(stderr, "Error: Failed to write authentication tag\n");
        ret = CRYPTO_ERR_FILE_IO;
        goto cleanup;
    }
    if (have_size && file_size > 0) {
        fprintf(stderr, "\n");
    }

    ret = CRYPTO_SUCCESS;

cleanup:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    close_stream(in_file);
    close_stream(out_file);
    free(in_buffer);
    free(out_buffer);
    free(ciphertext_kem);
    if (shared_secret) {
        OPENSSL_cleanse(shared_secret, kem->length_shared_secret);
        free(shared_secret);
    }
    OPENSSL_cleanse(aes_key, AES_KEY_SIZE);
    if (ret != CRYPTO_SUCCESS && output_created) {
        remove(output_filename); /* never leave a half-written ciphertext */
    }
    return ret;
}

/* Sink that consumes decrypted plaintext: peels off the leading metadata block,
 * opens the (possibly directory-resolved) output, then streams the rest. */
typedef struct {
    int meta_done;
    size_t meta_have;
    unsigned char meta[QSAFE_META_SIZE];

    int has_meta;
    char name[QSAFE_MAX_NAME + 1];
    unsigned int mode;
    uint64_t mtime;

    FILE *out;
    int out_created;
    int to_stdout;
    int skipped;
    char out_path[MAX_PATH_LENGTH];

    const char *output_arg;
    const crypto_config_t *config;
} dec_sink_t;

/* Resolves the output path and opens it once metadata has been parsed.
 * Returns CRYPTO_SUCCESS (out opened, or user skipped) or an error code. */
static crypto_error_t dec_sink_open(dec_sink_t *s) {
    if (is_stream_arg(s->output_arg)) {
        s->to_stdout = 1;
        s->out = stdout;
        return CRYPTO_SUCCESS;
    }

    /* If the destination is an existing directory, restore into it using the
     * stored original filename. */
    struct stat st;
    if (stat(s->output_arg, &st) == 0 && S_ISDIR(st.st_mode)) {
        if (!s->has_meta || s->name[0] == '\0') {
            fprintf(stderr, "Error: output is a directory but the file has no stored name\n");
            return CRYPTO_ERR_INVALID_INPUT;
        }
        if (snprintf(s->out_path, sizeof(s->out_path), "%s/%s", s->output_arg, s->name) >= (int)sizeof(s->out_path)) {
            fprintf(stderr, "Error: resolved output path too long\n");
            return CRYPTO_ERR_INVALID_INPUT;
        }
    } else {
        if (snprintf(s->out_path, sizeof(s->out_path), "%s", s->output_arg) >= (int)sizeof(s->out_path)) {
            fprintf(stderr, "Error: output path too long\n");
            return CRYPTO_ERR_INVALID_INPUT;
        }
    }

    if (!crypto_should_write(s->out_path, s->config)) {
        fprintf(stderr, "Skipped %s\n", s->out_path);
        s->skipped = 1;
        return CRYPTO_SUCCESS;
    }

    s->out = fopen(s->out_path, "wb");
    if (!s->out) {
        perror("Error opening output file");
        return CRYPTO_ERR_FILE_IO;
    }
    s->out_created = 1;
    return CRYPTO_SUCCESS;
}

/* Feed decrypted plaintext bytes through the sink. Returns CRYPTO_SUCCESS or an
 * error code. */
static crypto_error_t dec_sink_write(dec_sink_t *s, const unsigned char *p, size_t n) {
    if (!s->meta_done) {
        size_t need = QSAFE_META_SIZE - s->meta_have;
        size_t take = n < need ? n : need;
        memcpy(s->meta + s->meta_have, p, take);
        s->meta_have += take;
        p += take;
        n -= take;

        if (s->meta_have < QSAFE_META_SIZE) {
            return CRYPTO_SUCCESS; /* still collecting metadata */
        }

        /* Parse the metadata block. */
        s->has_meta = (s->meta[0] & QSAFE_META_FLAG_PRESENT) != 0;
        if (s->has_meta) {
            uint16_t nl = load_u16(s->meta + 2);
            if (nl > QSAFE_MAX_NAME) nl = QSAFE_MAX_NAME;
            memcpy(s->name, s->meta + 4, nl);
            s->name[nl] = '\0';
            /* Reject path components in the stored name (traversal defense). */
            const char *base = path_basename(s->name);
            if (base != s->name) memmove(s->name, base, strlen(base) + 1);
            if (strcmp(s->name, "..") == 0) s->name[0] = '\0';
            s->mode = load_u32(s->meta + 4 + QSAFE_META_NAME_FIELD);
            s->mtime = load_u64(s->meta + 4 + QSAFE_META_NAME_FIELD + 4);
        }
        s->meta_done = 1;

        crypto_error_t orc = dec_sink_open(s);
        if (orc != CRYPTO_SUCCESS) return orc;
    }

    if (n == 0 || s->skipped || !s->out) {
        return CRYPTO_SUCCESS;
    }
    if (fwrite(p, 1, n, s->out) != n) {
        fprintf(stderr, "Error: Failed to write output file\n");
        return CRYPTO_ERR_FILE_IO;
    }
    return CRYPTO_SUCCESS;
}

crypto_error_t crypto_decrypt_file(const char *input_filename, const char *output_filename, OQS_KEM *kem, unsigned char *aes_key, unsigned char *public_key, unsigned char *secret_key, const crypto_config_t *config) {
    (void)public_key; /* not needed for decryption */

    crypto_error_t ret = CRYPTO_ERR_CRYPTO;
    uint8_t *ciphertext_kem = NULL;
    uint8_t *shared_secret = NULL;
    unsigned char *in_buffer = NULL;
    unsigned char *out_buffer = NULL;
    unsigned char *work = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    FILE *in_file = NULL;
    unsigned char nonce[AES_GCM_NONCE_SIZE];
    unsigned char tag[AES_GCM_TAG_SIZE];
    unsigned char hold[AES_GCM_TAG_SIZE];
    size_t holdn = 0;
    char header[VERSION_HEADER_SIZE];

    dec_sink_t sink;
    memset(&sink, 0, sizeof(sink));
    sink.output_arg = output_filename;
    sink.config = config;

    in_file = open_input(input_filename);
    if (!in_file) {
        perror("Error opening input file");
        return CRYPTO_ERR_FILE_IO;
    }

    ciphertext_kem = malloc(kem->length_ciphertext);
    in_buffer = malloc(BUFFER_SIZE);
    out_buffer = malloc(BUFFER_SIZE + AES_BLOCK_SIZE);
    work = malloc(BUFFER_SIZE + AES_GCM_TAG_SIZE);
    shared_secret = malloc(kem->length_shared_secret);
    if (!ciphertext_kem || !in_buffer || !out_buffer || !work || !shared_secret) {
        fprintf(stderr, "Error: Failed to allocate memory\n");
        ret = CRYPTO_ERR_MEMORY;
        goto cleanup;
    }

    /* Header: magic | nonce | KEM ciphertext, read straight off the stream. */
    if (fread(header, 1, VERSION_HEADER_SIZE, in_file) != VERSION_HEADER_SIZE ||
        memcmp(header, VERSION_HEADER, VERSION_HEADER_SIZE) != 0) {
        fprintf(stderr, "Error: Invalid file format or version\n");
        ret = CRYPTO_ERR_INVALID_INPUT;
        goto cleanup;
    }
    if (fread(nonce, 1, AES_GCM_NONCE_SIZE, in_file) != AES_GCM_NONCE_SIZE) {
        fprintf(stderr, "Error: Failed to read nonce\n");
        ret = CRYPTO_ERR_FILE_IO;
        goto cleanup;
    }
    if (fread(ciphertext_kem, 1, kem->length_ciphertext, in_file) != kem->length_ciphertext) {
        fprintf(stderr, "Error: Failed to read KEM ciphertext\n");
        ret = CRYPTO_ERR_FILE_IO;
        goto cleanup;
    }

    if (OQS_KEM_decaps(kem, shared_secret, ciphertext_kem, secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "Error: ML-KEM decapsulation failed\n");
        goto cleanup;
    }

    if (crypto_derive_aes_key(shared_secret, kem->length_shared_secret, aes_key) != CRYPTO_SUCCESS) {
        fprintf(stderr, "Error: Failed to derive AES key\n");
        goto cleanup;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error: Failed to create cipher context\n");
        goto cleanup;
    }

    int len;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, aes_key, nonce) != 1) {
        fprintf(stderr, "Error: Failed to initialize decryption\n");
        crypto_handle_errors();
        goto cleanup;
    }

    /* Feed the same additional data the encryptor authenticated. */
    if (EVP_DecryptUpdate(ctx, NULL, &len, (const unsigned char *)VERSION_HEADER, VERSION_HEADER_SIZE) != 1 ||
        EVP_DecryptUpdate(ctx, NULL, &len, nonce, AES_GCM_NONCE_SIZE) != 1 ||
        EVP_DecryptUpdate(ctx, NULL, &len, ciphertext_kem, (int)kem->length_ciphertext) != 1) {
        crypto_handle_errors();
        goto cleanup;
    }

    /* Stream the remaining bytes, always holding back the final 16 (the tag).
     * This works identically for files and pipes since we never seek. */
    while (1) {
        size_t bytes_read = fread(in_buffer, 1, BUFFER_SIZE, in_file);
        if (bytes_read == 0) {
            if (ferror(in_file)) {
                fprintf(stderr, "Error: Failed to read ciphertext\n");
                ret = CRYPTO_ERR_FILE_IO;
                goto cleanup;
            }
            break; /* EOF */
        }

        /* Combine carried-over bytes with the new read, then process all but
         * the trailing 16 (which may turn out to be the tag). */
        memcpy(work, hold, holdn);
        memcpy(work + holdn, in_buffer, bytes_read);
        size_t total = holdn + bytes_read;

        if (total <= AES_GCM_TAG_SIZE) {
            memcpy(hold, work, total);
            holdn = total;
            continue;
        }

        size_t process = total - AES_GCM_TAG_SIZE;
        memcpy(hold, work + process, AES_GCM_TAG_SIZE);
        holdn = AES_GCM_TAG_SIZE;

        if (EVP_DecryptUpdate(ctx, out_buffer, &len, work, (int)process) != 1) {
            fprintf(stderr, "Error: AES-GCM decryption failed\n");
            crypto_handle_errors();
            goto cleanup;
        }
        if (len > 0) {
            crypto_error_t wr = dec_sink_write(&sink, out_buffer, (size_t)len);
            if (wr != CRYPTO_SUCCESS) {
                ret = wr;
                goto cleanup;
            }
        }
    }

    if (holdn != AES_GCM_TAG_SIZE) {
        fprintf(stderr, "Error: Truncated or invalid encrypted file\n");
        ret = CRYPTO_ERR_INVALID_INPUT;
        goto cleanup;
    }
    memcpy(tag, hold, AES_GCM_TAG_SIZE);

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE, tag) != 1 ||
        EVP_DecryptFinal_ex(ctx, out_buffer, &len) != 1) {
        fprintf(stderr, "Error: Authentication failed - file corrupt or wrong key\n");
        ret = CRYPTO_ERR_INTEGRITY;
        goto cleanup;
    }
    if (len > 0) {
        crypto_error_t wr = dec_sink_write(&sink, out_buffer, (size_t)len);
        if (wr != CRYPTO_SUCCESS) {
            ret = wr;
            goto cleanup;
        }
    }

    /* A valid file always carries at least the metadata block, so by now the
     * sink must have parsed it and opened (or deliberately skipped) the output. */
    if (!sink.meta_done) {
        fprintf(stderr, "Error: Encrypted file is missing its metadata block\n");
        ret = CRYPTO_ERR_INVALID_INPUT;
        goto cleanup;
    }

    ret = CRYPTO_SUCCESS;

cleanup:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    close_stream(in_file);
    if (sink.out && sink.out != stdout) fclose(sink.out);
    free(in_buffer);
    free(out_buffer);
    free(work);
    free(ciphertext_kem);
    if (shared_secret) {
        OPENSSL_cleanse(shared_secret, kem->length_shared_secret);
        free(shared_secret);
    }
    OPENSSL_cleanse(aes_key, AES_KEY_SIZE);

    if (ret == CRYPTO_SUCCESS) {
        /* Restore stored permissions and modification time on success. */
        if (sink.out_created && sink.has_meta && !sink.skipped) {
            chmod(sink.out_path, (mode_t)(sink.mode & 0777));
            struct utimbuf times;
            times.actime = (time_t)sink.mtime;
            times.modtime = (time_t)sink.mtime;
            utime(sink.out_path, &times);
        }
    } else if (sink.out_created) {
        remove(sink.out_path); /* never leave behind unauthenticated plaintext */
    }
    return ret;
}

/* Resolve a path to its canonical form. Returns 1 on success. */
static int crypto_realpath(const char *path, char *resolved) {
    return realpath(path, resolved) != NULL;
}

crypto_error_t crypto_process_directory(const char *dir_path, const char *output_dir, const char *operation, OQS_KEM *kem, unsigned char *aes_key, unsigned char *public_key, unsigned char *secret_key, const crypto_config_t *config) {
    DIR *dir = opendir(dir_path);
    if (!dir) {
        perror("Error opening directory");
        return CRYPTO_ERR_FILE_IO;
    }

    struct stat st;
    if (stat(output_dir, &st) != 0) {
        if (mkdir(output_dir, 0755) != 0) {
            perror("Error creating output directory");
            closedir(dir);
            return CRYPTO_ERR_FILE_IO;
        }
    }

    /* Resolve the key files so they are never treated as input files. */
    char key_real[PATH_MAX];
    char pub_real[PATH_MAX];
    int have_key_real = crypto_realpath(config->secret_key_file, key_real);
    int have_pub_real = config->public_key_file && crypto_realpath(config->public_key_file, pub_real);

    crypto_error_t ret = CRYPTO_SUCCESS;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char input_file_path[MAX_PATH_LENGTH];
        char output_file_path[MAX_PATH_LENGTH];
        if (snprintf(input_file_path, sizeof(input_file_path), "%s/%s", dir_path, entry->d_name) >= (int)sizeof(input_file_path) ||
            snprintf(output_file_path, sizeof(output_file_path), "%s/%s", output_dir, entry->d_name) >= (int)sizeof(output_file_path)) {
            fprintf(stderr, "Warning: path too long, skipping %s\n", entry->d_name);
            ret = CRYPTO_ERR_FILE_IO;
            continue;
        }

        if (stat(input_file_path, &st) != 0) {
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            crypto_error_t sub = crypto_process_directory(input_file_path, output_file_path, operation,
                                                          kem, aes_key, public_key, secret_key, config);
            if (sub != CRYPTO_SUCCESS) {
                ret = sub;
            }
            continue;
        }

        if (!S_ISREG(st.st_mode)) {
            continue;
        }

        /* Skip the key files if they happen to live inside the input tree. */
        char entry_real[PATH_MAX];
        if (crypto_realpath(input_file_path, entry_real) &&
            ((have_key_real && strcmp(entry_real, key_real) == 0) ||
             (have_pub_real && strcmp(entry_real, pub_real) == 0))) {
            continue;
        }

        crypto_error_t file_ret;
        if (strcmp(operation, "encrypt") == 0) {
            file_ret = crypto_encrypt_file(input_file_path, output_file_path, kem, aes_key, public_key, secret_key, config);
        } else {
            file_ret = crypto_decrypt_file(input_file_path, output_file_path, kem, aes_key, public_key, secret_key, config);
        }
        if (file_ret != CRYPTO_SUCCESS) {
            ret = file_ret;
        }
    }

    closedir(dir);
    return ret;
}
