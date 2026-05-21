#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <dirent.h>
#include <sys/stat.h>
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

    printf("[");
    for (int i = 0; i < bar_width; ++i) {
        if (i < pos) printf("=");
        else if (i == pos) printf(">");
        else printf(" ");
    }
    printf("] %d%%\r", (int)(progress * 100));
    fflush(stdout);
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
 * With --force, or when the path does not exist yet, this always returns 1. */
static int crypto_should_write(const char *path, const crypto_config_t *config) {
    if (config->force_overwrite) {
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
    unsigned char nonce[AES_GCM_NONCE_SIZE];
    unsigned char tag[AES_GCM_TAG_SIZE];

    in_file = fopen(input_filename, "rb");
    if (!in_file) {
        perror("Error opening input file");
        return CRYPTO_ERR_FILE_IO;
    }

    if (fseek(in_file, 0, SEEK_END) != 0) {
        ret = CRYPTO_ERR_FILE_IO;
        goto cleanup;
    }
    long fs = ftell(in_file);
    rewind(in_file);
    if (fs < 0) {
        ret = CRYPTO_ERR_FILE_IO;
        goto cleanup;
    }
    size_t file_size = (size_t)fs;

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

    if (config->verbose) {
        printf("AES Key: ");
        for (int i = 0; i < AES_KEY_SIZE; i++) printf("%02x", aes_key[i]);
        printf("\nNonce: ");
        for (int i = 0; i < AES_GCM_NONCE_SIZE; i++) printf("%02x", nonce[i]);
        printf("\n");
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

    /* Authenticate the version header + KEM ciphertext as additional data so a
     * swapped header or KEM ciphertext is rejected by the GCM tag. */
    if (EVP_EncryptUpdate(ctx, NULL, &len, (const unsigned char *)VERSION_HEADER, VERSION_HEADER_SIZE) != 1 ||
        EVP_EncryptUpdate(ctx, NULL, &len, ciphertext_kem, (int)kem->length_ciphertext) != 1) {
        crypto_handle_errors();
        goto cleanup;
    }

    if (!crypto_should_write(output_filename, config)) {
        printf("Skipped %s\n", output_filename);
        ret = CRYPTO_SUCCESS;
        goto cleanup;
    }

    out_file = fopen(output_filename, "wb");
    if (!out_file) {
        perror("Error opening output file");
        ret = CRYPTO_ERR_FILE_IO;
        goto cleanup;
    }
    output_created = 1;

    if (fwrite(VERSION_HEADER, 1, VERSION_HEADER_SIZE, out_file) != VERSION_HEADER_SIZE ||
        fwrite(ciphertext_kem, 1, kem->length_ciphertext, out_file) != kem->length_ciphertext) {
        fprintf(stderr, "Error: Failed to write file header\n");
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
        if (total_processed - last_report >= (1u << 20) || total_processed == file_size) {
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

    if (fwrite(nonce, 1, AES_GCM_NONCE_SIZE, out_file) != AES_GCM_NONCE_SIZE ||
        fwrite(tag, 1, AES_GCM_TAG_SIZE, out_file) != AES_GCM_TAG_SIZE) {
        fprintf(stderr, "Error: Failed to write nonce or tag\n");
        ret = CRYPTO_ERR_FILE_IO;
        goto cleanup;
    }
    if (file_size > 0) {
        printf("\n");
    }

    ret = CRYPTO_SUCCESS;

cleanup:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (in_file) fclose(in_file);
    if (out_file) fclose(out_file);
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

crypto_error_t crypto_decrypt_file(const char *input_filename, const char *output_filename, OQS_KEM *kem, unsigned char *aes_key, unsigned char *public_key, unsigned char *secret_key, const crypto_config_t *config) {
    (void)public_key; /* not needed for decryption */

    crypto_error_t ret = CRYPTO_ERR_CRYPTO;
    uint8_t *ciphertext_kem = NULL;
    uint8_t *shared_secret = NULL;
    unsigned char *in_buffer = NULL;
    unsigned char *out_buffer = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    FILE *in_file = NULL;
    FILE *out_file = NULL;
    int output_created = 0;
    unsigned char nonce[AES_GCM_NONCE_SIZE];
    unsigned char tag[AES_GCM_TAG_SIZE];
    char header[VERSION_HEADER_SIZE];

    in_file = fopen(input_filename, "rb");
    if (!in_file) {
        perror("Error opening input file");
        return CRYPTO_ERR_FILE_IO;
    }

    if (fseek(in_file, 0, SEEK_END) != 0) {
        ret = CRYPTO_ERR_FILE_IO;
        goto cleanup;
    }
    long fs = ftell(in_file);
    if (fs < 0) {
        ret = CRYPTO_ERR_FILE_IO;
        goto cleanup;
    }
    size_t file_size = (size_t)fs;

    size_t min_size = VERSION_HEADER_SIZE + kem->length_ciphertext + AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE;
    if (file_size < min_size) {
        fprintf(stderr, "Error: Invalid encrypted file (size %zu, expected >= %zu)\n", file_size, min_size);
        ret = CRYPTO_ERR_INVALID_INPUT;
        goto cleanup;
    }
    size_t aes_len = file_size - min_size;

    ciphertext_kem = malloc(kem->length_ciphertext);
    in_buffer = malloc(BUFFER_SIZE);
    out_buffer = malloc(BUFFER_SIZE + AES_BLOCK_SIZE);
    shared_secret = malloc(kem->length_shared_secret);
    if (!ciphertext_kem || !in_buffer || !out_buffer || !shared_secret) {
        fprintf(stderr, "Error: Failed to allocate memory\n");
        ret = CRYPTO_ERR_MEMORY;
        goto cleanup;
    }

    /* Header + KEM ciphertext live at the front of the file. */
    rewind(in_file);
    if (fread(header, 1, VERSION_HEADER_SIZE, in_file) != VERSION_HEADER_SIZE ||
        memcmp(header, VERSION_HEADER, VERSION_HEADER_SIZE) != 0) {
        fprintf(stderr, "Error: Invalid file format or version\n");
        ret = CRYPTO_ERR_INVALID_INPUT;
        goto cleanup;
    }
    if (fread(ciphertext_kem, 1, kem->length_ciphertext, in_file) != kem->length_ciphertext) {
        fprintf(stderr, "Error: Failed to read KEM ciphertext\n");
        ret = CRYPTO_ERR_FILE_IO;
        goto cleanup;
    }

    /* Nonce + tag are the last 28 bytes of the file. */
    if (fseek(in_file, (long)(file_size - AES_GCM_NONCE_SIZE - AES_GCM_TAG_SIZE), SEEK_SET) != 0 ||
        fread(nonce, 1, AES_GCM_NONCE_SIZE, in_file) != AES_GCM_NONCE_SIZE ||
        fread(tag, 1, AES_GCM_TAG_SIZE, in_file) != AES_GCM_TAG_SIZE) {
        fprintf(stderr, "Error: Failed to read nonce/tag\n");
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

    if (config->verbose) {
        printf("File size: %zu bytes\n", file_size);
        printf("AES ciphertext length: %zu bytes\n", aes_len);
        printf("AES Key: ");
        for (int i = 0; i < AES_KEY_SIZE; i++) printf("%02x", aes_key[i]);
        printf("\nNonce: ");
        for (int i = 0; i < AES_GCM_NONCE_SIZE; i++) printf("%02x", nonce[i]);
        printf("\n");
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
        EVP_DecryptUpdate(ctx, NULL, &len, ciphertext_kem, (int)kem->length_ciphertext) != 1) {
        crypto_handle_errors();
        goto cleanup;
    }

    if (!crypto_should_write(output_filename, config)) {
        printf("Skipped %s\n", output_filename);
        ret = CRYPTO_SUCCESS;
        goto cleanup;
    }

    out_file = fopen(output_filename, "wb");
    if (!out_file) {
        perror("Error opening output file");
        ret = CRYPTO_ERR_FILE_IO;
        goto cleanup;
    }
    output_created = 1;

    /* Stream the AES ciphertext directly from disk: it begins right after the
     * header + KEM ciphertext and runs for aes_len bytes. */
    if (fseek(in_file, (long)(VERSION_HEADER_SIZE + kem->length_ciphertext), SEEK_SET) != 0) {
        ret = CRYPTO_ERR_FILE_IO;
        goto cleanup;
    }

    size_t remaining = aes_len;
    size_t total_processed = 0;
    size_t last_report = 0;
    while (remaining > 0) {
        size_t want = remaining < BUFFER_SIZE ? remaining : BUFFER_SIZE;
        size_t got = fread(in_buffer, 1, want, in_file);
        if (got != want) {
            fprintf(stderr, "Error: Failed to read ciphertext\n");
            ret = CRYPTO_ERR_FILE_IO;
            goto cleanup;
        }

        if (EVP_DecryptUpdate(ctx, out_buffer, &len, in_buffer, (int)got) != 1) {
            fprintf(stderr, "Error: AES-GCM decryption failed\n");
            crypto_handle_errors();
            goto cleanup;
        }

        if (len > 0 && fwrite(out_buffer, 1, len, out_file) != (size_t)len) {
            fprintf(stderr, "Error: Failed to write output file\n");
            ret = CRYPTO_ERR_FILE_IO;
            goto cleanup;
        }

        remaining -= got;
        total_processed += got;
        if (total_processed - last_report >= (1u << 20) || remaining == 0) {
            crypto_print_progress_bar(total_processed, aes_len);
            last_report = total_processed;
        }
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE, tag) != 1 ||
        EVP_DecryptFinal_ex(ctx, out_buffer, &len) != 1) {
        fprintf(stderr, "Error: Authentication failed - file corrupt or wrong key\n");
        ret = CRYPTO_ERR_INTEGRITY;
        goto cleanup;
    }
    if (len > 0 && fwrite(out_buffer, 1, len, out_file) != (size_t)len) {
        fprintf(stderr, "Error: Failed to write final chunk\n");
        ret = CRYPTO_ERR_FILE_IO;
        goto cleanup;
    }
    if (aes_len > 0) {
        printf("\n");
    }

    ret = CRYPTO_SUCCESS;

cleanup:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (in_file) fclose(in_file);
    if (out_file) fclose(out_file);
    free(in_buffer);
    free(out_buffer);
    free(ciphertext_kem);
    if (shared_secret) {
        OPENSSL_cleanse(shared_secret, kem->length_shared_secret);
        free(shared_secret);
    }
    OPENSSL_cleanse(aes_key, AES_KEY_SIZE);
    if (ret != CRYPTO_SUCCESS && output_created) {
        remove(output_filename); /* never leave behind unauthenticated plaintext */
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

    /* Resolve the key file so it is never treated as an input file. */
    char key_real[PATH_MAX];
    int have_key_real = crypto_realpath(config->secret_key_file, key_real);

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

        /* Skip the secret key file if it happens to live inside the input tree. */
        char entry_real[PATH_MAX];
        if (have_key_real && crypto_realpath(input_file_path, entry_real) &&
            strcmp(entry_real, key_real) == 0) {
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
