#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <oqs/oqs.h>
#include "crypto_utils.h"

void crypto_handle_errors(void) {
    ERR_print_errors_fp(stderr);
}

void crypto_print_progress_bar(size_t current, size_t total) {
    int bar_width = 50;
    float progress = (float) current / total;
    int pos = bar_width * progress;

    printf("[");
    for (int i = 0; i < bar_width; ++i) {
        if (i < pos) printf("=");
        else if (i == pos) printf(">");
        else printf(" ");
    }
    printf("] %d%%\r", (int)(progress * 100));
    fflush(stdout);
}

crypto_error_t crypto_derive_aes_key(unsigned char *shared_secret, size_t secret_len, unsigned char *aes_key) {
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx) {
        crypto_handle_errors();
        EVP_KDF_free(kdf);
        return CRYPTO_ERR_CRYPTO;
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
        OSSL_PARAM_construct_octet_string("key", shared_secret, secret_len),
        OSSL_PARAM_construct_end()
    };

    if (EVP_KDF_derive(kctx, aes_key, AES_KEY_SIZE, params) != 1) {
        crypto_handle_errors();
        EVP_KDF_CTX_free(kctx);
        EVP_KDF_free(kdf);
        return CRYPTO_ERR_CRYPTO;
    }

    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    return CRYPTO_SUCCESS;
}

crypto_error_t crypto_save_secret_key(const char *filename, unsigned char *secret_key, size_t length, const crypto_config_t *config) {
    if (!config->passphrase) {
        fprintf(stderr, "Error: Passphrase required for secret key encryption\n");
        return CRYPTO_ERR_INVALID_INPUT;
    }

    unsigned char nonce[AES_GCM_NONCE_SIZE];
    unsigned char tag[AES_GCM_TAG_SIZE];
    unsigned char *ciphertext = malloc(length);
    if (!ciphertext || RAND_bytes(nonce, AES_GCM_NONCE_SIZE) != 1) {
        free(ciphertext);
        return CRYPTO_ERR_MEMORY;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(ciphertext);
        return CRYPTO_ERR_CRYPTO;
    }

    unsigned char key[AES_KEY_SIZE];
    if (crypto_derive_aes_key((unsigned char *)config->passphrase, strlen(config->passphrase), key) != CRYPTO_SUCCESS) {
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERR_CRYPTO;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        crypto_handle_errors();
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERR_CRYPTO;
    }

    int len;
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, secret_key, length) != 1) {
        crypto_handle_errors();
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERR_CRYPTO;
    }

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        crypto_handle_errors();
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERR_CRYPTO;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE, tag) != 1) {
        crypto_handle_errors();
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERR_CRYPTO;
    }

    FILE *file = fopen(filename, "wb");
    if (!file) {
        perror("Error opening key file");
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERR_FILE_IO;
    }

    if (fwrite(nonce, 1, AES_GCM_NONCE_SIZE, file) != AES_GCM_NONCE_SIZE ||
        fwrite(ciphertext, 1, length, file) != length ||
        fwrite(tag, 1, AES_GCM_TAG_SIZE, file) != AES_GCM_TAG_SIZE) {
        perror("Error writing key file");
        fclose(file);
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERR_FILE_IO;
    }

    fclose(file);
    free(ciphertext);
    EVP_CIPHER_CTX_free(ctx);
    return CRYPTO_SUCCESS;
}

unsigned char *crypto_load_secret_key(const char *filename, size_t *length, const crypto_config_t *config) {
    if (!config->passphrase) {
        fprintf(stderr, "Error: Passphrase required for secret key decryption\n");
        return NULL;
    }

    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening key file");
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (file_size < AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE) {
        fprintf(stderr, "Error: Invalid key file format\n");
        fclose(file);
        return NULL;
    }

    unsigned char nonce[AES_GCM_NONCE_SIZE];
    unsigned char tag[AES_GCM_TAG_SIZE];
    *length = file_size - AES_GCM_NONCE_SIZE - AES_GCM_TAG_SIZE;
    unsigned char *ciphertext = malloc(*length);
    unsigned char *plaintext = malloc(*length);

    if (!ciphertext || !plaintext ||
        fread(nonce, 1, AES_GCM_NONCE_SIZE, file) != AES_GCM_NONCE_SIZE ||
        fread(ciphertext, 1, *length, file) != *length ||
        fread(tag, 1, AES_GCM_TAG_SIZE, file) != AES_GCM_TAG_SIZE) {
        free(ciphertext);
        free(plaintext);
        fclose(file);
        return NULL;
    }
    fclose(file);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(ciphertext);
        free(plaintext);
        return NULL;
    }

    unsigned char key[AES_KEY_SIZE];
    if (crypto_derive_aes_key((unsigned char *)config->passphrase, strlen(config->passphrase), key) != CRYPTO_SUCCESS) {
        free(ciphertext);
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        crypto_handle_errors();
        free(ciphertext);
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    int len;
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, *length) != 1) {
        crypto_handle_errors();
        free(ciphertext);
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE, tag) != 1 ||
        EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        fprintf(stderr, "Error: Secret key decryption failed (invalid passphrase or corrupted key)\n");
        free(ciphertext);
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    free(ciphertext);
    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

crypto_error_t crypto_write_encrypted_file(const char *filename, unsigned char *kem_ciphertext, size_t kem_len, unsigned char *aes_ciphertext, size_t aes_len, unsigned char *nonce, unsigned char *tag, const crypto_config_t *config) {
    FILE *file = fopen(filename, "wb");
    if (!file) {
        perror("Error opening output file");
        return CRYPTO_ERR_FILE_IO;
    }

    if (fwrite(VERSION_HEADER, 1, VERSION_HEADER_SIZE, file) != VERSION_HEADER_SIZE ||
        fwrite(kem_ciphertext, 1, kem_len, file) != kem_len ||
        fwrite(aes_ciphertext, 1, aes_len, file) != aes_len ||
        fwrite(nonce, 1, AES_GCM_NONCE_SIZE, file) != AES_GCM_NONCE_SIZE ||
        fwrite(tag, 1, AES_GCM_TAG_SIZE, file) != AES_GCM_TAG_SIZE) {
        perror("Error writing encrypted file");
        fclose(file);
        return CRYPTO_ERR_FILE_IO;
    }

    fclose(file);
    return CRYPTO_SUCCESS;
}

crypto_error_t crypto_read_encrypted_file(const char *filename, unsigned char *kem_ciphertext, size_t kem_len, unsigned char *aes_ciphertext, size_t aes_len, unsigned char *nonce, unsigned char *tag) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening input file");
        return CRYPTO_ERR_FILE_IO;
    }

    char version[VERSION_HEADER_SIZE];
    if (fread(version, 1, VERSION_HEADER_SIZE, file) != VERSION_HEADER_SIZE ||
        strncmp(version, VERSION_HEADER, VERSION_HEADER_SIZE) != 0) {
        fprintf(stderr, "Error: Invalid file format or version\n");
        fclose(file);
        return CRYPTO_ERR_INVALID_INPUT;
    }

    if (fread(kem_ciphertext, 1, kem_len, file) != kem_len ||
        fread(aes_ciphertext, 1, aes_len, file) != aes_len ||
        fread(nonce, 1, AES_GCM_NONCE_SIZE, file) != AES_GCM_NONCE_SIZE ||
        fread(tag, 1, AES_GCM_TAG_SIZE, file) != AES_GCM_TAG_SIZE) {
        perror("Error reading encrypted file");
        fclose(file);
        return CRYPTO_ERR_FILE_IO;
    }

    fclose(file);
    return CRYPTO_SUCCESS;
}

crypto_error_t crypto_encrypt_file(const char *input_filename, const char *output_filename, OQS_KEM *kem, unsigned char *aes_key, unsigned char *public_key, unsigned char *secret_key, const crypto_config_t *config) {
    crypto_error_t ret = CRYPTO_ERR_CRYPTO;

    FILE *in_file = fopen(input_filename, "rb");
    if (!in_file) {
        perror("Error opening input file");
        return CRYPTO_ERR_FILE_IO;
    }

    FILE *out_file = fopen(output_filename, "wb");
    if (!out_file) {
        perror("Error opening output file");
        fclose(in_file);
        return CRYPTO_ERR_FILE_IO;
    }

    unsigned char nonce[AES_GCM_NONCE_SIZE];
    unsigned char tag[AES_GCM_TAG_SIZE];
    if (RAND_bytes(nonce, AES_GCM_NONCE_SIZE) != 1) {
        fprintf(stderr, "Error: Failed to generate random nonce\n");
        fclose(in_file);
        fclose(out_file);
        return CRYPTO_ERR_CRYPTO;
    }

    uint8_t *ciphertext_kem = malloc(kem->length_ciphertext);
    uint8_t *shared_secret = malloc(kem->length_shared_secret);
    if (!ciphertext_kem || !shared_secret) {
        fprintf(stderr, "Error: Failed to allocate memory for KEM\n");
        fclose(in_file);
        fclose(out_file);
        free(ciphertext_kem);
        free(shared_secret);
        return CRYPTO_ERR_MEMORY;
    }

    if (OQS_KEM_encaps(kem, ciphertext_kem, shared_secret, public_key) != OQS_SUCCESS) {
        fprintf(stderr, "Error: Kyber encapsulation failed\n");
        fclose(in_file);
        fclose(out_file);
        free(ciphertext_kem);
        free(shared_secret);
        return CRYPTO_ERR_CRYPTO;
    }

    if (crypto_derive_aes_key(shared_secret, kem->length_shared_secret, aes_key) != CRYPTO_SUCCESS) {
        fprintf(stderr, "Error: Failed to derive AES key\n");
        fclose(in_file);
        fclose(out_file);
        free(ciphertext_kem);
        free(shared_secret);
        return CRYPTO_ERR_CRYPTO;
    }

    if (config->verbose) {
        printf("AES Key: ");
        for (int i = 0; i < AES_KEY_SIZE; i++) printf("%02x", aes_key[i]);
        printf("\nNonce: ");
        for (int i = 0; i < AES_GCM_NONCE_SIZE; i++) printf("%02x", nonce[i]);
        printf("\n");
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        crypto_handle_errors();
        fclose(in_file);
        fclose(out_file);
        free(ciphertext_kem);
        free(shared_secret);
        return CRYPTO_ERR_CRYPTO;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, aes_key, nonce) != 1) {
        crypto_handle_errors();
        EVP_CIPHER_CTX_free(ctx);
        fclose(in_file);
        fclose(out_file);
        free(ciphertext_kem);
        free(shared_secret);
        return CRYPTO_ERR_CRYPTO;
    }

    unsigned char *in_buffer = malloc(BUFFER_SIZE);
    unsigned char *out_buffer = malloc(BUFFER_SIZE + AES_BLOCK_SIZE);
    if (!in_buffer || !out_buffer) {
        fprintf(stderr, "Error: Failed to allocate memory\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(in_file);
        fclose(out_file);
        free(ciphertext_kem);
        free(shared_secret);
        free(in_buffer);
        free(out_buffer);
        return CRYPTO_ERR_MEMORY;
    }

    size_t total_processed = 0;
    fseek(in_file, 0, SEEK_END);
    size_t file_size = ftell(in_file);
    fseek(in_file, 0, SEEK_SET);

    fwrite(VERSION_HEADER, 1, VERSION_HEADER_SIZE, out_file);
    fwrite(ciphertext_kem, 1, kem->length_ciphertext, out_file);

    int len;
    while (1) {
        size_t bytes_read = fread(in_buffer, 1, BUFFER_SIZE, in_file);
        if (bytes_read == 0 && feof(in_file)) break;
        if (ferror(in_file)) {
            fprintf(stderr, "Error: Failed to read input file\n");
            goto encrypt_cleanup;
        }

        if (EVP_EncryptUpdate(ctx, out_buffer, &len, in_buffer, bytes_read) != 1) {
            fprintf(stderr, "Error: AES-GCM encryption failed (chunk size %zu)\n", bytes_read);
            crypto_handle_errors();
            goto encrypt_cleanup;
        }
        if (config->verbose) {
            printf("Encrypted chunk: %d bytes\n", len);
        }

        if (fwrite(out_buffer, 1, len, out_file) != (size_t)len) {
            fprintf(stderr, "Error: Failed to write to output file\n");
            goto encrypt_cleanup;
        }

        total_processed += bytes_read;
        if (total_processed % (1024 * 1024) == 0 || total_processed == file_size) {
            crypto_print_progress_bar(total_processed, file_size);
        }
    }

    if (EVP_EncryptFinal_ex(ctx, out_buffer, &len) != 1) {
        fprintf(stderr, "Error: AES-GCM encryption finalization failed\n");
        crypto_handle_errors();
        goto encrypt_cleanup;
    }
    if (config->verbose) {
        printf("Final chunk: %d bytes\n", len);
    }
    if (len > 0) {
        if (fwrite(out_buffer, 1, len, out_file) != (size_t)len) {
            fprintf(stderr, "Error: Failed to write final chunk to output file\n");
            goto encrypt_cleanup;
        }
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE, tag) != 1) {
        fprintf(stderr, "Error: Failed to get GCM tag\n");
        crypto_handle_errors();
        goto encrypt_cleanup;
    }

    if (fwrite(nonce, 1, AES_GCM_NONCE_SIZE, out_file) != AES_GCM_NONCE_SIZE ||
        fwrite(tag, 1, AES_GCM_TAG_SIZE, out_file) != AES_GCM_TAG_SIZE) {
        fprintf(stderr, "Error: Failed to write nonce or tag\n");
        goto encrypt_cleanup;
    }
    printf("\n");

    ret = CRYPTO_SUCCESS;

encrypt_cleanup:
    EVP_CIPHER_CTX_free(ctx);
    fclose(in_file);
    fclose(out_file);
    free(in_buffer);
    free(out_buffer);
    free(ciphertext_kem);
    memset(shared_secret, 0, kem->length_shared_secret);
    free(shared_secret);
    return ret;
}

crypto_error_t crypto_decrypt_file(const char *input_filename, const char *output_filename, OQS_KEM *kem, unsigned char *aes_key, unsigned char *public_key, unsigned char *secret_key, const crypto_config_t *config) {
    crypto_error_t ret = CRYPTO_ERR_CRYPTO;
    uint8_t *ciphertext_kem = NULL;
    unsigned char *ciphertext = NULL;
    unsigned char *nonce = NULL;
    unsigned char *tag = NULL;
    unsigned char *in_buffer = NULL;
    unsigned char *out_buffer = NULL;
    unsigned char shared_secret_buf[AES_KEY_SIZE];
    EVP_CIPHER_CTX *ctx = NULL;
    FILE *out_file = NULL;

    FILE *in_file = fopen(input_filename, "rb");
    if (!in_file) {
        perror("Error opening input file");
        return CRYPTO_ERR_FILE_IO;
    }

    fseek(in_file, 0, SEEK_END);
    size_t file_size = ftell(in_file);
    fclose(in_file);
    in_file = NULL;

    size_t min_size = VERSION_HEADER_SIZE + kem->length_ciphertext + AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE;
    if (file_size < min_size) {
        fprintf(stderr, "Error: Invalid encrypted file format (size %zu, expected >= %zu)\n",
                file_size, min_size);
        return CRYPTO_ERR_INVALID_INPUT;
    }

    size_t kem_ciphertext_len = kem->length_ciphertext;
    size_t aes_ciphertext_len = file_size - VERSION_HEADER_SIZE - kem_ciphertext_len - AES_GCM_NONCE_SIZE - AES_GCM_TAG_SIZE;

    if (config->verbose) {
        printf("File size: %zu bytes\n", file_size);
        printf("KEM ciphertext length: %zu bytes\n", kem_ciphertext_len);
        printf("AES ciphertext length: %zu bytes\n", aes_ciphertext_len);
    }

    ciphertext_kem = malloc(kem_ciphertext_len);
    ciphertext = malloc(aes_ciphertext_len);
    nonce = malloc(AES_GCM_NONCE_SIZE);
    tag = malloc(AES_GCM_TAG_SIZE);
    if (!ciphertext_kem || !ciphertext || !nonce || !tag) {
        fprintf(stderr, "Error: Failed to allocate memory\n");
        ret = CRYPTO_ERR_MEMORY;
        goto decrypt_cleanup;
    }

    ret = crypto_read_encrypted_file(input_filename, ciphertext_kem, kem_ciphertext_len, ciphertext, aes_ciphertext_len, nonce, tag);
    if (ret != CRYPTO_SUCCESS) {
        goto decrypt_cleanup;
    }

    if (OQS_KEM_decaps(kem, shared_secret_buf, ciphertext_kem, secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "Error: Kyber decapsulation failed\n");
        ret = CRYPTO_ERR_CRYPTO;
        goto decrypt_cleanup;
    }

    if (crypto_derive_aes_key(shared_secret_buf, kem->length_shared_secret, aes_key) != CRYPTO_SUCCESS) {
        fprintf(stderr, "Error: Failed to derive AES key\n");
        ret = CRYPTO_ERR_CRYPTO;
        goto decrypt_cleanup;
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
        fprintf(stderr, "Error: Failed to create cipher context\n");
        ret = CRYPTO_ERR_CRYPTO;
        goto decrypt_cleanup;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, aes_key, nonce) != 1) {
        fprintf(stderr, "Error: Failed to initialize decryption\n");
        crypto_handle_errors();
        ret = CRYPTO_ERR_CRYPTO;
        goto decrypt_cleanup;
    }

    out_file = fopen(output_filename, "wb");
    if (!out_file) {
        perror("Error opening output file");
        ret = CRYPTO_ERR_FILE_IO;
        goto decrypt_cleanup;
    }

    in_buffer = malloc(BUFFER_SIZE + AES_BLOCK_SIZE);
    out_buffer = malloc(BUFFER_SIZE + AES_BLOCK_SIZE);
    if (!in_buffer || !out_buffer) {
        fprintf(stderr, "Error: Failed to allocate memory\n");
        ret = CRYPTO_ERR_MEMORY;
        goto decrypt_cleanup;
    }

    size_t total_processed = 0;
    size_t offset = 0;
    int len;
    while (offset < aes_ciphertext_len) {
        size_t chunk_size = (aes_ciphertext_len - offset > BUFFER_SIZE) ? BUFFER_SIZE : (aes_ciphertext_len - offset);
        memcpy(in_buffer, ciphertext + offset, chunk_size);

        if (EVP_DecryptUpdate(ctx, out_buffer, &len, in_buffer, chunk_size) != 1) {
            fprintf(stderr, "Error: AES-GCM decryption failed (chunk at offset %zu, size %zu)\n", offset, chunk_size);
            crypto_handle_errors();
            ret = CRYPTO_ERR_CRYPTO;
            goto decrypt_cleanup;
        }
        if (config->verbose) {
            printf("Decrypted chunk: %d bytes\n", len);
        }

        if (fwrite(out_buffer, 1, len, out_file) != (size_t)len) {
            fprintf(stderr, "Error: Failed to write output file\n");
            ret = CRYPTO_ERR_FILE_IO;
            goto decrypt_cleanup;
        }

        total_processed += chunk_size;
        if (total_processed % (1024 * 1024) == 0 || total_processed == aes_ciphertext_len) {
            crypto_print_progress_bar(total_processed, aes_ciphertext_len);
        }
        offset += chunk_size;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE, tag) != 1 ||
        EVP_DecryptFinal_ex(ctx, out_buffer, &len) != 1) {
        fprintf(stderr, "Error: AES-GCM decryption finalization failed (authentication failure)\n");
        crypto_handle_errors();
        ret = CRYPTO_ERR_INTEGRITY;
        goto decrypt_cleanup;
    }
    if (config->verbose) {
        printf("Final chunk: %d bytes\n", len);
    }
    if (len > 0) {
        if (fwrite(out_buffer, 1, len, out_file) != (size_t)len) {
            fprintf(stderr, "Error: Failed to write final chunk to output file\n");
            ret = CRYPTO_ERR_FILE_IO;
            goto decrypt_cleanup;
        }
    }
    printf("\n");

    ret = CRYPTO_SUCCESS;

decrypt_cleanup:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (out_file) fclose(out_file);
    memset(shared_secret_buf, 0, sizeof(shared_secret_buf));
    free(ciphertext_kem);
    free(ciphertext);
    free(nonce);
    free(tag);
    free(in_buffer);
    free(out_buffer);
    return ret;
}

crypto_error_t crypto_process_directory(const char *dir_path, const char *output_dir, const char *operation, OQS_KEM *kem, unsigned char *aes_key, unsigned char *public_key, unsigned char *secret_key, const crypto_config_t *config) {
    DIR *dir;
    struct dirent *entry;
    char input_file_path[MAX_PATH_LENGTH];
    char output_file_path[MAX_PATH_LENGTH];

    dir = opendir(dir_path);
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

    crypto_error_t ret = CRYPTO_SUCCESS;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        snprintf(input_file_path, sizeof(input_file_path), "%s/%s", dir_path, entry->d_name);
        snprintf(output_file_path, sizeof(output_file_path), "%s/%s", output_dir, entry->d_name);

        if (stat(input_file_path, &st) == 0 && S_ISREG(st.st_mode)) {
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
    }

    closedir(dir);
    return ret;
}