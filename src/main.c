#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <oqs/oqs.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include "crypto_utils.h"

#define PROGRAM_NAME "crypto-v2"
#define VERSION "2.0.0"

static void print_usage(const char *program_name) {
    printf("%s v%s - Post-Quantum File Encryption Tool\n", program_name, VERSION);
    printf("Usage: %s [options] <encrypt|decrypt> <input_path> <output_path> <file|dir>\n", program_name);
    printf("Options:\n");
    printf("  --help           Display this help message\n");
    printf("  --verbose        Enable verbose output\n");
    printf("  --force          Overwrite output without prompting\n");
    printf("  --key-file <path> Specify secret key file (default: %s)\n", DEFAULT_SECRET_KEY_FILE);
    printf("  --passphrase <str> Passphrase for secret key encryption\n");
    printf("Examples:\n");
    printf("  %s --passphrase mypass encrypt input.txt output.enc file\n", program_name);
    printf("  %s --verbose --passphrase mypass decrypt output.enc decrypted.txt file\n", program_name);
    printf("  %s --key-file mykey.bin --passphrase mypass encrypt input_dir output_dir dir\n", program_name);
}

static crypto_error_t parse_args(int argc, char *argv[], crypto_config_t *config, const char **operation, const char **input_path, const char **output_path, const char **input_type) {
    config->secret_key_file = DEFAULT_SECRET_KEY_FILE;
    config->verbose = 0;
    config->force_overwrite = 0;
    config->passphrase = NULL;

    int i = 1;
    while (i < argc) {
        if (strcmp(argv[i], "--help") == 0) {
            print_usage(PROGRAM_NAME);
            exit(0);
        } else if (strcmp(argv[i], "--verbose") == 0) {
            config->verbose = 1;
            i++;
        } else if (strcmp(argv[i], "--force") == 0) {
            config->force_overwrite = 1;
            i++;
        } else if (strcmp(argv[i], "--key-file") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --key-file requires a path\n");
                return CRYPTO_ERR_INVALID_INPUT;
            }
            config->secret_key_file = argv[++i];
            i++;
        } else if (strcmp(argv[i], "--passphrase") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --passphrase requires a string\n");
                return CRYPTO_ERR_INVALID_INPUT;
            }
            config->passphrase = argv[++i];
            i++;
        } else {
            break;
        }
    }

    if (argc - i != 4) {
        fprintf(stderr, "Error: Invalid number of arguments\n");
        print_usage(PROGRAM_NAME);
        return CRYPTO_ERR_INVALID_INPUT;
    }

    *operation = argv[i];
    *input_path = argv[i + 1];
    *output_path = argv[i + 2];
    *input_type = argv[i + 3];

    if (strcmp(*operation, "encrypt") != 0 && strcmp(*operation, "decrypt") != 0) {
        fprintf(stderr, "Error: Operation must be 'encrypt' or 'decrypt'\n");
        return CRYPTO_ERR_INVALID_INPUT;
    }
    if (strcmp(*input_type, "file") != 0 && strcmp(*input_type, "dir") != 0) {
        fprintf(stderr, "Error: Input type must be 'file' or 'dir'\n");
        return CRYPTO_ERR_INVALID_INPUT;
    }
    if (!config->passphrase) {
        fprintf(stderr, "Error: --passphrase is required\n");
        return CRYPTO_ERR_INVALID_INPUT;
    }

    return CRYPTO_SUCCESS;
}

int main(int argc, char *argv[]) {
    crypto_config_t config;
    const char *operation, *input_path, *output_path, *input_type;

    if (parse_args(argc, argv, &config, &operation, &input_path, &output_path, &input_type) != CRYPTO_SUCCESS) {
        return 1;
    }

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
    if (kem == NULL) {
        fprintf(stderr, "Error: Failed to initialize Kyber\n");
        return 1;
    }

    uint8_t *public_key = NULL;
    uint8_t *secret_key = NULL;
    unsigned char aes_key[AES_KEY_SIZE];
    crypto_error_t ret = CRYPTO_ERR_CRYPTO;

    if (strcmp(operation, "encrypt") == 0) {
        public_key = malloc(kem->length_public_key);
        secret_key = malloc(kem->length_secret_key);
        if (public_key == NULL || secret_key == NULL) {
            fprintf(stderr, "Error: Failed to allocate memory for keys\n");
            goto cleanup;
        }
        if (OQS_KEM_keypair(kem, public_key, secret_key) != OQS_SUCCESS) {
            fprintf(stderr, "Error: Failed to generate Kyber keypair\n");
            goto cleanup;
        }
        if (crypto_save_secret_key(config.secret_key_file, secret_key, kem->length_secret_key, &config) != CRYPTO_SUCCESS) {
            fprintf(stderr, "Error: Failed to save secret key\n");
            goto cleanup;
        }
    } else {
        size_t secret_key_len;
        secret_key = crypto_load_secret_key(config.secret_key_file, &secret_key_len, &config);
        if (secret_key == NULL || secret_key_len != kem->length_secret_key) {
            fprintf(stderr, "Error: Failed to load secret key or invalid key length\n");
            free(secret_key);
            goto cleanup;
        }
        public_key = malloc(kem->length_public_key);
        if (public_key == NULL) {
            fprintf(stderr, "Error: Failed to allocate memory for public key\n");
            free(secret_key);
            goto cleanup;
        }
    }

    if (config.verbose) {
        printf("Operation: %s\nInput: %s\nOutput: %s\nType: %s\nSecret Key File: %s\n",
               operation, input_path, output_path, input_type, config.secret_key_file);
    }

    if (strcmp(input_type, "file") == 0) {
        printf("%s the file...\n", strcmp(operation, "encrypt") == 0 ? "Encrypting" : "Decrypting");
        if (strcmp(operation, "encrypt") == 0) {
            ret = crypto_encrypt_file(input_path, output_path, kem, aes_key, public_key, secret_key, &config);
        } else {
            ret = crypto_decrypt_file(input_path, output_path, kem, aes_key, public_key, secret_key, &config);
        }
    } else {
        printf("%s files in directory...\n", strcmp(operation, "encrypt") == 0 ? "Encrypting" : "Decrypting");
        ret = crypto_process_directory(input_path, output_path, operation, kem, aes_key, public_key, secret_key, &config);
    }

    if (ret != CRYPTO_SUCCESS) {
        fprintf(stderr, "Error: Operation failed (code %d)\n", ret);
    }

cleanup:
    memset(aes_key, 0, AES_KEY_SIZE);
    if (public_key) {
        memset(public_key, 0, kem->length_public_key);
        free(public_key);
    }
    if (secret_key) {
        memset(secret_key, 0, kem->length_secret_key);
        free(secret_key);
    }
    if (kem) OQS_KEM_free(kem);
    return ret == CRYPTO_SUCCESS ? 0 : 1;
}