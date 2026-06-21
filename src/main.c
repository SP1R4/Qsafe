#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <termios.h>
#include <sys/stat.h>
#include <oqs/oqs.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include "crypto_utils.h"

#define PROGRAM_NAME "qsafe"
#define VERSION "4.0.0"
#define MAX_PASSPHRASE 1024

static void print_usage(void) {
    printf("%s v%s - Post-Quantum File Encryption Tool\n\n", PROGRAM_NAME, VERSION);
    printf("Usage:\n");
    printf("  %s keygen [options]\n", PROGRAM_NAME);
    printf("  %s encrypt [options] <input> [output]\n", PROGRAM_NAME);
    printf("  %s decrypt [options] <input> [output]\n", PROGRAM_NAME);
    printf("\n");
    printf("Commands:\n");
    printf("  keygen     Generate a new ML-KEM-1024 keypair (run this once)\n");
    printf("  encrypt    Encrypt a file or directory using the public key\n");
    printf("  decrypt    Decrypt a file or directory using the secret key\n");
    printf("\n");
    printf("Files vs. directories are detected automatically. Use '-' as the input\n");
    printf("or output to read from stdin / write to stdout.\n");
    printf("\n");
    printf("Options:\n");
    printf("  --key-file <path>       Secret key file (default: %s)\n", DEFAULT_SECRET_KEY_FILE);
    printf("  --pub-file <path>       Public key file (default: <key-file>%s)\n", PUBLIC_KEY_SUFFIX);
    printf("  --passphrase <str>      Passphrase (discouraged; visible to other users)\n");
    printf("  --passphrase-file <p>   Read the passphrase from the first line of a file\n");
    printf("  --verbose               Enable verbose output\n");
    printf("  --force                 Overwrite output without prompting\n");
    printf("  --help                  Display this help message\n");
    printf("  --version               Display version information\n");
    printf("\n");
    printf("The passphrase protects the secret key only. If none is supplied via\n");
    printf("--passphrase, --passphrase-file, or $QSAFE_PASSPHRASE, you are prompted.\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s keygen\n", PROGRAM_NAME);
    printf("  %s encrypt report.pdf\n", PROGRAM_NAME);
    printf("  %s decrypt report.pdf.qsafe\n", PROGRAM_NAME);
    printf("  tar cf - ./dir | %s encrypt - backup.tar.qsafe\n", PROGRAM_NAME);
    printf("  %s encrypt ./photos                 # -> ./photos_qsafe/\n", PROGRAM_NAME);
}

/* Reads a line without echoing it, preferring the controlling terminal so it
 * works even when stdin is a pipe. Returns 1 on success. */
static int read_hidden(const char *prompt, char *buf, size_t bufsz) {
    FILE *tty = fopen("/dev/tty", "r+");
    int use_tty = (tty != NULL);
    FILE *in = use_tty ? tty : stdin;
    FILE *out = use_tty ? tty : stderr;

    fprintf(out, "%s", prompt);
    fflush(out);

    struct termios old_term, no_echo;
    int have_term = (tcgetattr(fileno(in), &old_term) == 0);
    if (have_term) {
        no_echo = old_term;
        no_echo.c_lflag &= ~(tcflag_t)ECHO;
        tcsetattr(fileno(in), TCSAFLUSH, &no_echo);
    }

    char *r = fgets(buf, (int)bufsz, in);

    if (have_term) {
        tcsetattr(fileno(in), TCSAFLUSH, &old_term);
    }
    fprintf(out, "\n");
    if (use_tty) fclose(tty);

    if (!r) return 0;
    size_t l = strlen(buf);
    if (l > 0 && buf[l - 1] == '\n') buf[l - 1] = '\0';
    return 1;
}

/* Resolves the passphrase into buf and points config->passphrase at it (or, for
 * --passphrase, at argv directly). confirm=1 prompts twice and compares. */
static crypto_error_t resolve_passphrase(crypto_config_t *config, const char *cli,
                                         const char *pfile, int confirm,
                                         char *buf, size_t bufsz) {
    if (cli) {
        config->passphrase = cli;
        return CRYPTO_SUCCESS;
    }

    if (pfile) {
        FILE *f = fopen(pfile, "r");
        if (!f) {
            perror("Error opening passphrase file");
            return CRYPTO_ERR_FILE_IO;
        }
        char *r = fgets(buf, (int)bufsz, f);
        fclose(f);
        if (!r) {
            fprintf(stderr, "Error: passphrase file is empty\n");
            return CRYPTO_ERR_INVALID_INPUT;
        }
        size_t l = strlen(buf);
        if (l > 0 && buf[l - 1] == '\n') buf[l - 1] = '\0';
    } else {
        const char *env = getenv("QSAFE_PASSPHRASE");
        if (env) {
            if (strlen(env) >= bufsz) {
                fprintf(stderr, "Error: passphrase too long\n");
                return CRYPTO_ERR_INVALID_INPUT;
            }
            strcpy(buf, env);
        } else {
            if (!read_hidden("Passphrase: ", buf, bufsz)) {
                fprintf(stderr, "Error: failed to read passphrase\n");
                return CRYPTO_ERR_INVALID_INPUT;
            }
            if (confirm) {
                char again[MAX_PASSPHRASE];
                if (!read_hidden("Confirm passphrase: ", again, sizeof(again))) {
                    fprintf(stderr, "Error: failed to read passphrase\n");
                    return CRYPTO_ERR_INVALID_INPUT;
                }
                int mismatch = strcmp(buf, again) != 0;
                OPENSSL_cleanse(again, sizeof(again));
                if (mismatch) {
                    fprintf(stderr, "Error: passphrases do not match\n");
                    return CRYPTO_ERR_INVALID_INPUT;
                }
            }
        }
    }

    if (buf[0] == '\0') {
        fprintf(stderr, "Error: passphrase must not be empty\n");
        return CRYPTO_ERR_INVALID_INPUT;
    }
    config->passphrase = buf;
    return CRYPTO_SUCCESS;
}

/* Returns 1 if the path exists and is a directory. */
static int is_directory(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static int has_suffix(const char *s, const char *suffix) {
    size_t ls = strlen(s), lsuf = strlen(suffix);
    return ls >= lsuf && strcmp(s + ls - lsuf, suffix) == 0;
}

/* Computes a sensible default output path when the user omits one. Writes into
 * out (size outsz). */
static void default_output(const char *input, const char *operation, int is_dir, char *out, size_t outsz) {
    if (strcmp(input, "-") == 0) {
        snprintf(out, outsz, "-");
        return;
    }

    /* Trim a single trailing slash from directory inputs for cleaner names. */
    char trimmed[MAX_PATH_LENGTH];
    snprintf(trimmed, sizeof(trimmed), "%s", input);
    size_t tl = strlen(trimmed);
    if (tl > 1 && trimmed[tl - 1] == '/') trimmed[tl - 1] = '\0';

    if (strcmp(operation, "encrypt") == 0) {
        snprintf(out, outsz, "%s%s", trimmed, is_dir ? "_qsafe" : ".qsafe");
    } else {
        if (is_dir) {
            if (has_suffix(trimmed, "_qsafe")) {
                size_t n = strlen(trimmed) - strlen("_qsafe");
                snprintf(out, outsz, "%.*s", (int)n, trimmed);
            } else {
                snprintf(out, outsz, "%s_decrypted", trimmed);
            }
        } else if (has_suffix(trimmed, ".qsafe")) {
            size_t n = strlen(trimmed) - strlen(".qsafe");
            snprintf(out, outsz, "%.*s", (int)n, trimmed);
        } else {
            snprintf(out, outsz, "%s.dec", trimmed);
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    crypto_config_t config;
    config.verbose = 0;
    config.force_overwrite = 0;
    config.secret_key_file = DEFAULT_SECRET_KEY_FILE;
    config.public_key_file = NULL;
    config.passphrase = NULL;

    const char *command = NULL;
    const char *cli_passphrase = NULL;
    const char *passphrase_file = NULL;
    const char *pub_file_opt = NULL;
    const char *positionals[2] = { NULL, NULL };
    int npos = 0;

    /* Options may appear before or after the command; the first non-option
     * token is the command, the rest are positional arguments. */
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--help") == 0 || strcmp(a, "-h") == 0) {
            print_usage();
            return 0;
        } else if (strcmp(a, "--version") == 0) {
            printf("%s %s\n", PROGRAM_NAME, VERSION);
            return 0;
        } else if (strcmp(a, "--verbose") == 0) {
            config.verbose = 1;
        } else if (strcmp(a, "--force") == 0) {
            config.force_overwrite = 1;
        } else if (strcmp(a, "--key-file") == 0) {
            if (++i >= argc) { fprintf(stderr, "Error: --key-file requires a path\n"); return 1; }
            config.secret_key_file = argv[i];
        } else if (strcmp(a, "--pub-file") == 0) {
            if (++i >= argc) { fprintf(stderr, "Error: --pub-file requires a path\n"); return 1; }
            pub_file_opt = argv[i];
        } else if (strcmp(a, "--passphrase") == 0) {
            if (++i >= argc) { fprintf(stderr, "Error: --passphrase requires a string\n"); return 1; }
            cli_passphrase = argv[i];
        } else if (strcmp(a, "--passphrase-file") == 0) {
            if (++i >= argc) { fprintf(stderr, "Error: --passphrase-file requires a path\n"); return 1; }
            passphrase_file = argv[i];
        } else if (a[0] == '-' && a[1] == '-') {
            fprintf(stderr, "Error: unknown option '%s'\n", a);
            return 1;
        } else if (command == NULL) {
            if (strcmp(a, "help") == 0) { print_usage(); return 0; }
            if (strcmp(a, "version") == 0) { printf("%s %s\n", PROGRAM_NAME, VERSION); return 0; }
            command = a;
        } else {
            if (npos >= 2) {
                fprintf(stderr, "Error: too many arguments\n");
                return 1;
            }
            positionals[npos++] = a;
        }
    }

    if (command == NULL) {
        print_usage();
        return 1;
    }

    int is_keygen = strcmp(command, "keygen") == 0;
    int is_encrypt = strcmp(command, "encrypt") == 0;
    int is_decrypt = strcmp(command, "decrypt") == 0;
    if (!is_keygen && !is_encrypt && !is_decrypt) {
        fprintf(stderr, "Error: unknown command '%s'\n\n", command);
        print_usage();
        return 1;
    }

    /* Resolve the public key file path (default: <secret-key>.pub). */
    char pub_path[MAX_PATH_LENGTH];
    if (pub_file_opt) {
        snprintf(pub_path, sizeof(pub_path), "%s", pub_file_opt);
    } else {
        snprintf(pub_path, sizeof(pub_path), "%s%s", config.secret_key_file, PUBLIC_KEY_SUFFIX);
    }
    config.public_key_file = pub_path;

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
    if (kem == NULL) {
        fprintf(stderr, "Error: Failed to initialize ML-KEM-1024\n");
        return 1;
    }

    char passbuf[MAX_PASSPHRASE];
    memset(passbuf, 0, sizeof(passbuf));
    uint8_t *public_key = NULL;
    uint8_t *secret_key = NULL;
    unsigned char aes_key[AES_KEY_SIZE];
    crypto_error_t ret = CRYPTO_ERR_CRYPTO;

    /* ---------------- keygen ---------------- */
    if (is_keygen) {
        if (npos != 0) {
            fprintf(stderr, "Error: keygen takes no positional arguments\n");
            ret = CRYPTO_ERR_INVALID_INPUT;
            goto cleanup;
        }
        if (resolve_passphrase(&config, cli_passphrase, passphrase_file, 1, passbuf, sizeof(passbuf)) != CRYPTO_SUCCESS) {
            ret = CRYPTO_ERR_INVALID_INPUT;
            goto cleanup;
        }

        public_key = malloc(kem->length_public_key);
        secret_key = malloc(kem->length_secret_key);
        if (!public_key || !secret_key) {
            fprintf(stderr, "Error: Failed to allocate memory for keys\n");
            ret = CRYPTO_ERR_MEMORY;
            goto cleanup;
        }
        if (OQS_KEM_keypair(kem, public_key, secret_key) != OQS_SUCCESS) {
            fprintf(stderr, "Error: Failed to generate ML-KEM keypair\n");
            goto cleanup;
        }
        if (crypto_save_secret_key(config.secret_key_file, secret_key, kem->length_secret_key, &config) != CRYPTO_SUCCESS) {
            fprintf(stderr, "Error: Failed to save secret key\n");
            goto cleanup;
        }
        if (crypto_save_public_key(config.public_key_file, public_key, kem->length_public_key, &config) != CRYPTO_SUCCESS) {
            fprintf(stderr, "Error: Failed to save public key\n");
            goto cleanup;
        }
        printf("Keypair generated:\n");
        printf("  secret key: %s (passphrase-protected)\n", config.secret_key_file);
        printf("  public key: %s\n", config.public_key_file);
        ret = CRYPTO_SUCCESS;
        goto cleanup;
    }

    /* ------------- encrypt / decrypt ------------- */
    if (npos < 1) {
        fprintf(stderr, "Error: %s requires an input path\n", command);
        ret = CRYPTO_ERR_INVALID_INPUT;
        goto cleanup;
    }
    const char *input_path = positionals[0];
    int is_stream = strcmp(input_path, "-") == 0;
    int is_dir = !is_stream && is_directory(input_path);

    if (!is_stream && !is_dir) {
        struct stat st;
        if (stat(input_path, &st) != 0) {
            fprintf(stderr, "Error: input '%s' does not exist\n", input_path);
            ret = CRYPTO_ERR_INVALID_INPUT;
            goto cleanup;
        }
    }

    char output_buf[MAX_PATH_LENGTH];
    const char *output_path;
    if (positionals[1]) {
        output_path = positionals[1];
    } else {
        default_output(input_path, command, is_dir, output_buf, sizeof(output_buf));
        output_path = output_buf;
    }
    if (is_dir && strcmp(output_path, "-") == 0) {
        fprintf(stderr, "Error: cannot stream a directory to stdout\n");
        ret = CRYPTO_ERR_INVALID_INPUT;
        goto cleanup;
    }

    if (is_encrypt) {
        public_key = crypto_load_public_key(config.public_key_file, kem->length_public_key, &config);
        if (!public_key) {
            fprintf(stderr, "Error: could not load public key '%s'. Run '%s keygen' first.\n",
                    config.public_key_file, PROGRAM_NAME);
            ret = CRYPTO_ERR_FILE_IO;
            goto cleanup;
        }
    } else {
        if (resolve_passphrase(&config, cli_passphrase, passphrase_file, 0, passbuf, sizeof(passbuf)) != CRYPTO_SUCCESS) {
            ret = CRYPTO_ERR_INVALID_INPUT;
            goto cleanup;
        }
        size_t secret_key_len;
        secret_key = crypto_load_secret_key(config.secret_key_file, &secret_key_len, &config);
        if (secret_key == NULL || secret_key_len != kem->length_secret_key) {
            fprintf(stderr, "Error: Failed to load secret key or invalid key length\n");
            free(secret_key);
            secret_key = NULL;
            ret = CRYPTO_ERR_FILE_IO;
            goto cleanup;
        }
    }

    if (config.verbose) {
        fprintf(stderr, "Operation: %s\nInput: %s\nOutput: %s\nType: %s\n",
                command, input_path, output_path, is_dir ? "dir" : "file");
    }

    if (is_dir) {
        fprintf(stderr, "%s files in directory...\n", is_encrypt ? "Encrypting" : "Decrypting");
        ret = crypto_process_directory(input_path, output_path, command, kem, aes_key, public_key, secret_key, &config);
    } else {
        if (is_encrypt) {
            ret = crypto_encrypt_file(input_path, output_path, kem, aes_key, public_key, secret_key, &config);
        } else {
            ret = crypto_decrypt_file(input_path, output_path, kem, aes_key, public_key, secret_key, &config);
        }
    }

    if (ret != CRYPTO_SUCCESS) {
        fprintf(stderr, "Error: Operation failed (code %d)\n", ret);
    } else if (!is_stream && strcmp(output_path, "-") != 0) {
        fprintf(stderr, "Done -> %s\n", output_path);
    }

cleanup:
    OPENSSL_cleanse(passbuf, sizeof(passbuf));
    OPENSSL_cleanse(aes_key, AES_KEY_SIZE);
    if (public_key) {
        OPENSSL_cleanse(public_key, kem->length_public_key);
        free(public_key);
    }
    if (secret_key) {
        OPENSSL_cleanse(secret_key, kem->length_secret_key);
        free(secret_key);
    }
    if (kem) OQS_KEM_free(kem);
    return ret == CRYPTO_SUCCESS ? 0 : 1;
}
