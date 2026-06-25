/* Expose POSIX symbols (fileno, tcgetattr/tcsetattr, ...) under -std=c11,
 * which otherwise restricts glibc to strict ISO C. */
#define _DEFAULT_SOURCE

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
#define VERSION "5.0.0"
#define MAX_PASSPHRASE 1024
#define DEFAULT_SIGN_KEY_FILE "sign_key.bin"

static void print_usage(void) {
    printf("%s v%s - Post-Quantum File Encryption Tool\n\n", PROGRAM_NAME, VERSION);
    printf("Usage:\n");
    printf("  %s keygen [options]\n", PROGRAM_NAME);
    printf("  %s encrypt [options] <input> [output]\n", PROGRAM_NAME);
    printf("  %s decrypt [options] <input> [output]\n", PROGRAM_NAME);
    printf("  %s verify  [options] <input>\n", PROGRAM_NAME);
    printf("  %s rekey   [options]\n", PROGRAM_NAME);
    printf("  %s inspect <file>\n", PROGRAM_NAME);
    printf("  %s sign-keygen [options]\n", PROGRAM_NAME);
    printf("  %s sign    [options] <input> [signature]\n", PROGRAM_NAME);
    printf("  %s verify-sig [options] <input> [signature]\n", PROGRAM_NAME);
    printf("\n");
    printf("Commands:\n");
    printf("  keygen       Generate a hybrid X25519 + ML-KEM-1024 keypair (run once)\n");
    printf("  encrypt      Encrypt a file or directory to one or more public keys\n");
    printf("  decrypt      Decrypt a file or directory using the secret key\n");
    printf("  verify       Authenticate a file/directory without writing plaintext\n");
    printf("  rekey        Change the passphrase protecting a secret key\n");
    printf("  inspect      Show what a key or encrypted file is, without decrypting\n");
    printf("  sign-keygen  Generate an ML-DSA-87 signing keypair\n");
    printf("  sign         Create a detached signature for a file\n");
    printf("  verify-sig   Verify a detached signature against a file\n");
    printf("\n");
    printf("Files vs. directories are detected automatically. Use '-' as the input\n");
    printf("or output to read from stdin / write to stdout.\n");
    printf("\n");
    printf("Options:\n");
    printf("  --key-file <path>       Secret key file (default: %s)\n", DEFAULT_SECRET_KEY_FILE);
    printf("  --pub-file <path>       Public key file (default: <key-file>%s)\n", PUBLIC_KEY_SUFFIX);
    printf("  -r, --recipient <path>  encrypt: add a recipient public key (repeatable)\n");
    printf("  --passphrase <str>      Passphrase (discouraged; visible to other users)\n");
    printf("  --passphrase-file <p>   Read the passphrase from the first line of a file\n");
    printf("  --check                 decrypt/verify: authenticate only, write nothing\n");
    printf("  --armor                 encrypt: ASCII base64 output; decrypt: base64 input\n");
    printf("  --scrypt-cost <n>       keygen/rekey: scrypt cost as log2(N), 14-22 (default 15)\n");
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

/* Creates a unique temporary file path used to stage the binary container
 * while armoring/dearmoring. Returns 1 on success. */
static int make_temp_path(char *buf, size_t n) {
    const char *dir = getenv("TMPDIR");
    if (!dir || !*dir) dir = "/tmp";
    if ((size_t)snprintf(buf, n, "%s/qsafe_armor_XXXXXX", dir) >= n) return 0;
    int fd = mkstemp(buf);
    if (fd < 0) return 0;
    close(fd);
    return 1;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    crypto_config_t config;
    config.verbose = 0;
    config.force_overwrite = 0;
    config.check_only = 0;
    config.armor = 0;
    config.scrypt_n = 0; /* 0 -> library default cost */
    config.scrypt_r = 0;
    config.scrypt_p = 0;
    config.secret_key_file = DEFAULT_SECRET_KEY_FILE;
    config.public_key_file = NULL;
    config.passphrase = NULL;

    const char *command = NULL;
    const char *cli_passphrase = NULL;
    const char *passphrase_file = NULL;
    const char *pub_file_opt = NULL;
    const char *positionals[2] = { NULL, NULL };
    int npos = 0;
    int key_file_set = 0;
    const char *recipient_opts[QSAFE_MAX_RECIPIENTS];
    int n_recipient_opts = 0;

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
        } else if (strcmp(a, "--check") == 0) {
            config.check_only = 1;
        } else if (strcmp(a, "--armor") == 0) {
            config.armor = 1;
        } else if (strcmp(a, "--key-file") == 0) {
            if (++i >= argc) { fprintf(stderr, "Error: --key-file requires a path\n"); return 1; }
            config.secret_key_file = argv[i];
            key_file_set = 1;
        } else if (strcmp(a, "--recipient") == 0 || strcmp(a, "-r") == 0) {
            if (++i >= argc) { fprintf(stderr, "Error: --recipient requires a public key path\n"); return 1; }
            if (n_recipient_opts >= QSAFE_MAX_RECIPIENTS) {
                fprintf(stderr, "Error: at most %d recipients are supported\n", QSAFE_MAX_RECIPIENTS);
                return 1;
            }
            recipient_opts[n_recipient_opts++] = argv[i];
        } else if (strcmp(a, "--pub-file") == 0) {
            if (++i >= argc) { fprintf(stderr, "Error: --pub-file requires a path\n"); return 1; }
            pub_file_opt = argv[i];
        } else if (strcmp(a, "--passphrase") == 0) {
            if (++i >= argc) { fprintf(stderr, "Error: --passphrase requires a string\n"); return 1; }
            cli_passphrase = argv[i];
        } else if (strcmp(a, "--passphrase-file") == 0) {
            if (++i >= argc) { fprintf(stderr, "Error: --passphrase-file requires a path\n"); return 1; }
            passphrase_file = argv[i];
        } else if (strcmp(a, "--scrypt-cost") == 0) {
            if (++i >= argc) { fprintf(stderr, "Error: --scrypt-cost requires log2(N)\n"); return 1; }
            char *end = NULL;
            long logn = strtol(argv[i], &end, 10);
            if (end == argv[i] || *end != '\0' || logn < 14 || logn > 22) {
                fprintf(stderr, "Error: --scrypt-cost must be an integer in [14, 22]\n");
                return 1;
            }
            config.scrypt_n = 1ULL << logn;
            config.scrypt_r = SCRYPT_DEFAULT_R;
            config.scrypt_p = SCRYPT_DEFAULT_P;
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
    int is_verify = strcmp(command, "verify") == 0;
    int is_rekey = strcmp(command, "rekey") == 0;
    int is_inspect = strcmp(command, "inspect") == 0;
    int is_sign_keygen = strcmp(command, "sign-keygen") == 0;
    int is_sign = strcmp(command, "sign") == 0;
    int is_verify_sig = strcmp(command, "verify-sig") == 0;
    if (!is_keygen && !is_encrypt && !is_decrypt && !is_verify && !is_rekey &&
        !is_inspect && !is_sign_keygen && !is_sign && !is_verify_sig) {
        fprintf(stderr, "Error: unknown command '%s'\n\n", command);
        print_usage();
        return 1;
    }

    /* verify is decrypt that authenticates but writes nothing. */
    if (is_verify) {
        config.check_only = 1;
    }

    /* Signing commands use a distinct default key file so they never collide
     * with the hybrid encryption keypair. */
    if ((is_sign_keygen || is_sign || is_verify_sig) && !key_file_set) {
        config.secret_key_file = DEFAULT_SIGN_KEY_FILE;
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
    unsigned char *public_blob = NULL;   /* hybrid identity public key */
    unsigned char *secret_blob = NULL;   /* hybrid identity secret (or rekey blob) */
    size_t public_len = 0, secret_len = 0;
    unsigned char *recipient_bufs[QSAFE_MAX_RECIPIENTS];
    const unsigned char *recipient_ptrs[QSAFE_MAX_RECIPIENTS];
    size_t n_recip_loaded = 0;
    for (int i = 0; i < QSAFE_MAX_RECIPIENTS; i++) { recipient_bufs[i] = NULL; recipient_ptrs[i] = NULL; }
    crypto_error_t ret = CRYPTO_ERR_CRYPTO;

    /* ---------------- keygen (hybrid identity) ---------------- */
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
        if (crypto_generate_identity(kem, &public_blob, &public_len, &secret_blob, &secret_len) != CRYPTO_SUCCESS) {
            fprintf(stderr, "Error: Failed to generate hybrid identity\n");
            goto cleanup;
        }
        if (crypto_save_secret_key(config.secret_key_file, secret_blob, secret_len, &config) != CRYPTO_SUCCESS) {
            fprintf(stderr, "Error: Failed to save secret key\n");
            goto cleanup;
        }
        if (crypto_save_public_key(config.public_key_file, public_blob, public_len, &config) != CRYPTO_SUCCESS) {
            fprintf(stderr, "Error: Failed to save public key\n");
            goto cleanup;
        }
        printf("Hybrid keypair generated (X25519 + ML-KEM-1024):\n");
        printf("  secret key: %s (passphrase-protected)\n", config.secret_key_file);
        printf("  public key: %s\n", config.public_key_file);
        char fp[65];
        if (crypto_fingerprint(public_blob, public_len, fp, sizeof(fp)) == CRYPTO_SUCCESS) {
            printf("  fingerprint: %s\n", fp);
        }
        ret = CRYPTO_SUCCESS;
        goto cleanup;
    }

    /* ---------------- sign-keygen (ML-DSA-87) ---------------- */
    if (is_sign_keygen) {
        if (npos != 0) {
            fprintf(stderr, "Error: sign-keygen takes no positional arguments\n");
            ret = CRYPTO_ERR_INVALID_INPUT;
            goto cleanup;
        }
        if (resolve_passphrase(&config, cli_passphrase, passphrase_file, 1, passbuf, sizeof(passbuf)) != CRYPTO_SUCCESS) {
            ret = CRYPTO_ERR_INVALID_INPUT;
            goto cleanup;
        }
        ret = crypto_sig_keygen(config.secret_key_file, config.public_key_file, &config);
        if (ret == CRYPTO_SUCCESS) {
            printf("Signing keypair generated (ML-DSA-87):\n");
            printf("  secret key: %s (passphrase-protected)\n", config.secret_key_file);
            printf("  public key: %s\n", config.public_key_file);
        }
        goto cleanup;
    }

    /* ---------------- sign ---------------- */
    if (is_sign) {
        if (npos < 1) {
            fprintf(stderr, "Error: sign requires an input file\n");
            ret = CRYPTO_ERR_INVALID_INPUT;
            goto cleanup;
        }
        char sigbuf[MAX_PATH_LENGTH];
        const char *sigout;
        if (positionals[1]) {
            sigout = positionals[1];
        } else {
            snprintf(sigbuf, sizeof(sigbuf), "%s.sig", positionals[0]);
            sigout = sigbuf;
        }
        if (resolve_passphrase(&config, cli_passphrase, passphrase_file, 0, passbuf, sizeof(passbuf)) != CRYPTO_SUCCESS) {
            ret = CRYPTO_ERR_INVALID_INPUT;
            goto cleanup;
        }
        ret = crypto_sign_file(positionals[0], sigout, config.secret_key_file, &config);
        if (ret == CRYPTO_SUCCESS) {
            fprintf(stderr, "Signed -> %s\n", sigout);
        }
        goto cleanup;
    }

    /* ---------------- verify-sig ---------------- */
    if (is_verify_sig) {
        if (npos < 1) {
            fprintf(stderr, "Error: verify-sig requires an input file\n");
            ret = CRYPTO_ERR_INVALID_INPUT;
            goto cleanup;
        }
        char sigbuf[MAX_PATH_LENGTH];
        const char *sigfile;
        if (positionals[1]) {
            sigfile = positionals[1];
        } else {
            snprintf(sigbuf, sizeof(sigbuf), "%s.sig", positionals[0]);
            sigfile = sigbuf;
        }
        ret = crypto_verify_signature(positionals[0], sigfile, config.public_key_file, &config);
        if (ret == CRYPTO_SUCCESS) {
            fprintf(stderr, "OK: signature valid for %s\n", positionals[0]);
        }
        goto cleanup;
    }

    /* ---------------- inspect ---------------- */
    if (is_inspect) {
        if (npos != 1) {
            fprintf(stderr, "Error: inspect takes exactly one file argument\n");
            ret = CRYPTO_ERR_INVALID_INPUT;
            goto cleanup;
        }
        ret = crypto_inspect_file(positionals[0], kem, &config);
        goto cleanup;
    }

    /* ---------------- rekey ---------------- */
    if (is_rekey) {
        if (npos != 0) {
            fprintf(stderr, "Error: rekey takes no positional arguments\n");
            ret = CRYPTO_ERR_INVALID_INPUT;
            goto cleanup;
        }
        /* Unwrap the secret key with the current passphrase... */
        char oldbuf[MAX_PASSPHRASE];
        memset(oldbuf, 0, sizeof(oldbuf));
        if (resolve_passphrase(&config, cli_passphrase, passphrase_file, 0, oldbuf, sizeof(oldbuf)) != CRYPTO_SUCCESS) {
            OPENSSL_cleanse(oldbuf, sizeof(oldbuf));
            ret = CRYPTO_ERR_INVALID_INPUT;
            goto cleanup;
        }
        secret_blob = crypto_load_secret_key(config.secret_key_file, &secret_len, &config);
        OPENSSL_cleanse(oldbuf, sizeof(oldbuf));
        if (!secret_blob) {
            fprintf(stderr, "Error: could not load secret key (wrong passphrase?)\n");
            ret = CRYPTO_ERR_FILE_IO;
            goto cleanup;
        }
        /* ...then re-wrap it under a freshly confirmed passphrase. */
        if (!read_hidden("New passphrase: ", passbuf, sizeof(passbuf))) {
            fprintf(stderr, "Error: failed to read passphrase\n");
            ret = CRYPTO_ERR_INVALID_INPUT;
            goto cleanup;
        }
        char again[MAX_PASSPHRASE];
        if (!read_hidden("Confirm passphrase: ", again, sizeof(again))) {
            fprintf(stderr, "Error: failed to read passphrase\n");
            ret = CRYPTO_ERR_INVALID_INPUT;
            goto cleanup;
        }
        int mismatch = strcmp(passbuf, again) != 0;
        OPENSSL_cleanse(again, sizeof(again));
        if (mismatch) {
            fprintf(stderr, "Error: passphrases do not match\n");
            ret = CRYPTO_ERR_INVALID_INPUT;
            goto cleanup;
        }
        if (passbuf[0] == '\0') {
            fprintf(stderr, "Error: passphrase must not be empty\n");
            ret = CRYPTO_ERR_INVALID_INPUT;
            goto cleanup;
        }
        config.passphrase = passbuf;
        config.force_overwrite = 1; /* deliberately replacing the existing key file */
        if (crypto_save_secret_key(config.secret_key_file, secret_blob, secret_len, &config) != CRYPTO_SUCCESS) {
            fprintf(stderr, "Error: failed to write re-keyed secret key\n");
            ret = CRYPTO_ERR_FILE_IO;
            goto cleanup;
        }
        printf("Secret key re-wrapped under the new passphrase: %s\n", config.secret_key_file);
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
    if (is_dir && config.armor) {
        fprintf(stderr, "Error: --armor applies to single files, not directories\n");
        ret = CRYPTO_ERR_INVALID_INPUT;
        goto cleanup;
    }

    size_t expect_pub = X25519_KEY_SIZE + kem->length_public_key;

    if (is_encrypt) {
        /* Recipients are the --recipient public keys, or the default key. */
        if (n_recipient_opts > 0) {
            for (int i = 0; i < n_recipient_opts; i++) {
                recipient_bufs[i] = crypto_load_public_key(recipient_opts[i], expect_pub, &config);
                if (!recipient_bufs[i]) {
                    fprintf(stderr, "Error: could not load recipient public key '%s'\n", recipient_opts[i]);
                    ret = CRYPTO_ERR_FILE_IO;
                    goto cleanup;
                }
                recipient_ptrs[i] = recipient_bufs[i];
            }
            n_recip_loaded = (size_t)n_recipient_opts;
        } else {
            recipient_bufs[0] = crypto_load_public_key(config.public_key_file, expect_pub, &config);
            if (!recipient_bufs[0]) {
                fprintf(stderr, "Error: could not load public key '%s'. Run '%s keygen' first.\n",
                        config.public_key_file, PROGRAM_NAME);
                ret = CRYPTO_ERR_FILE_IO;
                goto cleanup;
            }
            recipient_ptrs[0] = recipient_bufs[0];
            n_recip_loaded = 1;
        }
    } else {
        if (resolve_passphrase(&config, cli_passphrase, passphrase_file, 0, passbuf, sizeof(passbuf)) != CRYPTO_SUCCESS) {
            ret = CRYPTO_ERR_INVALID_INPUT;
            goto cleanup;
        }
        secret_blob = crypto_load_secret_key(config.secret_key_file, &secret_len, &config);
        if (secret_blob == NULL || secret_len != X25519_KEY_SIZE + kem->length_secret_key) {
            fprintf(stderr, "Error: Failed to load secret key or invalid key length\n");
            free(secret_blob);
            secret_blob = NULL;
            ret = CRYPTO_ERR_FILE_IO;
            goto cleanup;
        }
    }

    if (config.verbose) {
        fprintf(stderr, "Operation: %s\nInput: %s\nOutput: %s\nType: %s\n",
                command, input_path, output_path, is_dir ? "dir" : "file");
    }

    /* process_directory dispatches on "encrypt" vs anything else (decrypt). */
    const char *op = is_encrypt ? "encrypt" : "decrypt";
    if (is_dir) {
        fprintf(stderr, "%s files in directory...\n", is_encrypt ? "Encrypting" : "Decrypting");
        ret = crypto_process_directory(input_path, output_path, op, kem,
                                       recipient_ptrs, n_recip_loaded, secret_blob, &config);
    } else if (config.armor) {
        /* Stage the binary container in a temp file, then (de)armor around it. */
        char tmp[MAX_PATH_LENGTH];
        if (!make_temp_path(tmp, sizeof(tmp))) {
            fprintf(stderr, "Error: could not create temporary file\n");
            ret = CRYPTO_ERR_FILE_IO;
        } else if (is_encrypt) {
            crypto_config_t tcfg = config;
            tcfg.force_overwrite = 1; /* the temp file is ours to overwrite */
            ret = crypto_encrypt_file(input_path, tmp, kem, recipient_ptrs, n_recip_loaded, &tcfg);
            if (ret == CRYPTO_SUCCESS) ret = crypto_armor(tmp, output_path);
            remove(tmp);
        } else {
            ret = crypto_dearmor(input_path, tmp);
            if (ret == CRYPTO_SUCCESS) ret = crypto_decrypt_file(tmp, output_path, kem, secret_blob, &config);
            remove(tmp);
        }
    } else if (is_encrypt) {
        ret = crypto_encrypt_file(input_path, output_path, kem, recipient_ptrs, n_recip_loaded, &config);
    } else {
        ret = crypto_decrypt_file(input_path, output_path, kem, secret_blob, &config);
    }

    if (ret != CRYPTO_SUCCESS) {
        fprintf(stderr, "Error: Operation failed (code %d)\n", ret);
    } else if (is_verify || config.check_only) {
        fprintf(stderr, "OK: %s authenticated successfully\n", input_path);
    } else if (!is_stream && strcmp(output_path, "-") != 0) {
        fprintf(stderr, "Done -> %s\n", output_path);
    }

cleanup:
    OPENSSL_cleanse(passbuf, sizeof(passbuf));
    if (public_blob) {
        free(public_blob); /* public material; no cleanse needed */
    }
    if (secret_blob) {
        OPENSSL_cleanse(secret_blob, secret_len);
        free(secret_blob);
    }
    for (int i = 0; i < QSAFE_MAX_RECIPIENTS; i++) {
        free(recipient_bufs[i]); /* recipient public keys */
    }
    if (kem) OQS_KEM_free(kem);
    return ret == CRYPTO_SUCCESS ? 0 : 1;
}
