/* Expose POSIX symbols (fileno, tcgetattr/tcsetattr, ...) under -std=c11,
 * which otherwise restricts glibc to strict ISO C. */
#define _DEFAULT_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <dirent.h>
#ifndef _WIN32
  #include <unistd.h>
  #include <termios.h>
#endif
#include <oqs/oqs.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include "platform.h"
#include "crypto_utils.h"
#include "age.h"
#include "keychain.h"
#include "sss.h"

#define KEYCHAIN_SERVICE "qsafe"

#define PROGRAM_NAME "qsafe"
#define VERSION "8.0.0"
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
    printf("  %s keys    <list|path|import <name> <pubkey>|remove <name>>\n", PROGRAM_NAME);
    printf("  %s split-key --threshold <t> --shares <n> [prefix]\n", PROGRAM_NAME);
    printf("  %s join-key <share> <share> [share...]\n", PROGRAM_NAME);
    printf("  %s age-keygen [keyfile]\n", PROGRAM_NAME);
    printf("  %s age-encrypt -r <age1...> <input> [output]\n", PROGRAM_NAME);
    printf("  %s age-decrypt -i <keyfile> <input> [output]\n", PROGRAM_NAME);
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
    printf("  keys         Manage the keyring (~/.qsafe): list/import/remove recipients\n");
    printf("  split-key    Split the secret key into n shares, any t of which recover it\n");
    printf("  join-key     Reconstruct a secret key from shares (re-wraps with a new passphrase)\n");
    printf("  age-keygen   Generate an age (X25519) keypair\n");
    printf("  age-encrypt  Encrypt to age 'age1...' recipients (interop; classical only)\n");
    printf("  age-decrypt  Decrypt an age file with an age identity file (-i)\n");
    printf("\n");
    printf("Files vs. directories are detected automatically. Use '-' as the input\n");
    printf("or output to read from stdin / write to stdout.\n");
    printf("\n");
    printf("Options:\n");
    printf("  --key-file <path>       Secret key file (default: %s)\n", DEFAULT_SECRET_KEY_FILE);
    printf("  --pub-file <path>       Public key file (default: <key-file>%s)\n", PUBLIC_KEY_SUFFIX);
    printf("  -r, --recipient <p|name> encrypt: recipient public key path OR keyring name (repeatable)\n");
    printf("  --identity <name>       use (or, for keygen, create) a keyring identity in ~/.qsafe\n");
    printf("  -i, --identity-file <p> age-decrypt: age identity file (AGE-SECRET-KEY-...)\n");
    printf("  --passphrase <str>      Passphrase (discouraged; visible to other users)\n");
    printf("  --passphrase-file <p>   Read the passphrase from the first line of a file\n");
    printf("  --check                 decrypt/verify: authenticate only, write nothing\n");
    printf("  --sign-with <sk>        encrypt: embed an ML-DSA-87 sender signature (needs <sk>.pub)\n");
    printf("  --signer <pk>           decrypt/verify: require the embedded signer to be this key\n");
    printf("  --pad                   encrypt: hide the exact file size (Padme padding)\n");
    printf("  --threshold <t>         split-key: shares needed to reconstruct (2-16)\n");
    printf("  --shares <n>            split-key: total shares to create (t-255)\n");
    printf("  --armor                 encrypt: ASCII base64 output; decrypt: base64 input\n");
    printf("  --scrypt-cost <n>       keygen/rekey: scrypt cost as log2(N), 14-22 (default 15)\n");
    printf("  --keychain              store/derive the key passphrase in the OS keychain (macOS/Windows)\n");
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

/* Strips a trailing newline (and CR, since stdin may be binary on Windows). */
static void strip_eol(char *buf) {
    size_t l = strlen(buf);
    while (l > 0 && (buf[l - 1] == '\n' || buf[l - 1] == '\r')) buf[--l] = '\0';
}

#ifdef _WIN32
/* Reads a line without echoing, by disabling console echo when stdin is a
 * console (a no-op for piped input, which never echoes). Returns 1 on success. */
static int read_hidden(const char *prompt, char *buf, size_t bufsz) {
    fprintf(stderr, "%s", prompt);
    fflush(stderr);

    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    int have_mode = GetConsoleMode(h, &mode);
    if (have_mode) SetConsoleMode(h, mode & ~(DWORD)ENABLE_ECHO_INPUT);

    char *r = fgets(buf, (int)bufsz, stdin);

    if (have_mode) SetConsoleMode(h, mode);
    fprintf(stderr, "\n");

    if (!r) return 0;
    strip_eol(buf);
    return 1;
}
#else
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
    strip_eol(buf);
    return 1;
}
#endif

/* Resolves the passphrase into buf and points config->passphrase at it (or, for
 * --passphrase, at argv directly). confirm=1 prompts twice and compares. */
static crypto_error_t resolve_passphrase(crypto_config_t *config, const char *cli,
                                         const char *pfile, int confirm,
                                         char *buf, size_t bufsz) {
    /* --keychain: the wrapping passphrase lives in the OS keychain. On a
     * key-creating op (confirm=1) generate a strong random one and store it;
     * otherwise retrieve it. The keychain item is keyed by the secret-key path. */
    if (config->use_keychain) {
        if (!keychain_available()) {
            fprintf(stderr, "Error: --keychain is not supported on this platform\n");
            return CRYPTO_ERR_INVALID_INPUT;
        }
        const char *account = config->secret_key_file;
        if (confirm) {
            unsigned char rnd[24];
            if (RAND_bytes(rnd, sizeof(rnd)) != 1) {
                fprintf(stderr, "Error: could not generate a keychain passphrase\n");
                return CRYPTO_ERR_CRYPTO;
            }
            static const char hex[] = "0123456789abcdef";
            if (bufsz < sizeof(rnd) * 2 + 1) return CRYPTO_ERR_INVALID_INPUT;
            for (size_t i = 0; i < sizeof(rnd); i++) {
                buf[2 * i] = hex[rnd[i] >> 4];
                buf[2 * i + 1] = hex[rnd[i] & 0xF];
            }
            buf[sizeof(rnd) * 2] = '\0';
            OPENSSL_cleanse(rnd, sizeof(rnd));
            if (keychain_store(KEYCHAIN_SERVICE, account, buf) != KC_OK) {
                fprintf(stderr, "Error: could not store passphrase in the keychain\n");
                return CRYPTO_ERR_FILE_IO;
            }
            config->passphrase = buf;
            return CRYPTO_SUCCESS;
        }
        kc_status kc = keychain_retrieve(KEYCHAIN_SERVICE, account, buf, bufsz);
        if (kc == KC_ERR_NOTFOUND) {
            fprintf(stderr, "Error: no keychain entry for '%s'\n", account);
            return CRYPTO_ERR_INVALID_INPUT;
        }
        if (kc != KC_OK) {
            fprintf(stderr, "Error: could not read the keychain\n");
            return CRYPTO_ERR_FILE_IO;
        }
        config->passphrase = buf;
        return CRYPTO_SUCCESS;
    }

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
#ifdef _WIN32
    char dir[MAX_PATH];
    if (GetTempPathA((DWORD)sizeof(dir), dir) == 0) return 0;
    char path[MAX_PATH];
    if (GetTempFileNameA(dir, "qsf", 0, path) == 0) return 0; /* creates the file */
    if ((size_t)snprintf(buf, n, "%s", path) >= n) return 0;
    return 1;
#else
    const char *dir = getenv("TMPDIR");
    if (!dir || !*dir) dir = "/tmp";
    if ((size_t)snprintf(buf, n, "%s/qsafe_armor_XXXXXX", dir) >= n) return 0;
    int fd = mkstemp(buf);
    if (fd < 0) return 0;
    close(fd);
    return 1;
#endif
}

/* ------------------------------- keyring ---------------------------------
 * A simple on-disk store under $QSAFE_HOME (default ~/.qsafe):
 *   identities/<name>/{secret_key.bin,public_key.bin}   your hybrid keypairs
 *   recipients/<name>.pub                               known recipient keys
 * Names may not contain path separators. `-r <name>` and `--identity <name>`
 * resolve through here; a real file path always wins. */

static int valid_keyname(const char *name) {
    if (!name || !*name) return 0;
    for (const char *c = name; *c; c++)
        if (*c == '/' || *c == '\\' || *c == ':') return 0;
    return strcmp(name, ".") != 0 && strcmp(name, "..") != 0;
}

static int file_exists(const char *p) {
    struct stat st;
    return stat(p, &st) == 0 && S_ISREG(st.st_mode);
}

/* Writes the keyring base dir into buf. Returns 1 on success. */
static int keyring_base(char *buf, size_t n) {
    const char *over = getenv("QSAFE_HOME");
    if (over && *over) return (size_t)snprintf(buf, n, "%s", over) < n;
    const char *home = qsafe_home_dir();
    if (!home) return 0;
    return (size_t)snprintf(buf, n, "%s/.qsafe", home) < n;
}

/* Writes identities/<name>/<leaf> into buf. Returns 1 on success. */
static int keyring_identity_path(const char *name, const char *leaf, char *buf, size_t n) {
    char base[MAX_PATH_LENGTH];
    if (!keyring_base(base, sizeof(base))) return 0;
    return (size_t)snprintf(buf, n, "%s/identities/%s%s%s", base, name,
                            (leaf && *leaf) ? "/" : "", leaf ? leaf : "") < n;
}

/* Resolves a recipient argument to a public-key path in buf: a real file wins,
 * else recipients/<name>.pub, else identities/<name>/public_key.bin. Returns 1. */
static int resolve_recipient_path(const char *arg, char *buf, size_t n) {
    if (file_exists(arg)) return (size_t)snprintf(buf, n, "%s", arg) < n;
    if (!valid_keyname(arg)) return 0;
    char base[MAX_PATH_LENGTH];
    if (!keyring_base(base, sizeof(base))) return 0;
    if ((size_t)snprintf(buf, n, "%s/recipients/%s.pub", base, arg) < n && file_exists(buf)) return 1;
    if ((size_t)snprintf(buf, n, "%s/identities/%s/public_key.bin", base, arg) < n && file_exists(buf)) return 1;
    return 0;
}

/* ------------------------------- age interop -----------------------------
 * Self-contained age v1 (X25519) commands. Recipients are "age1…" strings
 * (passed via -r); the decrypt identity is an "AGE-SECRET-KEY-1…" file (-i). */
static int run_age_command(const char *command, const char *const *positionals, int npos,
                           const char *const *recipients, int n_recipients,
                           const char *identity_file) {
    if (strcmp(command, "age-keygen") == 0) {
        char pub[200], sec[200];
        if (age_keygen(pub, sizeof(pub), sec, sizeof(sec)) != AGE_OK) {
            fprintf(stderr, "Error: age keypair generation failed\n");
            return 1;
        }
        const char *out = npos >= 1 ? positionals[0] : NULL;
        FILE *f = out ? fopen(out, "w") : stdout;
        if (!f) {
            fprintf(stderr, "Error: cannot write '%s'\n", out);
            OPENSSL_cleanse(sec, sizeof(sec));
            return 1;
        }
        fprintf(f, "# public key: %s\n%s\n", pub, sec);
        if (out) {
            fclose(f);
            qsafe_chmod_private(out);
            fprintf(stderr, "Public key: %s\n", pub);
        }
        OPENSSL_cleanse(sec, sizeof(sec));
        return 0;
    }
    if (strcmp(command, "age-encrypt") == 0) {
        if (n_recipients == 0) {
            fprintf(stderr, "Error: age-encrypt needs at least one '-r age1...'\n");
            return 1;
        }
        if (npos < 1) { fprintf(stderr, "Error: age-encrypt [-r age1...] <input> [output]\n"); return 1; }
        const char *out = npos >= 2 ? positionals[1] : "-";
        age_status rc = age_encrypt_file(positionals[0], out, recipients, (size_t)n_recipients);
        if (rc != AGE_OK) { fprintf(stderr, "Error: age-encrypt: %s\n", age_strerror(rc)); return 1; }
        return 0;
    }
    /* age-decrypt */
    if (!identity_file) { fprintf(stderr, "Error: age-decrypt requires -i <identity-file>\n"); return 1; }
    if (npos < 1) { fprintf(stderr, "Error: age-decrypt -i <key> <input> [output]\n"); return 1; }
    char line[256], secret[256] = "";
    FILE *kf = fopen(identity_file, "r");
    if (!kf) { fprintf(stderr, "Error: cannot open identity file '%s'\n", identity_file); return 1; }
    while (fgets(line, sizeof(line), kf)) {
        if (strncmp(line, "AGE-SECRET-KEY-", 15) == 0) {
            size_t l = strlen(line);
            while (l && (line[l - 1] == '\n' || line[l - 1] == '\r')) line[--l] = '\0';
            snprintf(secret, sizeof(secret), "%s", line);
            break;
        }
    }
    fclose(kf);
    if (!secret[0]) { fprintf(stderr, "Error: no AGE-SECRET-KEY in '%s'\n", identity_file); return 1; }
    const char *out = npos >= 2 ? positionals[1] : "-";
    age_status rc = age_decrypt_file(positionals[0], out, secret);
    OPENSSL_cleanse(secret, sizeof(secret));
    if (rc != AGE_OK) { fprintf(stderr, "Error: age-decrypt: %s\n", age_strerror(rc)); return 1; }
    return 0;
}

int main(int argc, char *argv[]) {
    /* On Windows, keep stdin/stdout binary so piped ciphertext isn't corrupted
     * by CRLF translation. No-op on POSIX. */
    qsafe_set_binary_stdio();

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
    config.use_keychain = 0;
    config.sign_sk_file = NULL;
    config.sign_pk_file = NULL;
    config.signer_pk_file = NULL;
    config.pad = 0;

    const char *command = NULL;
    const char *cli_passphrase = NULL;
    const char *passphrase_file = NULL;
    const char *sign_with = NULL;       /* encrypt: --sign-with signing secret key */
    unsigned int sss_threshold = 0;     /* split-key: --threshold */
    unsigned int sss_shares = 0;        /* split-key: --shares */
    const char *pub_file_opt = NULL;
    const char *identity_name = NULL;
    const char *identity_file = NULL;   /* age-decrypt: AGE-SECRET-KEY file */
    const char *positionals[16] = { NULL };  /* join-key takes up to 16 shares */
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
        } else if (strcmp(a, "--keychain") == 0) {
            config.use_keychain = 1;
        } else if (strcmp(a, "--armor") == 0) {
            config.armor = 1;
        } else if (strcmp(a, "--pad") == 0) {
            config.pad = 1;
        } else if (strcmp(a, "--sign-with") == 0) {
            if (++i >= argc) { fprintf(stderr, "Error: --sign-with requires a signing key path\n"); return 1; }
            sign_with = argv[i];
        } else if (strcmp(a, "--signer") == 0) {
            if (++i >= argc) { fprintf(stderr, "Error: --signer requires a public key path\n"); return 1; }
            config.signer_pk_file = argv[i];
        } else if (strcmp(a, "--threshold") == 0) {
            if (++i >= argc) { fprintf(stderr, "Error: --threshold requires a number\n"); return 1; }
            char *end = NULL;
            long v = strtol(argv[i], &end, 10);
            if (end == argv[i] || *end != '\0' || v < SSS_MIN_THRESHOLD || v > SSS_MAX_THRESHOLD) {
                fprintf(stderr, "Error: --threshold must be in [%d, %d]\n", SSS_MIN_THRESHOLD, SSS_MAX_THRESHOLD);
                return 1;
            }
            sss_threshold = (unsigned int)v;
        } else if (strcmp(a, "--shares") == 0) {
            if (++i >= argc) { fprintf(stderr, "Error: --shares requires a number\n"); return 1; }
            char *end = NULL;
            long v = strtol(argv[i], &end, 10);
            if (end == argv[i] || *end != '\0' || v < SSS_MIN_THRESHOLD || v > SSS_MAX_SHARES) {
                fprintf(stderr, "Error: --shares must be in [%d, %d]\n", SSS_MIN_THRESHOLD, SSS_MAX_SHARES);
                return 1;
            }
            sss_shares = (unsigned int)v;
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
        } else if (strcmp(a, "--identity") == 0) {
            if (++i >= argc) { fprintf(stderr, "Error: --identity requires a name\n"); return 1; }
            identity_name = argv[i];
        } else if (strcmp(a, "--identity-file") == 0 || strcmp(a, "-i") == 0) {
            if (++i >= argc) { fprintf(stderr, "Error: --identity-file requires a path\n"); return 1; }
            identity_file = argv[i];
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
            if (npos >= (int)(sizeof(positionals) / sizeof(positionals[0]))) {
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
    int is_keys = strcmp(command, "keys") == 0;
    int is_split_key = strcmp(command, "split-key") == 0;
    int is_join_key = strcmp(command, "join-key") == 0;
    int is_age_keygen = strcmp(command, "age-keygen") == 0;
    int is_age_encrypt = strcmp(command, "age-encrypt") == 0;
    int is_age_decrypt = strcmp(command, "age-decrypt") == 0;
    if (!is_keygen && !is_encrypt && !is_decrypt && !is_verify && !is_rekey &&
        !is_inspect && !is_sign_keygen && !is_sign && !is_verify_sig && !is_keys &&
        !is_split_key && !is_join_key &&
        !is_age_keygen && !is_age_encrypt && !is_age_decrypt) {
        fprintf(stderr, "Error: unknown command '%s'\n\n", command);
        print_usage();
        return 1;
    }

    /* age interop is a self-contained format (classical X25519, no liboqs) —
     * handle it before the hybrid engine sets up. */
    if (is_age_keygen || is_age_encrypt || is_age_decrypt) {
        return run_age_command(command, positionals, npos,
                               recipient_opts, n_recipient_opts, identity_file);
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

    /* --identity <name>: use (or, for keygen, create) a keyring identity. Its
     * secret/public keys override --key-file/--pub-file. */
    char id_sec[MAX_PATH_LENGTH], id_pub[MAX_PATH_LENGTH];
    if (identity_name) {
        if (!valid_keyname(identity_name)) {
            fprintf(stderr, "Error: invalid identity name '%s'\n", identity_name);
            return 1;
        }
        if (!keyring_identity_path(identity_name, "secret_key.bin", id_sec, sizeof(id_sec)) ||
            !keyring_identity_path(identity_name, "public_key.bin", id_pub, sizeof(id_pub))) {
            fprintf(stderr, "Error: could not resolve keyring path (is HOME/QSAFE_HOME set?)\n");
            return 1;
        }
        if (is_keygen) {
            char id_dir[MAX_PATH_LENGTH];
            if (!keyring_identity_path(identity_name, "", id_dir, sizeof(id_dir)) ||
                qsafe_mkdir_p(id_dir) != 0) {
                fprintf(stderr, "Error: could not create keyring directory\n");
                return 1;
            }
        }
        config.secret_key_file = id_sec;
        pub_file_opt = id_pub;
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

    /* ---------------- keys (keyring management) ---------------- */
    if (is_keys) {
        const char *sub = positionals[0];
        char base[MAX_PATH_LENGTH];
        if (!sub) {
            fprintf(stderr, "Error: keys <list|path|import <name> <pubkey>|remove <name>>\n");
            ret = CRYPTO_ERR_INVALID_INPUT; goto cleanup;
        }
        if (!keyring_base(base, sizeof(base))) {
            fprintf(stderr, "Error: cannot locate keyring (set HOME or QSAFE_HOME)\n");
            ret = CRYPTO_ERR_INVALID_INPUT; goto cleanup;
        }
        size_t explen = X25519_KEY_SIZE + kem->length_public_key;

        if (strcmp(sub, "path") == 0) {
            printf("%s\n", base);
            ret = CRYPTO_SUCCESS; goto cleanup;
        }
        if (strcmp(sub, "list") == 0) {
            char dir[MAX_PATH_LENGTH];
            if (snprintf(dir, sizeof(dir), "%s/identities", base) >= (int)sizeof(dir)) {
                ret = CRYPTO_ERR_INVALID_INPUT; goto cleanup;
            }
            printf("Identities:\n");
            DIR *d = opendir(dir);
            if (d) {
                struct dirent *e;
                while ((e = readdir(d)) != NULL) {
                    if (e->d_name[0] == '.') continue;
                    char pubp[MAX_PATH_LENGTH], fp[65] = "";
                    if (snprintf(pubp, sizeof(pubp), "%s/%s/public_key.bin", dir, e->d_name) >= (int)sizeof(pubp))
                        continue;
                    if (file_exists(pubp)) {
                        unsigned char *pk = crypto_load_public_key(pubp, explen, &config);
                        if (pk) { crypto_fingerprint(pk, explen, fp, sizeof(fp)); free(pk); }
                    }
                    printf("  %-20s %s\n", e->d_name, fp);
                }
                closedir(d);
            }
            if (snprintf(dir, sizeof(dir), "%s/recipients", base) >= (int)sizeof(dir)) {
                ret = CRYPTO_ERR_INVALID_INPUT; goto cleanup;
            }
            printf("Recipients:\n");
            d = opendir(dir);
            if (d) {
                struct dirent *e;
                while ((e = readdir(d)) != NULL) {
                    size_t L = strlen(e->d_name);
                    if (e->d_name[0] == '.' || L < 4 || strcmp(e->d_name + L - 4, ".pub") != 0) continue;
                    char pubp[MAX_PATH_LENGTH], fp[65] = "", name[256];
                    if (snprintf(pubp, sizeof(pubp), "%s/%s", dir, e->d_name) >= (int)sizeof(pubp))
                        continue;
                    snprintf(name, sizeof(name), "%.*s", (int)(L - 4), e->d_name);
                    unsigned char *pk = crypto_load_public_key(pubp, explen, &config);
                    if (pk) { crypto_fingerprint(pk, explen, fp, sizeof(fp)); free(pk); }
                    printf("  %-20s %s\n", name, fp);
                }
                closedir(d);
            }
            ret = CRYPTO_SUCCESS; goto cleanup;
        }
        if (strcmp(sub, "import") == 0) {
            const char *name = positionals[1], *src = positionals[2];
            if (!name || !src) {
                fprintf(stderr, "Error: keys import <name> <pubkey-file>\n");
                ret = CRYPTO_ERR_INVALID_INPUT; goto cleanup;
            }
            if (!valid_keyname(name)) {
                fprintf(stderr, "Error: invalid recipient name '%s'\n", name);
                ret = CRYPTO_ERR_INVALID_INPUT; goto cleanup;
            }
            unsigned char *pk = crypto_load_public_key(src, explen, &config);
            if (!pk) {
                fprintf(stderr, "Error: '%s' is not a valid hybrid public key\n", src);
                ret = CRYPTO_ERR_FILE_IO; goto cleanup;
            }
            char rdir[MAX_PATH_LENGTH], dest[MAX_PATH_LENGTH];
            if (snprintf(rdir, sizeof(rdir), "%s/recipients", base) >= (int)sizeof(rdir) ||
                snprintf(dest, sizeof(dest), "%s/recipients/%s.pub", base, name) >= (int)sizeof(dest)) {
                fprintf(stderr, "Error: keyring path too long\n");
                free(pk); ret = CRYPTO_ERR_INVALID_INPUT; goto cleanup;
            }
            if (qsafe_mkdir_p(rdir) != 0) {
                fprintf(stderr, "Error: cannot create %s\n", rdir);
                free(pk); ret = CRYPTO_ERR_FILE_IO; goto cleanup;
            }
            ret = crypto_save_public_key(dest, pk, explen, &config);
            free(pk);
            if (ret == CRYPTO_SUCCESS) printf("Imported recipient '%s'\n", name);
            goto cleanup;
        }
        if (strcmp(sub, "remove") == 0) {
            const char *name = positionals[1];
            if (!name || !valid_keyname(name)) {
                fprintf(stderr, "Error: keys remove <name>\n");
                ret = CRYPTO_ERR_INVALID_INPUT; goto cleanup;
            }
            char dest[MAX_PATH_LENGTH];
            if (snprintf(dest, sizeof(dest), "%s/recipients/%s.pub", base, name) >= (int)sizeof(dest)) {
                ret = CRYPTO_ERR_INVALID_INPUT; goto cleanup;
            }
            if (remove(dest) != 0) {
                fprintf(stderr, "Error: no such recipient '%s'\n", name);
                ret = CRYPTO_ERR_FILE_IO; goto cleanup;
            }
            printf("Removed recipient '%s'\n", name);
            ret = CRYPTO_SUCCESS; goto cleanup;
        }
        fprintf(stderr, "Error: unknown keys subcommand '%s'\n", sub);
        ret = CRYPTO_ERR_INVALID_INPUT; goto cleanup;
    }

    /* ---------------- split-key (Shamir shares) ---------------- */
    if (is_split_key) {
        if (npos > 1) {
            fprintf(stderr, "Error: split-key takes at most an output prefix\n");
            ret = CRYPTO_ERR_INVALID_INPUT;
            goto cleanup;
        }
        if (sss_threshold == 0 || sss_shares == 0 || sss_shares < sss_threshold) {
            fprintf(stderr, "Error: split-key requires --threshold <t> and --shares <n> with n >= t\n");
            ret = CRYPTO_ERR_INVALID_INPUT;
            goto cleanup;
        }
        if (resolve_passphrase(&config, cli_passphrase, passphrase_file, 0, passbuf, sizeof(passbuf)) != CRYPTO_SUCCESS) {
            ret = CRYPTO_ERR_INVALID_INPUT;
            goto cleanup;
        }
        secret_blob = crypto_load_secret_key(config.secret_key_file, &secret_len, &config);
        if (!secret_blob) {
            fprintf(stderr, "Error: could not load secret key (wrong passphrase?)\n");
            ret = CRYPTO_ERR_FILE_IO;
            goto cleanup;
        }
        const char *prefix = positionals[0] ? positionals[0] : config.secret_key_file;
        sss_status src = sss_split_to_files(secret_blob, secret_len,
                                            sss_threshold, sss_shares, prefix);
        if (src != SSS_OK) {
            fprintf(stderr, "Error: split-key failed: %s\n", sss_strerror(src));
            ret = CRYPTO_ERR_CRYPTO;
            goto cleanup;
        }
        printf("Split %s into %u shares (any %u reconstruct it):\n",
               config.secret_key_file, sss_shares, sss_threshold);
        for (unsigned int i = 1; i <= sss_shares; i++) {
            printf("  %s.share%u\n", prefix, i);
        }
        printf("Each share is UNENCRYPTED key material: store them separately\n");
        printf("(any %u of them recover the key without a passphrase).\n", sss_threshold);
        ret = CRYPTO_SUCCESS;
        goto cleanup;
    }

    /* ---------------- join-key (reconstruct from shares) ---------------- */
    if (is_join_key) {
        if (npos < SSS_MIN_THRESHOLD) {
            fprintf(stderr, "Error: join-key needs at least %d share files\n", SSS_MIN_THRESHOLD);
            ret = CRYPTO_ERR_INVALID_INPUT;
            goto cleanup;
        }
        unsigned char *joined = NULL;
        size_t joined_len = 0;
        sss_status src = sss_join_files(positionals, (size_t)npos, &joined, &joined_len);
        if (src != SSS_OK) {
            fprintf(stderr, "Error: join-key failed: %s\n", sss_strerror(src));
            ret = CRYPTO_ERR_CRYPTO;
            goto cleanup;
        }
        secret_blob = joined;   /* cleansed+freed in cleanup */
        secret_len = joined_len;
        /* Re-wrap under a freshly confirmed passphrase (like keygen). */
        if (resolve_passphrase(&config, cli_passphrase, passphrase_file, 1, passbuf, sizeof(passbuf)) != CRYPTO_SUCCESS) {
            ret = CRYPTO_ERR_INVALID_INPUT;
            goto cleanup;
        }
        if (crypto_save_secret_key(config.secret_key_file, secret_blob, secret_len, &config) != CRYPTO_SUCCESS) {
            fprintf(stderr, "Error: failed to write reconstructed secret key\n");
            ret = CRYPTO_ERR_FILE_IO;
            goto cleanup;
        }
        printf("Reconstructed secret key -> %s (wrapped under the new passphrase)\n",
               config.secret_key_file);
        ret = CRYPTO_SUCCESS;
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

    char sign_pub_buf[MAX_PATH_LENGTH];
    if (is_encrypt && sign_with) {
        /* Embedded sender signature: the signing secret key needs its
         * passphrase; the signer public key travels in the payload. */
        config.sign_sk_file = sign_with;
        if (snprintf(sign_pub_buf, sizeof(sign_pub_buf), "%s%s", sign_with, PUBLIC_KEY_SUFFIX)
            >= (int)sizeof(sign_pub_buf)) {
            fprintf(stderr, "Error: signing key path too long\n");
            ret = CRYPTO_ERR_INVALID_INPUT;
            goto cleanup;
        }
        config.sign_pk_file = sign_pub_buf;
        /* The passphrase (and any keychain entry) belongs to the signing key. */
        config.secret_key_file = sign_with;
        if (resolve_passphrase(&config, cli_passphrase, passphrase_file, 0, passbuf, sizeof(passbuf)) != CRYPTO_SUCCESS) {
            ret = CRYPTO_ERR_INVALID_INPUT;
            goto cleanup;
        }
    }

    if (is_encrypt) {
        /* Recipients are the --recipient public keys, or the default key. */
        if (n_recipient_opts > 0) {
            for (int i = 0; i < n_recipient_opts; i++) {
                /* Resolve "-r <arg>": a real file path, or a keyring name. */
                char rpath[MAX_PATH_LENGTH];
                if (!resolve_recipient_path(recipient_opts[i], rpath, sizeof(rpath))) {
                    fprintf(stderr, "Error: recipient '%s' is not a file or a known keyring name\n",
                            recipient_opts[i]);
                    ret = CRYPTO_ERR_INVALID_INPUT;
                    goto cleanup;
                }
                recipient_bufs[i] = crypto_load_public_key(rpath, expect_pub, &config);
                if (!recipient_bufs[i]) {
                    fprintf(stderr, "Error: could not load recipient public key '%s'\n", rpath);
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
