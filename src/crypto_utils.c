/* Expose POSIX symbols (mode_t, PATH_MAX, realpath, utime, ...) under -std=c11,
 * which otherwise restricts glibc to strict ISO C. */
#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <oqs/oqs.h>
#include "platform.h"
#include "crypto_utils.h"

/* Domain-separation label mixed into the HKDF expansion so the AES key derived
 * from a KEM shared secret is bound to this specific use. */
#define HKDF_INFO_LABEL "qsafe-v3-aes-key"

/* Label for the hybrid key-encryption key derived from (X25519 DH || ML-KEM ss). */
#define HKDF_HYBRID_LABEL "qsafe-v5-hybrid-kek"

/* Signature algorithm used both for detached signatures and the v7 embedded
 * signed-sender trailer. */
#define QSAFE_SIG_ALG OQS_SIG_alg_ml_dsa_87

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

crypto_error_t crypto_fingerprint(const unsigned char *data, size_t len, char *out, size_t outsz) {
    unsigned char digest[32];
    unsigned int dlen = 0;
    if (outsz < 2 * sizeof(digest) + 1) {
        return CRYPTO_ERR_INVALID_INPUT;
    }
    if (EVP_Digest(data, len, digest, &dlen, EVP_sha256(), NULL) != 1 || dlen != sizeof(digest)) {
        crypto_handle_errors();
        return CRYPTO_ERR_CRYPTO;
    }
    static const char hex[] = "0123456789abcdef";
    for (unsigned int i = 0; i < dlen; i++) {
        out[2 * i]     = hex[digest[i] >> 4];
        out[2 * i + 1] = hex[digest[i] & 0x0f];
    }
    out[2 * dlen] = '\0';
    return CRYPTO_SUCCESS;
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

crypto_error_t crypto_derive_key_from_passphrase(const char *passphrase, const unsigned char *salt,
                                                 uint64_t n, uint32_t r, uint32_t p, unsigned char *out_key) {
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

    /* The caller chooses N/r/p (default N=2^15, r=8, p=1 -> ~32 MiB per guess).
     * maxmem scales with the request so a higher N is permitted but a hostile
     * key file cannot ask OpenSSL for an unbounded allocation. */
    uint64_t maxmem = 128ULL * n * r * 2; /* ~2x scrypt's working-set bound */
    if (maxmem < (1ULL << 30)) maxmem = 1ULL << 30;

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
    unsigned char header[KEYFILE_MAGIC_SIZE + 8 + 4 + 4]; /* magic | N | r | p */
    unsigned char *ciphertext = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    FILE *file = NULL;

    /* Resolve the scrypt cost: caller-chosen, else the default. */
    uint64_t n = config->scrypt_n ? config->scrypt_n : (1ULL << SCRYPT_DEFAULT_LOG_N);
    uint32_t r = config->scrypt_r ? config->scrypt_r : SCRYPT_DEFAULT_R;
    uint32_t p = config->scrypt_p ? config->scrypt_p : SCRYPT_DEFAULT_P;

    memcpy(header, KEYFILE_MAGIC, KEYFILE_MAGIC_SIZE);
    store_u64(header + KEYFILE_MAGIC_SIZE, n);
    store_u32(header + KEYFILE_MAGIC_SIZE + 8, r);
    store_u32(header + KEYFILE_MAGIC_SIZE + 12, p);

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

    if (crypto_derive_key_from_passphrase(config->passphrase, salt, n, r, p, key) != CRYPTO_SUCCESS) {
        goto cleanup;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        goto cleanup;
    }

    int len;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1 ||
        /* Bind the header (magic + KDF cost) into the tag. */
        EVP_EncryptUpdate(ctx, NULL, &len, header, (int)sizeof(header)) != 1 ||
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

    if (fwrite(header, 1, sizeof(header), file) != sizeof(header) ||
        fwrite(nonce, 1, AES_GCM_NONCE_SIZE, file) != AES_GCM_NONCE_SIZE ||
        fwrite(salt, 1, KDF_SALT_SIZE, file) != KDF_SALT_SIZE ||
        fwrite(ciphertext, 1, length, file) != length ||
        fwrite(tag, 1, AES_GCM_TAG_SIZE, file) != AES_GCM_TAG_SIZE) {
        perror("Error writing key file");
        ret = CRYPTO_ERR_FILE_IO;
        goto cleanup;
    }

    /* Secret key material: restrict permissions to the owner. */
    fflush(file);
    qsafe_chmod_private(filename);

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
    unsigned char header[KEYFILE_MAGIC_SIZE + 8 + 4 + 4];
    int have_header = 0;
    uint64_t n = 1ULL << SCRYPT_DEFAULT_LOG_N;
    uint32_t r = SCRYPT_DEFAULT_R;
    uint32_t p = SCRYPT_DEFAULT_P;
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

    /* A header is present iff the file begins with the keyfile magic. */
    unsigned char peek[KEYFILE_MAGIC_SIZE];
    if (file_size >= (long)KEYFILE_MAGIC_SIZE &&
        fread(peek, 1, KEYFILE_MAGIC_SIZE, file) == KEYFILE_MAGIC_SIZE &&
        memcmp(peek, KEYFILE_MAGIC, KEYFILE_MAGIC_SIZE) == 0) {
        have_header = 1;
    }
    rewind(file);

    size_t overhead = AES_GCM_NONCE_SIZE + KDF_SALT_SIZE + AES_GCM_TAG_SIZE;
    if (have_header) overhead += sizeof(header);
    if (file_size < 0 || (size_t)file_size <= overhead) {
        fprintf(stderr, "Error: Invalid key file format\n");
        fclose(file);
        return NULL;
    }

    if (have_header) {
        if (fread(header, 1, sizeof(header), file) != sizeof(header)) {
            fprintf(stderr, "Error: Failed to read key file header\n");
            fclose(file);
            return NULL;
        }
        n = load_u64(header + KEYFILE_MAGIC_SIZE);
        r = load_u32(header + KEYFILE_MAGIC_SIZE + 8);
        p = load_u32(header + KEYFILE_MAGIC_SIZE + 12);
        /* Sanity-bound the advertised cost so a malicious file can't force an
         * absurd allocation; these ceilings are far above any real setting. */
        if (n < 2 || (n & (n - 1)) != 0 || n > (1ULL << 24) || r == 0 || r > 64 || p == 0 || p > 16) {
            fprintf(stderr, "Error: key file declares unsupported scrypt parameters\n");
            fclose(file);
            return NULL;
        }
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

    if (crypto_derive_key_from_passphrase(config->passphrase, salt, n, r, p, key) != CRYPTO_SUCCESS) {
        goto cleanup;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        goto cleanup;
    }

    int len;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1 ||
        /* Header is authenticated as additional data when present. */
        (have_header && EVP_DecryptUpdate(ctx, NULL, &len, header, (int)sizeof(header)) != 1) ||
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

crypto_error_t crypto_inspect_file(const char *filename, OQS_KEM *kem, const crypto_config_t *config) {
    (void)config;

    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening file");
        return CRYPTO_ERR_FILE_IO;
    }

    if (fseek(file, 0, SEEK_END) != 0) { fclose(file); return CRYPTO_ERR_FILE_IO; }
    long fsz = ftell(file);
    rewind(file);
    if (fsz < 0) { fclose(file); return CRYPTO_ERR_FILE_IO; }
    size_t file_size = (size_t)fsz;

    unsigned char prefix[VERSION_HEADER_SIZE + 1 + AES_GCM_NONCE_SIZE];
    size_t got = fread(prefix, 1, sizeof(prefix), file);
    fclose(file);

    printf("File: %s\n", filename);
    printf("Size: %zu bytes\n", file_size);

    /* Encrypted QSAFE container (v7/v6 = framed, v5 = single-AEAD)? */
    int v7 = (got >= VERSION_HEADER_SIZE && memcmp(prefix, VERSION_HEADER_V7, VERSION_HEADER_SIZE) == 0);
    int v6 = (got >= VERSION_HEADER_SIZE && memcmp(prefix, VERSION_HEADER_V6, VERSION_HEADER_SIZE) == 0);
    int v5 = (got >= VERSION_HEADER_SIZE && memcmp(prefix, VERSION_HEADER, VERSION_HEADER_SIZE) == 0);
    if (v5 || v6 || v7) {
        printf("Type: encrypted file (%.*s)\n", VERSION_HEADER_SIZE, (const char *)prefix);
        printf("KEM:  hybrid X25519 + %s\n", OQS_KEM_alg_ml_kem_1024);
        if (v6 || v7) {
            printf("AEAD: AES-256-GCM, framed (%d-byte frames)\n", QSAFE_FRAME_SIZE);
        } else {
            printf("AEAD: AES-256-GCM (nonce %d, tag %d bytes)\n", AES_GCM_NONCE_SIZE, AES_GCM_TAG_SIZE);
        }
        if (got > VERSION_HEADER_SIZE) {
            printf("Recipients: %u\n", (unsigned)prefix[VERSION_HEADER_SIZE]);
        }
        return CRYPTO_SUCCESS;
    }

    /* Raw hybrid public key? (x25519_pub || mlkem_pub, stored in the clear) */
    if (file_size == X25519_KEY_SIZE + kem->length_public_key) {
        unsigned char *buf = malloc(file_size);
        if (!buf) return CRYPTO_ERR_MEMORY;
        FILE *f2 = fopen(filename, "rb");
        if (f2 && fread(buf, 1, file_size, f2) == file_size) {
            char fp[65];
            if (crypto_fingerprint(buf, file_size, fp, sizeof(fp)) == CRYPTO_SUCCESS) {
                printf("Type: hybrid public key (X25519 + ML-KEM-1024)\n");
                printf("Fingerprint (SHA-256): %s\n", fp);
            }
        }
        if (f2) fclose(f2);
        free(buf);
        return CRYPTO_SUCCESS;
    }

    /* Otherwise most likely an encrypted secret key. */
    printf("Type: encrypted secret key (passphrase-protected) or unrecognized file\n");
    return CRYPTO_SUCCESS;
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

#define ARMOR_BEGIN "-----BEGIN QSAFE MESSAGE-----\n"
#define ARMOR_END   "-----END QSAFE MESSAGE-----\n"

crypto_error_t crypto_armor(const char *in_path, const char *out_path) {
    FILE *in = open_input(in_path);
    if (!in) { perror("Error opening input file"); return CRYPTO_ERR_FILE_IO; }
    FILE *out = open_output(out_path);
    if (!out) { perror("Error opening output file"); close_stream(in); return CRYPTO_ERR_FILE_IO; }

    crypto_error_t ret = CRYPTO_ERR_CRYPTO;
    EVP_ENCODE_CTX *ectx = EVP_ENCODE_CTX_new();
    unsigned char inbuf[BUFFER_SIZE];
    unsigned char outbuf[BUFFER_SIZE * 2];
    if (!ectx) goto done;
    EVP_EncodeInit(ectx);

    if (fwrite(ARMOR_BEGIN, 1, strlen(ARMOR_BEGIN), out) != strlen(ARMOR_BEGIN)) { ret = CRYPTO_ERR_FILE_IO; goto done; }
    size_t n;
    int outl;
    while ((n = fread(inbuf, 1, sizeof(inbuf), in)) > 0) {
        if (EVP_EncodeUpdate(ectx, outbuf, &outl, inbuf, (int)n) != 1) goto done;
        if (outl > 0 && fwrite(outbuf, 1, (size_t)outl, out) != (size_t)outl) { ret = CRYPTO_ERR_FILE_IO; goto done; }
    }
    if (ferror(in)) { ret = CRYPTO_ERR_FILE_IO; goto done; }
    EVP_EncodeFinal(ectx, outbuf, &outl);
    if (outl > 0 && fwrite(outbuf, 1, (size_t)outl, out) != (size_t)outl) { ret = CRYPTO_ERR_FILE_IO; goto done; }
    if (fwrite(ARMOR_END, 1, strlen(ARMOR_END), out) != strlen(ARMOR_END)) { ret = CRYPTO_ERR_FILE_IO; goto done; }
    ret = CRYPTO_SUCCESS;

done:
    if (ectx) EVP_ENCODE_CTX_free(ectx);
    close_stream(in);
    close_stream(out);
    return ret;
}

crypto_error_t crypto_dearmor(const char *in_path, const char *out_path) {
    FILE *in = open_input(in_path);
    if (!in) { perror("Error opening input file"); return CRYPTO_ERR_FILE_IO; }
    FILE *out = open_output(out_path);
    if (!out) { perror("Error opening output file"); close_stream(in); return CRYPTO_ERR_FILE_IO; }

    crypto_error_t ret = CRYPTO_ERR_CRYPTO;
    EVP_ENCODE_CTX *dctx = EVP_ENCODE_CTX_new();
    char line[1024];
    unsigned char decbuf[sizeof(line)]; /* decoded output is smaller than input */
    int started = 0;
    if (!dctx) goto done;
    EVP_DecodeInit(dctx);

    while (fgets(line, sizeof(line), in)) {
        if (strncmp(line, "-----", 5) == 0) {
            if (strstr(line, "BEGIN")) started = 1;
            else if (strstr(line, "END")) break;
            continue;
        }
        if (!started) continue; /* ignore anything before the BEGIN marker */
        int outl = 0;
        int rc = EVP_DecodeUpdate(dctx, decbuf, &outl, (unsigned char *)line, (int)strlen(line));
        if (rc < 0) {
            fprintf(stderr, "Error: invalid armored input\n");
            ret = CRYPTO_ERR_INVALID_INPUT;
            goto done;
        }
        if (outl > 0 && fwrite(decbuf, 1, (size_t)outl, out) != (size_t)outl) { ret = CRYPTO_ERR_FILE_IO; goto done; }
    }
    if (!started) {
        fprintf(stderr, "Error: no QSAFE armor header found\n");
        ret = CRYPTO_ERR_INVALID_INPUT;
        goto done;
    }
    int outl = 0;
    if (EVP_DecodeFinal(dctx, decbuf, &outl) != 1) {
        fprintf(stderr, "Error: invalid armored input\n");
        ret = CRYPTO_ERR_INVALID_INPUT;
        goto done;
    }
    if (outl > 0 && fwrite(decbuf, 1, (size_t)outl, out) != (size_t)outl) { ret = CRYPTO_ERR_FILE_IO; goto done; }
    ret = CRYPTO_SUCCESS;

done:
    if (dctx) EVP_ENCODE_CTX_free(dctx);
    close_stream(in);
    close_stream(out);
    return ret;
}

/* --- hybrid key-establishment helpers (X25519 + ML-KEM) --- */

/* Generic HKDF-SHA256 expansion of arbitrary input keying material. */
static crypto_error_t hkdf_sha256(const unsigned char *ikm, size_t ikm_len,
                                  const char *info, unsigned char *out, size_t outlen) {
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) { crypto_handle_errors(); return CRYPTO_ERR_CRYPTO; }
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!kctx) { crypto_handle_errors(); return CRYPTO_ERR_CRYPTO; }

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)ikm, ikm_len),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)info, strlen(info)),
        OSSL_PARAM_construct_end()
    };
    crypto_error_t ret = CRYPTO_SUCCESS;
    if (EVP_KDF_derive(kctx, out, outlen, params) != 1) { crypto_handle_errors(); ret = CRYPTO_ERR_CRYPTO; }
    EVP_KDF_CTX_free(kctx);
    return ret;
}

/* Generates an X25519 keypair into raw 32-byte buffers. Returns 1 on success. */
static int x25519_keypair(unsigned char sec[X25519_KEY_SIZE], unsigned char pub[X25519_KEY_SIZE]) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!pctx) return 0;
    EVP_PKEY *pkey = NULL;
    int ok = 0;
    if (EVP_PKEY_keygen_init(pctx) == 1 && EVP_PKEY_keygen(pctx, &pkey) == 1) {
        size_t sl = X25519_KEY_SIZE, pl = X25519_KEY_SIZE;
        if (EVP_PKEY_get_raw_private_key(pkey, sec, &sl) == 1 &&
            EVP_PKEY_get_raw_public_key(pkey, pub, &pl) == 1 &&
            sl == X25519_KEY_SIZE && pl == X25519_KEY_SIZE) {
            ok = 1;
        }
    }
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    return ok;
}

/* Computes the X25519 shared secret between our raw secret and a peer's raw
 * public key. Returns 1 on success. */
static int x25519_dh(const unsigned char sec[X25519_KEY_SIZE],
                     const unsigned char peer_pub[X25519_KEY_SIZE],
                     unsigned char out[X25519_KEY_SIZE]) {
    EVP_PKEY *priv = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, sec, X25519_KEY_SIZE);
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pub, X25519_KEY_SIZE);
    int ok = 0;
    if (priv && peer) {
        EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(priv, NULL);
        size_t outlen = X25519_KEY_SIZE;
        if (dctx && EVP_PKEY_derive_init(dctx) == 1 &&
            EVP_PKEY_derive_set_peer(dctx, peer) == 1 &&
            EVP_PKEY_derive(dctx, out, &outlen) == 1 && outlen == X25519_KEY_SIZE) {
            ok = 1;
        }
        if (dctx) EVP_PKEY_CTX_free(dctx);
    }
    EVP_PKEY_free(priv);
    EVP_PKEY_free(peer);
    return ok;
}

/* AES-256-GCM seal/open of a small buffer (used to wrap the CEK per recipient).
 * Returns 1 on success; gcm_open returns 0 if the tag does not verify. */
static int gcm_seal(const unsigned char key[AES_KEY_SIZE], const unsigned char nonce[AES_GCM_NONCE_SIZE],
                    const unsigned char *pt, int ptlen, unsigned char *ct, unsigned char tag[AES_GCM_TAG_SIZE]) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;
    int len, ok = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) == 1 &&
        EVP_EncryptUpdate(ctx, ct, &len, pt, ptlen) == 1 &&
        EVP_EncryptFinal_ex(ctx, ct + len, &len) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE, tag) == 1) {
        ok = 1;
    }
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int gcm_open(const unsigned char key[AES_KEY_SIZE], const unsigned char nonce[AES_GCM_NONCE_SIZE],
                    const unsigned char *ct, int ctlen, const unsigned char tag[AES_GCM_TAG_SIZE], unsigned char *pt) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;
    int len, ok = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) == 1 &&
        EVP_DecryptUpdate(ctx, pt, &len, ct, ctlen) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE, (void *)tag) == 1 &&
        EVP_DecryptFinal_ex(ctx, pt + len, &len) == 1) {
        ok = 1;
    }
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

/* --- framed-AEAD (v6) helpers --- */

/* Builds the 12-byte nonce for frame `counter`: 3 zero bytes, an 8-byte
 * big-endian counter, and a final byte that is 1 on the last frame else 0.
 * The content key is random per file, so this deterministic per-frame nonce is
 * unique under that key; the counter binds frame order and the final flag makes
 * truncation (a missing final frame) detectable. */
static void frame_nonce(uint64_t counter, int last, unsigned char nonce[AES_GCM_NONCE_SIZE]) {
    memset(nonce, 0, AES_GCM_NONCE_SIZE);
    for (int i = 0; i < 8; i++) {
        nonce[3 + i] = (unsigned char)((counter >> (8 * (7 - i))) & 0xff);
    }
    nonce[11] = last ? 0x01 : 0x00;
}

/* AES-256-GCM seal/open of one frame, with optional additional authenticated
 * data. ct must have room for ptlen bytes; tag is 16 bytes. */
static int gcm_seal_aad(const unsigned char key[AES_KEY_SIZE], const unsigned char nonce[AES_GCM_NONCE_SIZE],
                        const unsigned char *aad, size_t aadlen,
                        const unsigned char *pt, int ptlen, unsigned char *ct, unsigned char tag[AES_GCM_TAG_SIZE]) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;
    int len, ok = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) == 1 &&
        (aadlen == 0 || EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aadlen) == 1) &&
        EVP_EncryptUpdate(ctx, ct, &len, pt, ptlen) == 1 &&
        EVP_EncryptFinal_ex(ctx, ct + len, &len) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE, tag) == 1) {
        ok = 1;
    }
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int gcm_open_aad(const unsigned char key[AES_KEY_SIZE], const unsigned char nonce[AES_GCM_NONCE_SIZE],
                        const unsigned char *aad, size_t aadlen,
                        const unsigned char *ct, int ctlen, const unsigned char tag[AES_GCM_TAG_SIZE], unsigned char *pt) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;
    int len, ok = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) == 1 &&
        (aadlen == 0 || EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aadlen) == 1) &&
        EVP_DecryptUpdate(ctx, pt, &len, ct, ctlen) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE, (void *)tag) == 1 &&
        EVP_DecryptFinal_ex(ctx, pt + len, &len) == 1) {
        ok = 1;
    }
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

/* Padmé padded size (from the PURBs paper): round L up so that only
 * O(log log L) mantissa bits survive, bounding the leak about the true length
 * while keeping overhead under ~12%. Returns the padded length (>= L). */
uint64_t crypto_padme_size(uint64_t L) {
    if (L < 2) return L;
    int E = 63 - __builtin_clzll(L);                 /* floor(log2 L) */
    int S = 64 - __builtin_clzll((uint64_t)E);       /* floor(log2 E) + 1 */
    int last_bits = E - S;
    if (last_bits <= 0) return L;
    uint64_t mask = (1ULL << last_bits) - 1;
    return (L + mask) & ~mask;
}

crypto_error_t crypto_generate_identity(OQS_KEM *kem,
                                        unsigned char **public_blob, size_t *public_len,
                                        unsigned char **secret_blob, size_t *secret_len) {
    *public_blob = NULL;
    *secret_blob = NULL;
    size_t plen = X25519_KEY_SIZE + kem->length_public_key;
    size_t slen = X25519_KEY_SIZE + kem->length_secret_key;

    unsigned char *pub = malloc(plen);
    unsigned char *sec = malloc(slen);
    if (!pub || !sec) {
        free(pub);
        if (sec) { OPENSSL_cleanse(sec, slen); free(sec); }
        return CRYPTO_ERR_MEMORY;
    }

    if (!x25519_keypair(sec, pub)) {
        fprintf(stderr, "Error: X25519 keypair generation failed\n");
        crypto_handle_errors();
        free(pub); OPENSSL_cleanse(sec, slen); free(sec);
        return CRYPTO_ERR_CRYPTO;
    }
    if (OQS_KEM_keypair(kem, pub + X25519_KEY_SIZE, sec + X25519_KEY_SIZE) != OQS_SUCCESS) {
        fprintf(stderr, "Error: ML-KEM keypair generation failed\n");
        free(pub); OPENSSL_cleanse(sec, slen); free(sec);
        return CRYPTO_ERR_CRYPTO;
    }

    *public_blob = pub;
    *public_len = plen;
    *secret_blob = sec;
    *secret_len = slen;
    return CRYPTO_SUCCESS;
}

/* Builds one recipient record into `rec` (size = X25519_KEY_SIZE + kem ct +
 * nonce + key_len + tag) wrapping `key` to recipient_pub, deriving the KEK
 * under `label` (domain separation per consuming format). */
crypto_error_t crypto_hybrid_wrap(OQS_KEM *kem, const unsigned char *recipient_pub,
                                  const char *label, const unsigned char *key,
                                  size_t key_len, unsigned char *rec) {
    crypto_error_t ret = CRYPTO_ERR_CRYPTO;
    unsigned char eph_sec[X25519_KEY_SIZE];
    unsigned char dh[X25519_KEY_SIZE];
    unsigned char *kem_ss = malloc(kem->length_shared_secret);
    unsigned char ikm[X25519_KEY_SIZE + 64]; /* dh || kem_ss (ss <= 32 for ML-KEM) */
    unsigned char kek[AES_KEY_SIZE];
    if (!kem_ss) { return CRYPTO_ERR_MEMORY; }

    unsigned char *p_eph = rec;
    unsigned char *p_ct  = p_eph + X25519_KEY_SIZE;
    unsigned char *p_non = p_ct + kem->length_ciphertext;
    unsigned char *p_key = p_non + AES_GCM_NONCE_SIZE;
    unsigned char *p_tag = p_key + key_len;

    if (!x25519_keypair(eph_sec, p_eph)) goto done;
    if (!x25519_dh(eph_sec, recipient_pub, dh)) goto done;
    if (OQS_KEM_encaps(kem, p_ct, kem_ss, recipient_pub + X25519_KEY_SIZE) != OQS_SUCCESS) goto done;

    memcpy(ikm, dh, X25519_KEY_SIZE);
    memcpy(ikm + X25519_KEY_SIZE, kem_ss, kem->length_shared_secret);
    if (hkdf_sha256(ikm, X25519_KEY_SIZE + kem->length_shared_secret, label, kek, sizeof(kek)) != CRYPTO_SUCCESS) goto done;

    if (RAND_bytes(p_non, AES_GCM_NONCE_SIZE) != 1) goto done;
    if (!gcm_seal(kek, p_non, key, (int)key_len, p_key, p_tag)) goto done;
    ret = CRYPTO_SUCCESS;

done:
    OPENSSL_cleanse(eph_sec, sizeof(eph_sec));
    OPENSSL_cleanse(dh, sizeof(dh));
    OPENSSL_cleanse(ikm, sizeof(ikm));
    OPENSSL_cleanse(kek, sizeof(kek));
    if (kem_ss) { OPENSSL_cleanse(kem_ss, kem->length_shared_secret); free(kem_ss); }
    return ret;
}

/* Attempts to recover a wrapped key from one recipient record using our secret
 * blob. Returns 1 if the wrap authenticates (key filled), 0 otherwise. */
int crypto_hybrid_unwrap(OQS_KEM *kem, const unsigned char *secret_blob,
                         const char *label, const unsigned char *rec,
                         size_t key_len, unsigned char *key_out) {
    const unsigned char *p_eph = rec;
    const unsigned char *p_ct  = p_eph + X25519_KEY_SIZE;
    const unsigned char *p_non = p_ct + kem->length_ciphertext;
    const unsigned char *p_key = p_non + AES_GCM_NONCE_SIZE;
    const unsigned char *p_tag = p_key + key_len;

    unsigned char dh[X25519_KEY_SIZE];
    unsigned char *kem_ss = malloc(kem->length_shared_secret);
    unsigned char ikm[X25519_KEY_SIZE + 64];
    unsigned char kek[AES_KEY_SIZE];
    int ok = 0;
    if (!kem_ss) return 0;

    if (!x25519_dh(secret_blob, p_eph, dh)) goto done;
    if (OQS_KEM_decaps(kem, kem_ss, p_ct, secret_blob + X25519_KEY_SIZE) != OQS_SUCCESS) goto done;
    memcpy(ikm, dh, X25519_KEY_SIZE);
    memcpy(ikm + X25519_KEY_SIZE, kem_ss, kem->length_shared_secret);
    if (hkdf_sha256(ikm, X25519_KEY_SIZE + kem->length_shared_secret, label, kek, sizeof(kek)) != CRYPTO_SUCCESS) goto done;
    ok = gcm_open(kek, p_non, p_key, (int)key_len, p_tag, key_out);

done:
    OPENSSL_cleanse(dh, sizeof(dh));
    OPENSSL_cleanse(ikm, sizeof(ikm));
    OPENSSL_cleanse(kek, sizeof(kek));
    if (kem_ss) { OPENSSL_cleanse(kem_ss, kem->length_shared_secret); free(kem_ss); }
    return ok;
}

/* v5/v6/v7 container wrappers (fixed 32-byte CEK, v5 hybrid label). */
static crypto_error_t hybrid_wrap_cek(OQS_KEM *kem, const unsigned char *recipient_pub,
                                      const unsigned char cek[QSAFE_CEK_SIZE], unsigned char *rec) {
    return crypto_hybrid_wrap(kem, recipient_pub, HKDF_HYBRID_LABEL, cek, QSAFE_CEK_SIZE, rec);
}

static int hybrid_unwrap_cek(OQS_KEM *kem, const unsigned char *secret_blob,
                             const unsigned char *rec, unsigned char cek[QSAFE_CEK_SIZE]) {
    return crypto_hybrid_unwrap(kem, secret_blob, HKDF_HYBRID_LABEL, rec, QSAFE_CEK_SIZE, cek);
}

crypto_error_t crypto_encrypt_file(const char *input_filename, const char *output_filename, OQS_KEM *kem,
                                   const unsigned char *const *recipient_pubs, size_t n_recipients,
                                   const crypto_config_t *config) {

    crypto_error_t ret = CRYPTO_ERR_CRYPTO;
    unsigned char *header = NULL;      /* magic | count | records (v6: no payload nonce) */
    size_t header_len = 0;
    unsigned char *frame_pt = NULL;    /* one plaintext frame */
    unsigned char *frame_ct = NULL;    /* one ciphertext frame */
    FILE *in_file = NULL;
    FILE *out_file = NULL;
    int output_created = 0;
    int from_stdin = is_stream_arg(input_filename);
    unsigned char nonce[AES_GCM_NONCE_SIZE];
    unsigned char tag[AES_GCM_TAG_SIZE];
    unsigned char meta[QSAFE_META_SIZE_V7];
    unsigned char cek[QSAFE_CEK_SIZE];

    /* v7 signed-sender mode state. */
    int signing = (config->sign_sk_file != NULL);
    OQS_SIG *sig = NULL;
    unsigned char *sig_sk = NULL;
    unsigned char *sig_pk = NULL;
    size_t sig_sk_len = 0;
    EVP_MD_CTX *sig_md = NULL;
    unsigned char trailer[QSAFE_TRAILER_SIZE];

    if (n_recipients == 0 || n_recipients > QSAFE_MAX_RECIPIENTS) {
        fprintf(stderr, "Error: recipient count must be between 1 and %d\n", QSAFE_MAX_RECIPIENTS);
        return CRYPTO_ERR_INVALID_INPUT;
    }

    if (signing) {
        sig = OQS_SIG_new(QSAFE_SIG_ALG);
        if (!sig || sig->length_public_key != QSAFE_SIG_PUB_SIZE ||
            sig->length_signature != QSAFE_SIG_MAX_SIZE) {
            fprintf(stderr, "Error: ML-DSA-87 is not available in this liboqs build\n");
            if (sig) OQS_SIG_free(sig);
            return CRYPTO_ERR_CRYPTO;
        }
        sig_sk = crypto_load_secret_key(config->sign_sk_file, &sig_sk_len, config);
        if (!sig_sk || sig_sk_len != sig->length_secret_key) {
            fprintf(stderr, "Error: failed to load signing secret key (wrong passphrase or not a signing key)\n");
            if (sig_sk) { OPENSSL_cleanse(sig_sk, sig_sk_len); free(sig_sk); }
            OQS_SIG_free(sig);
            return CRYPTO_ERR_FILE_IO;
        }
        sig_pk = crypto_load_public_key(config->sign_pk_file, QSAFE_SIG_PUB_SIZE, config);
        if (!sig_pk) {
            fprintf(stderr, "Error: failed to load signing public key '%s'\n",
                    config->sign_pk_file ? config->sign_pk_file : "(null)");
            OPENSSL_cleanse(sig_sk, sig_sk_len); free(sig_sk);
            OQS_SIG_free(sig);
            return CRYPTO_ERR_FILE_IO;
        }
    }

    in_file = open_input(input_filename);
    if (!in_file) {
        perror("Error opening input file");
        ret = CRYPTO_ERR_FILE_IO;
        goto cleanup;
    }

    /* Build the v7 metadata block. For real files we capture the original name,
     * permission bits, mtime, and content length; for stdin the length is
     * unknown (and padding, which needs it, is unavailable). */
    memset(meta, 0, sizeof(meta));
    size_t file_size = 0;
    int have_size = 0;
    uint64_t content_len = QSAFE_LEN_UNKNOWN;
    uint64_t pad_len = 0;
    if (!from_stdin) {
        struct stat st;
        if (stat(input_filename, &st) == 0) {
            file_size = (size_t)st.st_size;
            have_size = 1;
            content_len = (uint64_t)st.st_size;

            const char *base = path_basename(input_filename);
            size_t name_len = strlen(base);
            if (name_len > QSAFE_MAX_NAME) name_len = QSAFE_MAX_NAME;

            meta[0] |= QSAFE_META_FLAG_PRESENT;
            store_u16(meta + 2, (uint16_t)name_len);
            memcpy(meta + 4, base, name_len);
            store_u32(meta + 4 + QSAFE_META_NAME_FIELD, (uint32_t)(st.st_mode & 0777));
            store_u64(meta + 4 + QSAFE_META_NAME_FIELD + 4, (uint64_t)st.st_mtime);
        }
    }
    if (config->pad) {
        if (content_len == QSAFE_LEN_UNKNOWN) {
            fprintf(stderr, "Error: --pad requires a regular file input (stdin length is unknown)\n");
            ret = CRYPTO_ERR_INVALID_INPUT;
            goto cleanup;
        }
        pad_len = crypto_padme_size(content_len) - content_len;
        if (pad_len > 0) meta[0] |= QSAFE_META_FLAG_PADDED;
    }
    if (signing) meta[0] |= QSAFE_META_FLAG_SIGNED;
    store_u64(meta + QSAFE_META_SIZE, content_len);
    store_u64(meta + QSAFE_META_SIZE + 8, pad_len);

    /* Random content key; per-frame nonces are derived from a counter (§ frame_nonce). */
    if (RAND_bytes(cek, QSAFE_CEK_SIZE) != 1) {
        fprintf(stderr, "Error: Failed to generate random key\n");
        goto cleanup;
    }

    frame_pt = malloc(QSAFE_FRAME_SIZE);
    frame_ct = malloc(QSAFE_FRAME_SIZE);
    if (!frame_pt || !frame_ct) {
        fprintf(stderr, "Error: Failed to allocate memory\n");
        ret = CRYPTO_ERR_MEMORY;
        goto cleanup;
    }

    /* Header: magic(8) | recipient_count(1) | record[0..R-1]. */
    size_t record_size = X25519_KEY_SIZE + kem->length_ciphertext +
                         AES_GCM_NONCE_SIZE + QSAFE_CEK_SIZE + AES_GCM_TAG_SIZE;
    size_t prefix = VERSION_HEADER_SIZE + 1;
    header_len = prefix + n_recipients * record_size;
    header = malloc(header_len);
    if (!header) {
        fprintf(stderr, "Error: Failed to allocate memory\n");
        ret = CRYPTO_ERR_MEMORY;
        goto cleanup;
    }
    memcpy(header, VERSION_HEADER_V7, VERSION_HEADER_SIZE);
    header[VERSION_HEADER_SIZE] = (unsigned char)n_recipients;
    for (size_t i = 0; i < n_recipients; i++) {
        unsigned char *rec = header + prefix + i * record_size;
        crypto_error_t wr = hybrid_wrap_cek(kem, recipient_pubs[i], cek, rec);
        if (wr != CRYPTO_SUCCESS) {
            fprintf(stderr, "Error: failed to wrap key for recipient %zu\n", i + 1);
            ret = wr;
            goto cleanup;
        }
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

    if (fwrite(header, 1, header_len, out_file) != header_len) {
        fprintf(stderr, "Error: Failed to write file header\n");
        ret = CRYPTO_ERR_FILE_IO;
        goto cleanup;
    }

    /* Plaintext stream = META ‖ contents ‖ [signature trailer] ‖ [padding],
     * emitted as authenticated frames. A full QSAFE_FRAME_SIZE frame is
     * non-final; the first short/empty frame ends the stream as the final
     * frame, so the final frame is always strictly shorter on the wire.
     *
     * When signing, the embedded signature covers
     * SHA-256(QSAFE_SIGNED_CONTEXT ‖ header ‖ META ‖ contents), computed
     * incrementally so the input still streams in constant memory. */
    if (signing) {
        sig_md = EVP_MD_CTX_new();
        if (!sig_md || EVP_DigestInit_ex(sig_md, EVP_sha256(), NULL) != 1 ||
            EVP_DigestUpdate(sig_md, QSAFE_SIGNED_CONTEXT, strlen(QSAFE_SIGNED_CONTEXT)) != 1 ||
            EVP_DigestUpdate(sig_md, header, header_len) != 1 ||
            EVP_DigestUpdate(sig_md, meta, QSAFE_META_SIZE_V7) != 1) {
            fprintf(stderr, "Error: failed to initialize signing digest\n");
            crypto_handle_errors();
            goto cleanup;
        }
    }
    {
        size_t meta_off = 0;
        uint64_t ctr = 0;
        uint64_t content_left = content_len;   /* QSAFE_LEN_UNKNOWN for streams */
        uint64_t pad_left = pad_len;
        size_t trailer_off = 0;
        int content_done = 0, trailer_built = 0;
        size_t total_processed = 0, last_report = 0;
        int done = 0;
        while (!done) {
            size_t filled = 0;
            /* 1) metadata block */
            if (meta_off < QSAFE_META_SIZE_V7) {
                size_t take = QSAFE_META_SIZE_V7 - meta_off;
                if (take > QSAFE_FRAME_SIZE) take = QSAFE_FRAME_SIZE;
                memcpy(frame_pt, meta + meta_off, take);
                meta_off += take;
                filled = take;
            }
            /* 2) file contents. With a known length we read exactly that many
             * bytes, so a file that shrinks or grows mid-encrypt is an error
             * rather than a malformed container. */
            while (!content_done && filled < QSAFE_FRAME_SIZE) {
                size_t want = QSAFE_FRAME_SIZE - filled;
                if (content_len != QSAFE_LEN_UNKNOWN && content_left < (uint64_t)want) {
                    want = (size_t)content_left;
                }
                size_t n = want ? fread(frame_pt + filled, 1, want, in_file) : 0;
                if (n == 0) {
                    if (ferror(in_file)) {
                        fprintf(stderr, "Error: Failed to read input file\n");
                        ret = CRYPTO_ERR_FILE_IO;
                        goto cleanup;
                    }
                    if (content_len != QSAFE_LEN_UNKNOWN && content_left != 0) {
                        fprintf(stderr, "Error: input shrank while encrypting\n");
                        ret = CRYPTO_ERR_FILE_IO;
                        goto cleanup;
                    }
                    content_done = 1;
                    break;
                }
                if (sig_md && EVP_DigestUpdate(sig_md, frame_pt + filled, n) != 1) {
                    fprintf(stderr, "Error: signing digest failed\n");
                    goto cleanup;
                }
                filled += n;
                if (content_len != QSAFE_LEN_UNKNOWN) {
                    content_left -= n;
                    if (content_left == 0) content_done = 1;
                }
            }
            /* 3) signature trailer: signer_pub | u16 sig_len | sig (zero-padded) */
            if (content_done && signing) {
                if (!trailer_built) {
                    unsigned char digest[32];
                    unsigned int dl = 0;
                    size_t sl = 0;
                    if (EVP_DigestFinal_ex(sig_md, digest, &dl) != 1 || dl != 32) {
                        fprintf(stderr, "Error: signing digest failed\n");
                        goto cleanup;
                    }
                    memset(trailer, 0, sizeof(trailer));
                    memcpy(trailer, sig_pk, QSAFE_SIG_PUB_SIZE);
                    if (OQS_SIG_sign(sig, trailer + QSAFE_SIG_PUB_SIZE + 2, &sl,
                                     digest, sizeof(digest), sig_sk) != OQS_SUCCESS ||
                        sl == 0 || sl > QSAFE_SIG_MAX_SIZE) {
                        fprintf(stderr, "Error: embedded signing failed\n");
                        goto cleanup;
                    }
                    store_u16(trailer + QSAFE_SIG_PUB_SIZE, (uint16_t)sl);
                    trailer_built = 1;
                }
                if (trailer_off < QSAFE_TRAILER_SIZE && filled < QSAFE_FRAME_SIZE) {
                    size_t take = QSAFE_TRAILER_SIZE - trailer_off;
                    if (take > QSAFE_FRAME_SIZE - filled) take = QSAFE_FRAME_SIZE - filled;
                    memcpy(frame_pt + filled, trailer + trailer_off, take);
                    trailer_off += take;
                    filled += take;
                }
            }
            /* 4) size-hiding padding (random bytes; discarded on decrypt) */
            if (content_done && (!signing || trailer_off == QSAFE_TRAILER_SIZE) &&
                filled < QSAFE_FRAME_SIZE && pad_left > 0) {
                size_t take = QSAFE_FRAME_SIZE - filled;
                if ((uint64_t)take > pad_left) take = (size_t)pad_left;
                if (RAND_bytes(frame_pt + filled, (int)take) != 1) {
                    fprintf(stderr, "Error: failed to generate padding\n");
                    goto cleanup;
                }
                pad_left -= take;
                filled += take;
            }

            int last = (filled < QSAFE_FRAME_SIZE) ? 1 : 0;
            frame_nonce(ctr, last, nonce);
            /* Bind the header into the first frame only; the counter+flag nonce
             * orders the rest and makes truncation detectable. */
            const unsigned char *aad = (ctr == 0) ? header : NULL;
            size_t aadlen = (ctr == 0) ? header_len : 0;
            if (!gcm_seal_aad(cek, nonce, aad, aadlen, frame_pt, (int)filled, frame_ct, tag)) {
                fprintf(stderr, "Error: AES-GCM frame encryption failed\n");
                crypto_handle_errors();
                goto cleanup;
            }
            if ((filled > 0 && fwrite(frame_ct, 1, filled, out_file) != filled) ||
                fwrite(tag, 1, AES_GCM_TAG_SIZE, out_file) != AES_GCM_TAG_SIZE) {
                fprintf(stderr, "Error: Failed to write frame\n");
                ret = CRYPTO_ERR_FILE_IO;
                goto cleanup;
            }
            ctr++;
            if (last) done = 1;

            if (have_size) {
                total_processed += filled;
                if (total_processed - last_report >= (1u << 20)) {
                    crypto_print_progress_bar(total_processed, file_size + QSAFE_META_SIZE);
                    last_report = total_processed;
                }
            }
        }
        if (have_size && file_size > 0) fprintf(stderr, "\n");
    }

    ret = CRYPTO_SUCCESS;

cleanup:
    close_stream(in_file);
    close_stream(out_file);
    if (frame_pt) { OPENSSL_cleanse(frame_pt, QSAFE_FRAME_SIZE); free(frame_pt); }
    free(frame_ct);
    free(header); /* records hold only public material; the CEK is cleansed below */
    OPENSSL_cleanse(cek, sizeof(cek));
    if (sig_md) EVP_MD_CTX_free(sig_md);
    if (sig_sk) { OPENSSL_cleanse(sig_sk, sig_sk_len); free(sig_sk); }
    free(sig_pk);
    if (sig) OQS_SIG_free(sig);
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
    size_t meta_need;          /* 288 for v7, 272 for v5/v6 */
    unsigned char meta[QSAFE_META_SIZE_V7];

    int has_meta;
    char name[QSAFE_MAX_NAME + 1];
    unsigned int mode;
    uint64_t mtime;

    /* v7 payload routing: contents, then an optional fixed-size signature
     * trailer, then optional padding. */
    int is_v7;
    int signed_mode;           /* META flag bit 1: signature trailer present */
    int padded;                /* META flag bit 2: padding present */
    uint64_t content_len;      /* QSAFE_LEN_UNKNOWN when the encryptor streamed */
    uint64_t pad_len;
    uint64_t content_written;
    uint64_t pad_seen;
    unsigned char tbuf[QSAFE_TRAILER_SIZE]; /* trailer (or rolling holdback) */
    size_t tlen;
    EVP_MD_CTX *sig_md;        /* SHA-256(ctx ‖ header ‖ META ‖ contents) */
    const unsigned char *header_ptr; /* container header, hashed when signed */
    size_t header_len;

    FILE *out;
    int out_created;
    int to_stdout;
    int skipped;
    int verify_only;          /* authenticate without writing any plaintext */
    int frame_verified;       /* v6: input is verified per-frame, so never defer */
    char out_path[MAX_PATH_LENGTH];

    /* When the output is a pipe/stdout, decrypted plaintext is held in this
     * buffer and only flushed once the GCM tag has verified (see dec_sink_commit).
     * This avoids releasing unverified plaintext to a downstream consumer, at the
     * cost of buffering the whole payload in memory. File outputs stream directly
     * and are removed on authentication failure instead. */
    int defer;
    unsigned char *buf;
    size_t buf_len;
    size_t buf_cap;

    const char *output_arg;
    const crypto_config_t *config;
} dec_sink_t;

/* Resolves the output path and opens it once metadata has been parsed.
 * Returns CRYPTO_SUCCESS (out opened, or user skipped) or an error code. */
static crypto_error_t dec_sink_open(dec_sink_t *s) {
    /* Verify-only: parse metadata but never open or write an output file. */
    if (s->verify_only) {
        return CRYPTO_SUCCESS;
    }

    if (is_stream_arg(s->output_arg)) {
        s->to_stdout = 1;
        s->out = stdout;
        /* v5 buffers stdout until the single tag verifies; v6 verifies each
         * frame before release, so it can stream straight through. */
        s->defer = s->frame_verified ? 0 : 1;
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

/* Emits authenticated content bytes to the output (or drops them for
 * verify-only / user-skipped runs). Deferred outputs accumulate instead. */
static crypto_error_t dec_sink_emit(dec_sink_t *s, const unsigned char *p, size_t n) {
    if (n == 0 || s->skipped || !s->out) {
        return CRYPTO_SUCCESS;
    }

    /* Pipe/stdout (v5): accumulate, do not release until the tag verifies. */
    if (s->defer) {
        if (s->buf_len + n > s->buf_cap) {
            size_t newcap = s->buf_cap ? s->buf_cap : BUFFER_SIZE;
            while (newcap < s->buf_len + n) {
                if (newcap > (SIZE_MAX / 2)) { newcap = s->buf_len + n; break; }
                newcap *= 2;
            }
            unsigned char *nb = realloc(s->buf, newcap);
            if (!nb) {
                fprintf(stderr, "Error: out of memory buffering pipe output\n");
                return CRYPTO_ERR_MEMORY;
            }
            s->buf = nb;
            s->buf_cap = newcap;
        }
        memcpy(s->buf + s->buf_len, p, n);
        s->buf_len += n;
        return CRYPTO_SUCCESS;
    }

    if (fwrite(p, 1, n, s->out) != n) {
        fprintf(stderr, "Error: Failed to write output file\n");
        return CRYPTO_ERR_FILE_IO;
    }
    return CRYPTO_SUCCESS;
}

/* One byte-chunk of file *contents*: hash it (signed mode) and emit it. */
static crypto_error_t dec_sink_content(dec_sink_t *s, const unsigned char *p, size_t n) {
    if (s->sig_md && n > 0 && EVP_DigestUpdate(s->sig_md, p, n) != 1) {
        fprintf(stderr, "Error: signature digest failed\n");
        return CRYPTO_ERR_CRYPTO;
    }
    s->content_written += n;
    return dec_sink_emit(s, p, n);
}

/* Feed decrypted plaintext bytes through the sink. Returns CRYPTO_SUCCESS or an
 * error code. */
static crypto_error_t dec_sink_write(dec_sink_t *s, const unsigned char *p, size_t n) {
    if (!s->meta_done) {
        size_t need = s->meta_need - s->meta_have;
        size_t take = n < need ? n : need;
        memcpy(s->meta + s->meta_have, p, take);
        s->meta_have += take;
        p += take;
        n -= take;

        if (s->meta_have < s->meta_need) {
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
        if (s->is_v7) {
            s->signed_mode = (s->meta[0] & QSAFE_META_FLAG_SIGNED) != 0;
            s->padded = (s->meta[0] & QSAFE_META_FLAG_PADDED) != 0;
            s->content_len = load_u64(s->meta + QSAFE_META_SIZE);
            s->pad_len = load_u64(s->meta + QSAFE_META_SIZE + 8);
            /* Padding needs a declared length to strip; the pad flag and pad
             * length must agree. */
            if ((s->padded && (s->content_len == QSAFE_LEN_UNKNOWN || s->pad_len == 0)) ||
                (!s->padded && s->pad_len != 0)) {
                fprintf(stderr, "Error: inconsistent padding declaration in metadata\n");
                return CRYPTO_ERR_INVALID_INPUT;
            }
            if (s->signed_mode) {
                s->sig_md = EVP_MD_CTX_new();
                if (!s->sig_md ||
                    EVP_DigestInit_ex(s->sig_md, EVP_sha256(), NULL) != 1 ||
                    EVP_DigestUpdate(s->sig_md, QSAFE_SIGNED_CONTEXT, strlen(QSAFE_SIGNED_CONTEXT)) != 1 ||
                    EVP_DigestUpdate(s->sig_md, s->header_ptr, s->header_len) != 1 ||
                    EVP_DigestUpdate(s->sig_md, s->meta, QSAFE_META_SIZE_V7) != 1) {
                    fprintf(stderr, "Error: failed to initialize signature digest\n");
                    return CRYPTO_ERR_CRYPTO;
                }
            }
        }
        s->meta_done = 1;

        crypto_error_t orc = dec_sink_open(s);
        if (orc != CRYPTO_SUCCESS) return orc;
    }

    if (n == 0) {
        return CRYPTO_SUCCESS;
    }

    /* v5/v6 payloads (and unsigned, unpadded v7 streams) are pure contents. */
    if (!s->is_v7 || (!s->signed_mode && !s->padded && s->content_len == QSAFE_LEN_UNKNOWN)) {
        return dec_sink_emit(s, p, n);
    }

    /* Known content length: split contents | trailer | padding exactly. */
    if (s->content_len != QSAFE_LEN_UNKNOWN) {
        while (n > 0) {
            if (s->content_written < s->content_len) {
                uint64_t left = s->content_len - s->content_written;
                size_t take = (uint64_t)n < left ? n : (size_t)left;
                crypto_error_t rc = dec_sink_content(s, p, take);
                if (rc != CRYPTO_SUCCESS) return rc;
                p += take;
                n -= take;
            } else if (s->signed_mode && s->tlen < QSAFE_TRAILER_SIZE) {
                size_t take = QSAFE_TRAILER_SIZE - s->tlen;
                if (take > n) take = n;
                memcpy(s->tbuf + s->tlen, p, take);
                s->tlen += take;
                p += take;
                n -= take;
            } else if (s->pad_seen < s->pad_len) {
                uint64_t left = s->pad_len - s->pad_seen;
                size_t take = (uint64_t)n < left ? n : (size_t)left;
                s->pad_seen += take; /* padding is discarded */
                p += take;
                n -= take;
            } else {
                fprintf(stderr, "Error: encrypted payload longer than declared\n");
                return CRYPTO_ERR_INVALID_INPUT;
            }
        }
        return CRYPTO_SUCCESS;
    }

    /* Unknown content length with a signature trailer (signed stdin stream):
     * hold back the last QSAFE_TRAILER_SIZE bytes; everything older is
     * contents. */
    {
        size_t total = s->tlen + n;
        if (total > QSAFE_TRAILER_SIZE) {
            size_t release = total - QSAFE_TRAILER_SIZE;
            size_t from_buf = release < s->tlen ? release : s->tlen;
            if (from_buf > 0) {
                crypto_error_t rc = dec_sink_content(s, s->tbuf, from_buf);
                if (rc != CRYPTO_SUCCESS) return rc;
                memmove(s->tbuf, s->tbuf + from_buf, s->tlen - from_buf);
                s->tlen -= from_buf;
                release -= from_buf;
            }
            if (release > 0) {
                crypto_error_t rc = dec_sink_content(s, p, release);
                if (rc != CRYPTO_SUCCESS) return rc;
                p += release;
                n -= release;
            }
        }
        memcpy(s->tbuf + s->tlen, p, n);
        s->tlen += n;
        return CRYPTO_SUCCESS;
    }
}

/* Called once every frame has authenticated: enforce the declared layout and
 * verify the embedded sender signature, if any. */
static crypto_error_t dec_sink_finish(dec_sink_t *s, const crypto_config_t *config) {
    if (!s->is_v7) return CRYPTO_SUCCESS;

    if (s->content_len != QSAFE_LEN_UNKNOWN) {
        if (s->content_written != s->content_len ||
            (s->signed_mode && s->tlen != QSAFE_TRAILER_SIZE) ||
            s->pad_seen != s->pad_len) {
            fprintf(stderr, "Error: encrypted payload shorter than declared\n");
            return CRYPTO_ERR_INVALID_INPUT;
        }
    } else if (s->signed_mode && s->tlen != QSAFE_TRAILER_SIZE) {
        fprintf(stderr, "Error: signed file is too short to contain its signature\n");
        return CRYPTO_ERR_INVALID_INPUT;
    }

    if (!s->signed_mode) return CRYPTO_SUCCESS;

    const unsigned char *signer_pk = s->tbuf;
    uint16_t sl = load_u16(s->tbuf + QSAFE_SIG_PUB_SIZE);
    if (sl == 0 || sl > QSAFE_SIG_MAX_SIZE) {
        fprintf(stderr, "Error: invalid embedded signature length\n");
        return CRYPTO_ERR_INVALID_INPUT;
    }

    unsigned char digest[32];
    unsigned int dl = 0;
    if (EVP_DigestFinal_ex(s->sig_md, digest, &dl) != 1 || dl != 32) {
        fprintf(stderr, "Error: signature digest failed\n");
        return CRYPTO_ERR_CRYPTO;
    }

    OQS_SIG *sig = OQS_SIG_new(QSAFE_SIG_ALG);
    if (!sig) {
        fprintf(stderr, "Error: ML-DSA-87 is not available in this liboqs build\n");
        return CRYPTO_ERR_CRYPTO;
    }
    OQS_STATUS vr = OQS_SIG_verify(sig, digest, sizeof(digest),
                                   s->tbuf + QSAFE_SIG_PUB_SIZE + 2, sl, signer_pk);
    OQS_SIG_free(sig);
    if (vr != OQS_SUCCESS) {
        fprintf(stderr, "Error: embedded sender signature verification FAILED\n");
        return CRYPTO_ERR_INTEGRITY;
    }

    /* --signer: pin the embedded signer to a specific public key. */
    if (config->signer_pk_file) {
        unsigned char *expect = crypto_load_public_key(config->signer_pk_file,
                                                       QSAFE_SIG_PUB_SIZE, config);
        if (!expect) {
            fprintf(stderr, "Error: failed to load expected signer key '%s'\n",
                    config->signer_pk_file);
            return CRYPTO_ERR_FILE_IO;
        }
        int match = (CRYPTO_memcmp(expect, signer_pk, QSAFE_SIG_PUB_SIZE) == 0);
        free(expect);
        if (!match) {
            fprintf(stderr, "Error: file is signed, but not by the expected signer\n");
            return CRYPTO_ERR_INTEGRITY;
        }
    }

    char fp[65];
    if (crypto_fingerprint(signer_pk, QSAFE_SIG_PUB_SIZE, fp, sizeof(fp)) == CRYPTO_SUCCESS) {
        fprintf(stderr, "Signed by (ML-DSA-87, SHA-256 fingerprint): %s\n", fp);
    }
    return CRYPTO_SUCCESS;
}

/* Releases buffered (deferred) plaintext to the output. Call ONLY after the
 * AEAD tag has been verified. No-op when output streamed directly. */
static crypto_error_t dec_sink_commit(dec_sink_t *s) {
    if (!s->defer || s->buf_len == 0 || !s->out) {
        return CRYPTO_SUCCESS;
    }
    if (fwrite(s->buf, 1, s->buf_len, s->out) != s->buf_len) {
        fprintf(stderr, "Error: Failed to write output\n");
        return CRYPTO_ERR_FILE_IO;
    }
    return CRYPTO_SUCCESS;
}

crypto_error_t crypto_decrypt_file(const char *input_filename, const char *output_filename, OQS_KEM *kem,
                                   const unsigned char *secret_blob, const crypto_config_t *config) {
    crypto_error_t ret = CRYPTO_ERR_CRYPTO;
    unsigned char *header = NULL;     /* exact header bytes, re-fed as AAD */
    unsigned char *in_buffer = NULL;  /* v5 */
    unsigned char *out_buffer = NULL; /* v5 */
    unsigned char *work = NULL;       /* v5 */
    unsigned char *cbuf = NULL;       /* v6: one ciphertext frame */
    unsigned char *pbuf = NULL;       /* v6: one plaintext frame */
    EVP_CIPHER_CTX *ctx = NULL;
    FILE *in_file = NULL;
    unsigned char nonce[AES_GCM_NONCE_SIZE];
    unsigned char tag[AES_GCM_TAG_SIZE];
    unsigned char hold[AES_GCM_TAG_SIZE];
    unsigned char cek[QSAFE_CEK_SIZE];
    unsigned char magic[VERSION_HEADER_SIZE];
    int have_cek = 0;
    int framed = 0;   /* v6/v7 framed payload vs. v5 single-AEAD */
    int is_v7 = 0;
    size_t holdn = 0;

    dec_sink_t sink;
    memset(&sink, 0, sizeof(sink));
    sink.output_arg = output_filename;
    sink.config = config;
    sink.verify_only = config->check_only;
    sink.content_len = QSAFE_LEN_UNKNOWN;

    in_file = open_input(input_filename);
    if (!in_file) {
        perror("Error opening input file");
        return CRYPTO_ERR_FILE_IO;
    }

    /* Identify the format by its 8-byte magic (v7/v6 = framed, v5 = single-AEAD). */
    if (fread(magic, 1, sizeof(magic), in_file) != sizeof(magic)) {
        fprintf(stderr, "Error: Invalid file format or version\n");
        ret = CRYPTO_ERR_INVALID_INPUT;
        goto cleanup;
    }
    if (memcmp(magic, VERSION_HEADER_V7, VERSION_HEADER_SIZE) == 0) {
        framed = 1;
        is_v7 = 1;
    } else if (memcmp(magic, VERSION_HEADER_V6, VERSION_HEADER_SIZE) == 0) {
        framed = 1;
    } else if (memcmp(magic, VERSION_HEADER, VERSION_HEADER_SIZE) == 0) {
        framed = 0;
    } else {
        fprintf(stderr, "Error: Invalid file format or version\n");
        ret = CRYPTO_ERR_INVALID_INPUT;
        goto cleanup;
    }
    sink.is_v7 = is_v7;
    sink.meta_need = is_v7 ? QSAFE_META_SIZE_V7 : QSAFE_META_SIZE;

    unsigned char cnt;
    if (fread(&cnt, 1, 1, in_file) != 1) {
        fprintf(stderr, "Error: truncated header\n");
        ret = CRYPTO_ERR_INVALID_INPUT;
        goto cleanup;
    }
    size_t n_recipients = cnt;
    if (n_recipients == 0 || n_recipients > QSAFE_MAX_RECIPIENTS) {
        fprintf(stderr, "Error: invalid recipient count in header\n");
        ret = CRYPTO_ERR_INVALID_INPUT;
        goto cleanup;
    }

    size_t record_size = X25519_KEY_SIZE + kem->length_ciphertext +
                         AES_GCM_NONCE_SIZE + QSAFE_CEK_SIZE + AES_GCM_TAG_SIZE;

    /* Reconstruct the exact header bytes for AAD:
     *   v5:    magic(8) | count(1) | payload_nonce(12) | records
     *   v6/v7: magic(8) | count(1) | records                       */
    size_t prefix = VERSION_HEADER_SIZE + 1 + (framed ? 0 : AES_GCM_NONCE_SIZE);
    size_t header_len = prefix + n_recipients * record_size;
    header = malloc(header_len);
    if (!header) {
        ret = CRYPTO_ERR_MEMORY;
        goto cleanup;
    }
    memcpy(header, magic, VERSION_HEADER_SIZE);
    header[VERSION_HEADER_SIZE] = cnt;
    if (!framed) {
        if (fread(header + VERSION_HEADER_SIZE + 1, 1, AES_GCM_NONCE_SIZE, in_file) != AES_GCM_NONCE_SIZE) {
            fprintf(stderr, "Error: truncated header\n");
            ret = CRYPTO_ERR_INVALID_INPUT;
            goto cleanup;
        }
        memcpy(nonce, header + VERSION_HEADER_SIZE + 1, AES_GCM_NONCE_SIZE);
    }
    if (fread(header + prefix, 1, n_recipients * record_size, in_file) != n_recipients * record_size) {
        fprintf(stderr, "Error: Failed to read recipient records (truncated file?)\n");
        ret = CRYPTO_ERR_INVALID_INPUT;
        goto cleanup;
    }
    sink.header_ptr = header;
    sink.header_len = header_len;

    /* Recover the content key from whichever record is ours. */
    for (size_t i = 0; i < n_recipients; i++) {
        if (hybrid_unwrap_cek(kem, secret_blob, header + prefix + i * record_size, cek)) {
            have_cek = 1;
            break;
        }
    }
    if (!have_cek) {
        fprintf(stderr, "Error: this key cannot decrypt the file (not a recipient or wrong key)\n");
        ret = CRYPTO_ERR_INTEGRITY;
        goto cleanup;
    }

    if (framed) {
        /* --- framed payload: verify each frame, then release it (constant
         * memory, and no unverified bytes ever reach the output). --- */
        sink.frame_verified = 1;
        cbuf = malloc(QSAFE_FRAME_SIZE + AES_GCM_TAG_SIZE);
        pbuf = malloc(QSAFE_FRAME_SIZE);
        if (!cbuf || !pbuf) { ret = CRYPTO_ERR_MEMORY; goto cleanup; }

        uint64_t ctr = 0;
        int saw_final = 0;
        while (!saw_final) {
            size_t want = QSAFE_FRAME_SIZE + AES_GCM_TAG_SIZE;
            size_t n = 0, r;
            while (n < want && (r = fread(cbuf + n, 1, want - n, in_file)) > 0) n += r;
            if (ferror(in_file)) {
                fprintf(stderr, "Error: Failed to read ciphertext\n");
                ret = CRYPTO_ERR_FILE_IO;
                goto cleanup;
            }
            /* A full read is a non-final frame; a short read is the final frame.
             * Anything smaller than a bare tag is truncated/garbage. */
            if (n < AES_GCM_TAG_SIZE) {
                fprintf(stderr, "Error: Truncated or invalid encrypted file\n");
                ret = CRYPTO_ERR_INVALID_INPUT;
                goto cleanup;
            }
            int last = (n < want) ? 1 : 0;
            size_t ptlen = n - AES_GCM_TAG_SIZE;
            frame_nonce(ctr, last, nonce);
            const unsigned char *aad = (ctr == 0) ? header : NULL;
            size_t aadlen = (ctr == 0) ? header_len : 0;
            if (!gcm_open_aad(cek, nonce, aad, aadlen, cbuf, (int)ptlen, cbuf + ptlen, pbuf)) {
                fprintf(stderr, "Error: Authentication failed - file corrupt or wrong key\n");
                ret = CRYPTO_ERR_INTEGRITY;
                goto cleanup;
            }
            crypto_error_t wr = dec_sink_write(&sink, pbuf, ptlen);
            if (wr != CRYPTO_SUCCESS) { ret = wr; goto cleanup; }
            ctr++;
            if (last) saw_final = 1;
        }
    } else {
        /* --- v5 single-AEAD payload: hold back the trailing 16-byte tag --- */
        in_buffer = malloc(BUFFER_SIZE);
        out_buffer = malloc(BUFFER_SIZE + AES_BLOCK_SIZE);
        work = malloc(BUFFER_SIZE + AES_GCM_TAG_SIZE);
        if (!in_buffer || !out_buffer || !work) {
            fprintf(stderr, "Error: Failed to allocate memory\n");
            ret = CRYPTO_ERR_MEMORY;
            goto cleanup;
        }

        ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            fprintf(stderr, "Error: Failed to create cipher context\n");
            goto cleanup;
        }
        int len;
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
            EVP_DecryptInit_ex(ctx, NULL, NULL, cek, nonce) != 1 ||
            EVP_DecryptUpdate(ctx, NULL, &len, header, (int)header_len) != 1) {
            fprintf(stderr, "Error: Failed to initialize decryption\n");
            crypto_handle_errors();
            goto cleanup;
        }
        while (1) {
            size_t bytes_read = fread(in_buffer, 1, BUFFER_SIZE, in_file);
            if (bytes_read == 0) {
                if (ferror(in_file)) {
                    fprintf(stderr, "Error: Failed to read ciphertext\n");
                    ret = CRYPTO_ERR_FILE_IO;
                    goto cleanup;
                }
                break;
            }
            memcpy(work, hold, holdn);
            memcpy(work + holdn, in_buffer, bytes_read);
            size_t total = holdn + bytes_read;
            if (total <= AES_GCM_TAG_SIZE) { memcpy(hold, work, total); holdn = total; continue; }
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
                if (wr != CRYPTO_SUCCESS) { ret = wr; goto cleanup; }
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
            if (wr != CRYPTO_SUCCESS) { ret = wr; goto cleanup; }
        }
    }

    /* A valid file always carries at least the metadata block, so by now the
     * sink must have parsed it and opened (or deliberately skipped) the output. */
    if (!sink.meta_done) {
        fprintf(stderr, "Error: Encrypted file is missing its metadata block\n");
        ret = CRYPTO_ERR_INVALID_INPUT;
        goto cleanup;
    }

    /* Enforce the declared v7 layout and verify the embedded sender signature
     * (if any) now that every frame has authenticated. */
    ret = dec_sink_finish(&sink, config);
    if (ret != CRYPTO_SUCCESS) goto cleanup;

    /* Release any deferred (v5 pipe) output now that authentication passed. */
    ret = dec_sink_commit(&sink);
    if (ret != CRYPTO_SUCCESS) goto cleanup;

    ret = CRYPTO_SUCCESS;

cleanup:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    close_stream(in_file);
    if (sink.out && sink.out != stdout) fclose(sink.out);
    if (sink.buf) {
        OPENSSL_cleanse(sink.buf, sink.buf_len); /* may hold plaintext */
        free(sink.buf);
    }
    if (sink.sig_md) EVP_MD_CTX_free(sink.sig_md);
    OPENSSL_cleanse(sink.tbuf, sizeof(sink.tbuf)); /* may hold held-back plaintext */
    free(in_buffer);
    free(out_buffer);
    free(work);
    free(cbuf);
    if (pbuf) { OPENSSL_cleanse(pbuf, QSAFE_FRAME_SIZE); free(pbuf); }
    free(header);
    OPENSSL_cleanse(cek, sizeof(cek));

    if (ret == CRYPTO_SUCCESS) {
        /* Restore stored permissions and modification time on success. */
        if (sink.out_created && sink.has_meta && !sink.skipped) {
            qsafe_restore_meta(sink.out_path, sink.mode, sink.mtime);
        }
    } else if (sink.out_created) {
        remove(sink.out_path); /* never leave behind unauthenticated plaintext */
    }
    return ret;
}

/* Resolve a path to its canonical form. Returns 1 on success. */
static int crypto_realpath(const char *path, char *resolved) {
    return qsafe_realpath(path, resolved);
}

crypto_error_t crypto_process_directory(const char *dir_path, const char *output_dir, const char *operation,
                                        OQS_KEM *kem, const unsigned char *const *recipient_pubs,
                                        size_t n_recipients, const unsigned char *secret_blob,
                                        const crypto_config_t *config) {
    DIR *dir = opendir(dir_path);
    if (!dir) {
        perror("Error opening directory");
        return CRYPTO_ERR_FILE_IO;
    }

    struct stat st;
    if (stat(output_dir, &st) != 0) {
        if (qsafe_mkdir(output_dir) != 0) {
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
                                                          kem, recipient_pubs, n_recipients, secret_blob, config);
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
            file_ret = crypto_encrypt_file(input_file_path, output_file_path, kem, recipient_pubs, n_recipients, config);
        } else {
            file_ret = crypto_decrypt_file(input_file_path, output_file_path, kem, secret_blob, config);
        }
        if (file_ret != CRYPTO_SUCCESS) {
            ret = file_ret;
        }
    }

    closedir(dir);
    return ret;
}

/* ===================== detached signatures (ML-DSA-87) =====================
 *
 * Qsafe signs the SHA-256 digest of the file (hash-then-sign), so signing and
 * verification stream the input in constant memory and the signature is bound
 * to the exact file contents. Signing keys are independent of encryption keys:
 * a signing secret key is passphrase-wrapped with the same scheme as a KEM
 * secret key, and the signing public key is stored in the clear. */

/* Streams a file (or stdin for "-") through SHA-256. */
static crypto_error_t sha256_file(const char *path, unsigned char out[32]) {
    FILE *f = is_stream_arg(path) ? stdin : fopen(path, "rb");
    if (!f) {
        perror("Error opening file");
        return CRYPTO_ERR_FILE_IO;
    }
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    crypto_error_t ret = CRYPTO_ERR_CRYPTO;
    unsigned char buf[BUFFER_SIZE];
    if (md && EVP_DigestInit_ex(md, EVP_sha256(), NULL) == 1) {
        size_t n;
        int ok = 1;
        while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
            if (EVP_DigestUpdate(md, buf, n) != 1) { ok = 0; break; }
        }
        unsigned int dl = 0;
        if (ok && !ferror(f) && EVP_DigestFinal_ex(md, out, &dl) == 1 && dl == 32) {
            ret = CRYPTO_SUCCESS;
        }
    }
    if (md) EVP_MD_CTX_free(md);
    if (f != stdin) fclose(f);
    return ret;
}

crypto_error_t crypto_sig_keygen(const char *sk_file, const char *pk_file, const crypto_config_t *config) {
    OQS_SIG *sig = OQS_SIG_new(QSAFE_SIG_ALG);
    if (!sig) {
        fprintf(stderr, "Error: ML-DSA-87 is not available in this liboqs build\n");
        return CRYPTO_ERR_CRYPTO;
    }
    crypto_error_t ret = CRYPTO_ERR_CRYPTO;
    unsigned char *pk = malloc(sig->length_public_key);
    unsigned char *sk = malloc(sig->length_secret_key);
    if (!pk || !sk) { ret = CRYPTO_ERR_MEMORY; goto done; }

    if (OQS_SIG_keypair(sig, pk, sk) != OQS_SUCCESS) {
        fprintf(stderr, "Error: signing keypair generation failed\n");
        goto done;
    }
    if (crypto_save_secret_key(sk_file, sk, sig->length_secret_key, config) != CRYPTO_SUCCESS) {
        fprintf(stderr, "Error: failed to save signing secret key\n");
        goto done;
    }
    if (crypto_save_public_key(pk_file, pk, sig->length_public_key, config) != CRYPTO_SUCCESS) {
        fprintf(stderr, "Error: failed to save signing public key\n");
        goto done;
    }
    ret = CRYPTO_SUCCESS;

done:
    if (sk) { OPENSSL_cleanse(sk, sig->length_secret_key); free(sk); }
    free(pk);
    OQS_SIG_free(sig);
    return ret;
}

crypto_error_t crypto_sign_file(const char *input_filename, const char *sig_file,
                                const char *sig_sk_file, const crypto_config_t *config) {
    OQS_SIG *sig = OQS_SIG_new(QSAFE_SIG_ALG);
    if (!sig) {
        fprintf(stderr, "Error: ML-DSA-87 is not available in this liboqs build\n");
        return CRYPTO_ERR_CRYPTO;
    }
    crypto_error_t ret = CRYPTO_ERR_CRYPTO;
    unsigned char *sk = NULL;
    unsigned char *signature = NULL;
    size_t sk_len = 0, sig_len = 0;
    unsigned char digest[32];
    FILE *out = NULL;

    sk = crypto_load_secret_key(sig_sk_file, &sk_len, config);
    if (!sk || sk_len != sig->length_secret_key) {
        fprintf(stderr, "Error: failed to load signing secret key (wrong passphrase or not a signing key)\n");
        goto done;
    }
    if (sha256_file(input_filename, digest) != CRYPTO_SUCCESS) {
        fprintf(stderr, "Error: failed to hash input\n");
        goto done;
    }
    signature = malloc(sig->length_signature);
    if (!signature) { ret = CRYPTO_ERR_MEMORY; goto done; }
    if (OQS_SIG_sign(sig, signature, &sig_len, digest, sizeof(digest), sk) != OQS_SUCCESS) {
        fprintf(stderr, "Error: signing failed\n");
        goto done;
    }
    if (!crypto_should_write(sig_file, config)) {
        fprintf(stderr, "Aborted: not overwriting %s\n", sig_file);
        ret = CRYPTO_ERR_FILE_IO;
        goto done;
    }
    out = fopen(sig_file, "wb");
    if (!out) { perror("Error opening signature file"); ret = CRYPTO_ERR_FILE_IO; goto done; }
    if (fwrite(signature, 1, sig_len, out) != sig_len) {
        perror("Error writing signature");
        ret = CRYPTO_ERR_FILE_IO;
        goto done;
    }
    ret = CRYPTO_SUCCESS;

done:
    if (out) fclose(out);
    if (sk) { OPENSSL_cleanse(sk, sk_len); free(sk); }
    free(signature);
    OQS_SIG_free(sig);
    return ret;
}

crypto_error_t crypto_verify_signature(const char *input_filename, const char *sig_file,
                                       const char *sig_pk_file, const crypto_config_t *config) {
    OQS_SIG *sig = OQS_SIG_new(QSAFE_SIG_ALG);
    if (!sig) {
        fprintf(stderr, "Error: ML-DSA-87 is not available in this liboqs build\n");
        return CRYPTO_ERR_CRYPTO;
    }
    crypto_error_t ret = CRYPTO_ERR_CRYPTO;
    unsigned char *pk = NULL;
    unsigned char *signature = NULL;
    size_t sig_len = 0;
    unsigned char digest[32];
    FILE *sf = NULL;

    pk = crypto_load_public_key(sig_pk_file, sig->length_public_key, config);
    if (!pk) {
        fprintf(stderr, "Error: failed to load signing public key\n");
        goto done;
    }

    sf = fopen(sig_file, "rb");
    if (!sf) { perror("Error opening signature file"); ret = CRYPTO_ERR_FILE_IO; goto done; }
    if (fseek(sf, 0, SEEK_END) != 0) { ret = CRYPTO_ERR_FILE_IO; goto done; }
    long sl = ftell(sf);
    rewind(sf);
    if (sl <= 0 || (size_t)sl > sig->length_signature) {
        fprintf(stderr, "Error: invalid signature file\n");
        ret = CRYPTO_ERR_INVALID_INPUT;
        goto done;
    }
    signature = malloc((size_t)sl);
    if (!signature) { ret = CRYPTO_ERR_MEMORY; goto done; }
    if (fread(signature, 1, (size_t)sl, sf) != (size_t)sl) {
        fprintf(stderr, "Error: failed to read signature\n");
        ret = CRYPTO_ERR_FILE_IO;
        goto done;
    }
    sig_len = (size_t)sl;

    if (sha256_file(input_filename, digest) != CRYPTO_SUCCESS) {
        fprintf(stderr, "Error: failed to hash input\n");
        goto done;
    }
    if (OQS_SIG_verify(sig, digest, sizeof(digest), signature, sig_len, pk) == OQS_SUCCESS) {
        ret = CRYPTO_SUCCESS;
    } else {
        fprintf(stderr, "Error: signature verification FAILED\n");
        ret = CRYPTO_ERR_INTEGRITY;
    }

done:
    if (sf) fclose(sf);
    free(pk);
    free(signature);
    OQS_SIG_free(sig);
    return ret;
}
