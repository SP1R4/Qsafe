#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>
#include <openssl/rand.h>
#include "crypto_utils.h"

static int tests_run = 0;
static int tests_passed = 0;

#define ASSERT(cond, msg) do { \
    tests_run++; \
    if (!(cond)) { \
        fprintf(stderr, "  FAIL: %s\n", msg); \
    } else { \
        tests_passed++; \
        printf("  PASS: %s\n", msg); \
    } \
} while (0)

/* --- small file helpers --- */

static int write_file(const char *path, const unsigned char *data, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) return 0;
    size_t w = (len > 0) ? fwrite(data, 1, len, f) : 0;
    fclose(f);
    return w == len;
}

/* Reads an entire file into a freshly malloc'd buffer. Caller frees *out. */
static int read_file(const char *path, unsigned char **out, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return 0; }
    long sz = ftell(f);
    rewind(f);
    if (sz < 0) { fclose(f); return 0; }
    unsigned char *buf = malloc((size_t)sz + 1); /* +1 keeps malloc(0) well-defined */
    if (!buf) { fclose(f); return 0; }
    size_t got = (sz > 0) ? fread(buf, 1, (size_t)sz, f) : 0;
    fclose(f);
    if (got != (size_t)sz) { free(buf); return 0; }
    *out = buf;
    *out_len = (size_t)sz;
    return 1;
}

static int files_equal(const char *a, const char *b) {
    unsigned char *da = NULL, *db = NULL;
    size_t la = 0, lb = 0;
    if (!read_file(a, &da, &la) || !read_file(b, &db, &lb)) {
        free(da); free(db);
        return 0;
    }
    int eq = (la == lb) && (la == 0 || memcmp(da, db, la) == 0);
    free(da);
    free(db);
    return eq;
}

/* --- tests --- */

static void test_derive_aes_key(void) {
    printf("\n[test_derive_aes_key]\n");

    unsigned char secret[32];
    memset(secret, 0xAB, sizeof(secret));
    unsigned char key1[AES_KEY_SIZE];
    unsigned char key2[AES_KEY_SIZE];

    crypto_error_t ret = crypto_derive_aes_key(secret, sizeof(secret), key1);
    ASSERT(ret == CRYPTO_SUCCESS, "HKDF derivation returns CRYPTO_SUCCESS");

    ret = crypto_derive_aes_key(secret, sizeof(secret), key2);
    ASSERT(ret == CRYPTO_SUCCESS, "second HKDF derivation returns CRYPTO_SUCCESS");
    ASSERT(memcmp(key1, key2, AES_KEY_SIZE) == 0, "same input produces same key (deterministic)");

    unsigned char different_secret[32];
    memset(different_secret, 0xCD, sizeof(different_secret));
    unsigned char key3[AES_KEY_SIZE];
    ret = crypto_derive_aes_key(different_secret, sizeof(different_secret), key3);
    ASSERT(ret == CRYPTO_SUCCESS, "HKDF derivation with different input succeeds");
    ASSERT(memcmp(key1, key3, AES_KEY_SIZE) != 0, "different input produces different key");
}

static void test_derive_key_from_passphrase(void) {
    printf("\n[test_derive_key_from_passphrase]\n");

    unsigned char salt1[KDF_SALT_SIZE];
    unsigned char salt2[KDF_SALT_SIZE];
    memset(salt1, 0x11, sizeof(salt1));
    memset(salt2, 0x22, sizeof(salt2));

    unsigned char k1[AES_KEY_SIZE], k2[AES_KEY_SIZE], k3[AES_KEY_SIZE], k4[AES_KEY_SIZE];

    ASSERT(crypto_derive_key_from_passphrase("hunter2", salt1, k1) == CRYPTO_SUCCESS,
           "scrypt derivation returns CRYPTO_SUCCESS");
    ASSERT(crypto_derive_key_from_passphrase("hunter2", salt1, k2) == CRYPTO_SUCCESS,
           "second scrypt derivation returns CRYPTO_SUCCESS");
    ASSERT(memcmp(k1, k2, AES_KEY_SIZE) == 0, "same passphrase + salt is deterministic");

    ASSERT(crypto_derive_key_from_passphrase("hunter2", salt2, k3) == CRYPTO_SUCCESS,
           "scrypt derivation with different salt succeeds");
    ASSERT(memcmp(k1, k3, AES_KEY_SIZE) != 0, "different salt produces different key");

    ASSERT(crypto_derive_key_from_passphrase("different", salt1, k4) == CRYPTO_SUCCESS,
           "scrypt derivation with different passphrase succeeds");
    ASSERT(memcmp(k1, k4, AES_KEY_SIZE) != 0, "different passphrase produces different key");
}

static void test_save_load_secret_key(void) {
    printf("\n[test_save_load_secret_key]\n");

    const char *keyfile = "/tmp/test_qsafe_key.bin";
    unsigned char original[64];
    RAND_bytes(original, sizeof(original));

    crypto_config_t config = {
        .verbose = 0,
        .force_overwrite = 1,
        .secret_key_file = keyfile,
        .passphrase = "test-passphrase-123"
    };

    crypto_error_t ret = crypto_save_secret_key(keyfile, original, sizeof(original), &config);
    ASSERT(ret == CRYPTO_SUCCESS, "save_secret_key returns CRYPTO_SUCCESS");

    size_t loaded_len = 0;
    unsigned char *loaded = crypto_load_secret_key(keyfile, &loaded_len, &config);
    ASSERT(loaded != NULL, "load_secret_key returns non-NULL");
    ASSERT(loaded_len == sizeof(original), "loaded length matches original");
    if (loaded) {
        ASSERT(memcmp(original, loaded, sizeof(original)) == 0, "loaded key matches original (round-trip)");
        free(loaded);
    }

    /* Saving the same key twice must produce different files (random salt + nonce). */
    const char *keyfile2 = "/tmp/test_qsafe_key2.bin";
    crypto_config_t config2 = config;
    config2.secret_key_file = keyfile2;
    ret = crypto_save_secret_key(keyfile2, original, sizeof(original), &config2);
    ASSERT(ret == CRYPTO_SUCCESS, "second save_secret_key returns CRYPTO_SUCCESS");
    ASSERT(!files_equal(keyfile, keyfile2), "same key saved twice yields different ciphertext (salt is random)");

    /* Wrong passphrase should fail. */
    crypto_config_t bad_config = config;
    bad_config.passphrase = "wrong-passphrase";
    loaded = crypto_load_secret_key(keyfile, &loaded_len, &bad_config);
    ASSERT(loaded == NULL, "wrong passphrase returns NULL");
    free(loaded);

    /* No passphrase should fail. */
    crypto_config_t no_pass_config = config;
    no_pass_config.passphrase = NULL;
    ret = crypto_save_secret_key(keyfile, original, sizeof(original), &no_pass_config);
    ASSERT(ret == CRYPTO_ERR_INVALID_INPUT, "save without passphrase returns CRYPTO_ERR_INVALID_INPUT");

    remove(keyfile);
    remove(keyfile2);
}

static void test_save_load_public_key(void) {
    printf("\n[test_save_load_public_key]\n");

    const char *pubfile = "/tmp/test_qsafe_pub.bin";
    unsigned char original[1568];
    RAND_bytes(original, sizeof(original));

    crypto_config_t config = {
        .verbose = 0, .force_overwrite = 1,
        .secret_key_file = DEFAULT_SECRET_KEY_FILE,
        .public_key_file = pubfile, .passphrase = NULL
    };

    crypto_error_t ret = crypto_save_public_key(pubfile, original, sizeof(original), &config);
    ASSERT(ret == CRYPTO_SUCCESS, "save_public_key returns CRYPTO_SUCCESS");

    unsigned char *loaded = crypto_load_public_key(pubfile, sizeof(original), &config);
    ASSERT(loaded != NULL, "load_public_key returns non-NULL");
    if (loaded) {
        ASSERT(memcmp(original, loaded, sizeof(original)) == 0, "public key round-trips unchanged");
        free(loaded);
    }

    /* Loading with the wrong expected length must fail. */
    loaded = crypto_load_public_key(pubfile, sizeof(original) - 1, &config);
    ASSERT(loaded == NULL, "wrong expected length is rejected");
    free(loaded);

    remove(pubfile);
}

/* Encrypts then decrypts a buffer of the given size and checks the round-trip. */
static void roundtrip_case(OQS_KEM *kem, uint8_t *public_key, uint8_t *secret_key,
                           size_t size, const char *label) {
    const char *plain = "/tmp/test_qsafe_rt_plain.bin";
    const char *enc = "/tmp/test_qsafe_rt_enc.bin";
    const char *dec = "/tmp/test_qsafe_rt_dec.bin";

    unsigned char *data = malloc(size + 1);
    if (!data) { ASSERT(0, label); return; }
    if (size > 0) RAND_bytes(data, size);

    ASSERT(write_file(plain, data, size), label);
    free(data);

    unsigned char aes_key[AES_KEY_SIZE];
    crypto_config_t config = {
        .verbose = 0,
        .force_overwrite = 1,
        .secret_key_file = DEFAULT_SECRET_KEY_FILE,
        .passphrase = "test-pass"
    };

    crypto_error_t ret = crypto_encrypt_file(plain, enc, kem, aes_key, public_key, secret_key, &config);
    ASSERT(ret == CRYPTO_SUCCESS, label);

    ret = crypto_decrypt_file(enc, dec, kem, aes_key, public_key, secret_key, &config);
    ASSERT(ret == CRYPTO_SUCCESS, label);

    ASSERT(files_equal(plain, dec), label);

    remove(plain);
    remove(enc);
    remove(dec);
}

static void test_encrypt_decrypt_file(void) {
    printf("\n[test_encrypt_decrypt_file]\n");

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
    ASSERT(kem != NULL, "initialize ML-KEM-1024 KEM");
    if (!kem) return;

    uint8_t *public_key = malloc(kem->length_public_key);
    uint8_t *secret_key = malloc(kem->length_secret_key);
    ASSERT(public_key != NULL && secret_key != NULL, "allocate keypair memory");
    if (!public_key || !secret_key) {
        free(public_key); free(secret_key); OQS_KEM_free(kem);
        return;
    }

    ASSERT(OQS_KEM_keypair(kem, public_key, secret_key) == OQS_SUCCESS, "generate ML-KEM keypair");

    /* Round-trip across sizes: empty, single-chunk, and multi-chunk (streaming). */
    roundtrip_case(kem, public_key, secret_key, 0, "round-trip: empty file");
    roundtrip_case(kem, public_key, secret_key, 100, "round-trip: small single-chunk file");
    roundtrip_case(kem, public_key, secret_key, 4096, "round-trip: exact one-chunk file");
    roundtrip_case(kem, public_key, secret_key, 100000, "round-trip: multi-chunk file (streaming)");

    /* Tamper detection. */
    const char *plain = "/tmp/test_qsafe_plain.txt";
    const char *enc = "/tmp/test_qsafe_enc.bin";
    const char *dec = "/tmp/test_qsafe_dec.txt";
    const char *data = "Hello, Qsafe 3.0! Post-quantum encryption integrity check.\n";
    ASSERT(write_file(plain, (const unsigned char *)data, strlen(data)), "create tamper-test plaintext");

    unsigned char aes_key[AES_KEY_SIZE];
    crypto_config_t config = {
        .verbose = 0, .force_overwrite = 1,
        .secret_key_file = DEFAULT_SECRET_KEY_FILE, .passphrase = "test-pass"
    };

    crypto_error_t ret = crypto_encrypt_file(plain, enc, kem, aes_key, public_key, secret_key, &config);
    ASSERT(ret == CRYPTO_SUCCESS, "encrypt tamper-test file");

    /* Flip a byte inside the AES ciphertext region (past header, nonce, KEM
     * ciphertext, and the prepended metadata block). */
    FILE *e = fopen(enc, "r+b");
    ASSERT(e != NULL, "open encrypted file for tampering");
    if (e) {
        long off = (long)(VERSION_HEADER_SIZE + AES_GCM_NONCE_SIZE + kem->length_ciphertext + QSAFE_META_SIZE + 1);
        unsigned char byte = 0;
        ASSERT(fseek(e, off, SEEK_SET) == 0 && fread(&byte, 1, 1, e) == 1, "read byte to tamper");
        byte ^= 0xFF;
        ASSERT(fseek(e, off, SEEK_SET) == 0 && fwrite(&byte, 1, 1, e) == 1, "write tampered byte");
        fclose(e);

        ret = crypto_decrypt_file(enc, dec, kem, aes_key, public_key, secret_key, &config);
        ASSERT(ret == CRYPTO_ERR_INTEGRITY, "tampered ciphertext returns CRYPTO_ERR_INTEGRITY");
    }

    /* A corrupt KEM ciphertext must also be rejected (it is authenticated as AAD). */
    ret = crypto_encrypt_file(plain, enc, kem, aes_key, public_key, secret_key, &config);
    ASSERT(ret == CRYPTO_SUCCESS, "re-encrypt for KEM-tamper test");
    e = fopen(enc, "r+b");
    if (e) {
        long koff = (long)(VERSION_HEADER_SIZE + AES_GCM_NONCE_SIZE);
        unsigned char byte = 0;
        ASSERT(fseek(e, koff, SEEK_SET) == 0 && fread(&byte, 1, 1, e) == 1, "read KEM byte");
        byte ^= 0xFF;
        ASSERT(fseek(e, koff, SEEK_SET) == 0 && fwrite(&byte, 1, 1, e) == 1, "tamper KEM byte");
        fclose(e);
        ret = crypto_decrypt_file(enc, dec, kem, aes_key, public_key, secret_key, &config);
        ASSERT(ret == CRYPTO_ERR_INTEGRITY || ret == CRYPTO_ERR_CRYPTO,
               "tampered KEM ciphertext is rejected");
    }

    remove(plain);
    remove(enc);
    remove(dec);

    free(public_key);
    free(secret_key);
    OQS_KEM_free(kem);
}

static void test_error_codes(void) {
    printf("\n[test_error_codes]\n");

    ASSERT(CRYPTO_SUCCESS == 0, "CRYPTO_SUCCESS is 0");
    ASSERT(CRYPTO_ERR_FILE_IO == 1, "CRYPTO_ERR_FILE_IO is 1");
    ASSERT(CRYPTO_ERR_MEMORY == 2, "CRYPTO_ERR_MEMORY is 2");
    ASSERT(CRYPTO_ERR_CRYPTO == 3, "CRYPTO_ERR_CRYPTO is 3");
    ASSERT(CRYPTO_ERR_INVALID_INPUT == 4, "CRYPTO_ERR_INVALID_INPUT is 4");
    ASSERT(CRYPTO_ERR_INTEGRITY == 5, "CRYPTO_ERR_INTEGRITY is 5");
}

int main(void) {
    printf("=== Qsafe 3.0 Unit Tests ===\n");

    test_derive_aes_key();
    test_derive_key_from_passphrase();
    test_save_load_secret_key();
    test_save_load_public_key();
    test_encrypt_decrypt_file();
    test_error_codes();

    printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
