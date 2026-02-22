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

static void test_derive_aes_key(void) {
    printf("\n[test_derive_aes_key]\n");

    unsigned char secret[32];
    memset(secret, 0xAB, sizeof(secret));
    unsigned char key1[AES_KEY_SIZE];
    unsigned char key2[AES_KEY_SIZE];

    crypto_error_t ret = crypto_derive_aes_key(secret, sizeof(secret), key1);
    ASSERT(ret == CRYPTO_SUCCESS, "derivation returns CRYPTO_SUCCESS");

    ret = crypto_derive_aes_key(secret, sizeof(secret), key2);
    ASSERT(ret == CRYPTO_SUCCESS, "second derivation returns CRYPTO_SUCCESS");
    ASSERT(memcmp(key1, key2, AES_KEY_SIZE) == 0, "same input produces same key (deterministic)");

    unsigned char different_secret[32];
    memset(different_secret, 0xCD, sizeof(different_secret));
    unsigned char key3[AES_KEY_SIZE];
    ret = crypto_derive_aes_key(different_secret, sizeof(different_secret), key3);
    ASSERT(ret == CRYPTO_SUCCESS, "derivation with different input succeeds");
    ASSERT(memcmp(key1, key3, AES_KEY_SIZE) != 0, "different input produces different key");
}

static void test_save_load_secret_key(void) {
    printf("\n[test_save_load_secret_key]\n");

    const char *keyfile = "/tmp/test_qsafe_key.bin";
    unsigned char original[64];
    RAND_bytes(original, sizeof(original));

    crypto_config_t config = {
        .verbose = 0,
        .force_overwrite = 0,
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

    /* Wrong passphrase should fail */
    crypto_config_t bad_config = config;
    bad_config.passphrase = "wrong-passphrase";
    loaded = crypto_load_secret_key(keyfile, &loaded_len, &bad_config);
    ASSERT(loaded == NULL, "wrong passphrase returns NULL");
    free(loaded);

    /* No passphrase should fail */
    crypto_config_t no_pass_config = config;
    no_pass_config.passphrase = NULL;
    ret = crypto_save_secret_key(keyfile, original, sizeof(original), &no_pass_config);
    ASSERT(ret == CRYPTO_ERR_INVALID_INPUT, "save without passphrase returns CRYPTO_ERR_INVALID_INPUT");

    remove(keyfile);
}

static void test_encrypt_decrypt_file(void) {
    printf("\n[test_encrypt_decrypt_file]\n");

    const char *plaintext_file = "/tmp/test_qsafe_plain.txt";
    const char *encrypted_file = "/tmp/test_qsafe_enc.bin";
    const char *decrypted_file = "/tmp/test_qsafe_dec.txt";

    /* Create a test plaintext file */
    const char *test_data = "Hello, Qsafe 2.0! This is a test of post-quantum encryption.\n"
                            "Line two with some more data to ensure multi-chunk isn't needed.\n";
    FILE *f = fopen(plaintext_file, "wb");
    ASSERT(f != NULL, "create test plaintext file");
    if (f) {
        fwrite(test_data, 1, strlen(test_data), f);
        fclose(f);
    }

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
    ASSERT(kem != NULL, "initialize Kyber1024 KEM");
    if (!kem) return;

    uint8_t *public_key = malloc(kem->length_public_key);
    uint8_t *secret_key = malloc(kem->length_secret_key);
    ASSERT(public_key != NULL && secret_key != NULL, "allocate keypair memory");

    OQS_STATUS kem_ret = OQS_KEM_keypair(kem, public_key, secret_key);
    ASSERT(kem_ret == OQS_SUCCESS, "generate Kyber keypair");

    unsigned char aes_key[AES_KEY_SIZE];
    crypto_config_t config = {
        .verbose = 0,
        .force_overwrite = 0,
        .secret_key_file = DEFAULT_SECRET_KEY_FILE,
        .passphrase = "test-pass"
    };

    /* Encrypt */
    crypto_error_t ret = crypto_encrypt_file(plaintext_file, encrypted_file, kem, aes_key, public_key, secret_key, &config);
    ASSERT(ret == CRYPTO_SUCCESS, "encrypt_file returns CRYPTO_SUCCESS");

    /* Decrypt */
    unsigned char aes_key2[AES_KEY_SIZE];
    ret = crypto_decrypt_file(encrypted_file, decrypted_file, kem, aes_key2, public_key, secret_key, &config);
    ASSERT(ret == CRYPTO_SUCCESS, "decrypt_file returns CRYPTO_SUCCESS");

    /* Compare original and decrypted */
    FILE *orig = fopen(plaintext_file, "rb");
    FILE *dec = fopen(decrypted_file, "rb");
    ASSERT(orig != NULL && dec != NULL, "open files for comparison");
    if (orig && dec) {
        fseek(orig, 0, SEEK_END);
        fseek(dec, 0, SEEK_END);
        long orig_size = ftell(orig);
        long dec_size = ftell(dec);
        ASSERT(orig_size == dec_size, "decrypted file size matches original");

        if (orig_size == dec_size) {
            fseek(orig, 0, SEEK_SET);
            fseek(dec, 0, SEEK_SET);
            unsigned char *buf1 = malloc(orig_size);
            unsigned char *buf2 = malloc(orig_size);
            fread(buf1, 1, orig_size, orig);
            fread(buf2, 1, orig_size, dec);
            ASSERT(memcmp(buf1, buf2, orig_size) == 0, "decrypted content matches original");
            free(buf1);
            free(buf2);
        }
        fclose(orig);
        fclose(dec);
    }

    /* Test integrity: tamper with encrypted file */
    FILE *enc = fopen(encrypted_file, "r+b");
    ASSERT(enc != NULL, "open encrypted file for tampering");
    if (enc) {
        /* Tamper with a byte in the AES ciphertext area (after header + KEM ciphertext) */
        long tamper_offset = VERSION_HEADER_SIZE + kem->length_ciphertext + 1;
        fseek(enc, tamper_offset, SEEK_SET);
        unsigned char byte;
        fread(&byte, 1, 1, enc);
        byte ^= 0xFF;
        fseek(enc, tamper_offset, SEEK_SET);
        fwrite(&byte, 1, 1, enc);
        fclose(enc);

        const char *tampered_out = "/tmp/test_qsafe_tampered.txt";
        ret = crypto_decrypt_file(encrypted_file, tampered_out, kem, aes_key2, public_key, secret_key, &config);
        ASSERT(ret == CRYPTO_ERR_INTEGRITY, "tampered ciphertext returns CRYPTO_ERR_INTEGRITY");
        remove(tampered_out);
    }

    /* Cleanup */
    free(public_key);
    free(secret_key);
    OQS_KEM_free(kem);
    remove(plaintext_file);
    remove(encrypted_file);
    remove(decrypted_file);
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
    printf("=== Qsafe 2.0 Unit Tests ===\n");

    test_derive_aes_key();
    test_save_load_secret_key();
    test_encrypt_decrypt_file();
    test_error_codes();

    printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
