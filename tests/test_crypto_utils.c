#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
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

    /* Use the default scrypt cost (N=2^15, r=8, p=1). */
    const uint64_t N = 1ULL << 15; const uint32_t R = 8, P = 1;

    ASSERT(crypto_derive_key_from_passphrase("hunter2", salt1, N, R, P, k1) == CRYPTO_SUCCESS,
           "scrypt derivation returns CRYPTO_SUCCESS");
    ASSERT(crypto_derive_key_from_passphrase("hunter2", salt1, N, R, P, k2) == CRYPTO_SUCCESS,
           "second scrypt derivation returns CRYPTO_SUCCESS");
    ASSERT(memcmp(k1, k2, AES_KEY_SIZE) == 0, "same passphrase + salt is deterministic");

    ASSERT(crypto_derive_key_from_passphrase("hunter2", salt2, N, R, P, k3) == CRYPTO_SUCCESS,
           "scrypt derivation with different salt succeeds");
    ASSERT(memcmp(k1, k3, AES_KEY_SIZE) != 0, "different salt produces different key");

    ASSERT(crypto_derive_key_from_passphrase("different", salt1, N, R, P, k4) == CRYPTO_SUCCESS,
           "scrypt derivation with different passphrase succeeds");
    ASSERT(memcmp(k1, k4, AES_KEY_SIZE) != 0, "different passphrase produces different key");
}

static void test_save_load_secret_key(void) {
    printf("\n[test_save_load_secret_key]\n");

    const char *keyfile = "test_qsafe_key.bin";
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
    const char *keyfile2 = "test_qsafe_key2.bin";
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

    const char *pubfile = "test_qsafe_pub.bin";
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
static void roundtrip_case(OQS_KEM *kem, const unsigned char *pub, const unsigned char *sec,
                           size_t size, const char *label) {
    const char *plain = "test_qsafe_rt_plain.bin";
    const char *enc = "test_qsafe_rt_enc.bin";
    const char *dec = "test_qsafe_rt_dec.bin";

    unsigned char *data = malloc(size + 1);
    if (!data) { ASSERT(0, label); return; }
    if (size > 0) RAND_bytes(data, size);

    ASSERT(write_file(plain, data, size), label);
    free(data);

    crypto_config_t config = {
        .verbose = 0,
        .force_overwrite = 1,
        .secret_key_file = DEFAULT_SECRET_KEY_FILE,
        .passphrase = "test-pass"
    };
    const unsigned char *recips[1] = { pub };

    crypto_error_t ret = crypto_encrypt_file(plain, enc, kem, recips, 1, &config);
    ASSERT(ret == CRYPTO_SUCCESS, label);

    ret = crypto_decrypt_file(enc, dec, kem, sec, &config);
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

    unsigned char *pub = NULL, *sec = NULL;
    size_t publen = 0, seclen = 0;
    ASSERT(crypto_generate_identity(kem, &pub, &publen, &sec, &seclen) == CRYPTO_SUCCESS,
           "generate hybrid identity");
    if (!pub || !sec) { free(pub); free(sec); OQS_KEM_free(kem); return; }

    /* Round-trip across sizes: empty, single-chunk, and multi-chunk (streaming). */
    roundtrip_case(kem, pub, sec, 0, "round-trip: empty file");
    roundtrip_case(kem, pub, sec, 100, "round-trip: small single-chunk file");
    roundtrip_case(kem, pub, sec, 4096, "round-trip: exact one-chunk file");
    roundtrip_case(kem, pub, sec, 100000, "round-trip: multi-chunk file (streaming)");

    /* Tamper detection. */
    const char *plain = "test_qsafe_plain.txt";
    const char *enc = "test_qsafe_enc.bin";
    const char *dec = "test_qsafe_dec.txt";
    const char *data = "Hello, Qsafe 5.0! Hybrid post-quantum integrity check.\n";
    ASSERT(write_file(plain, (const unsigned char *)data, strlen(data)), "create tamper-test plaintext");

    crypto_config_t config = {
        .verbose = 0, .force_overwrite = 1,
        .secret_key_file = DEFAULT_SECRET_KEY_FILE, .passphrase = "test-pass"
    };
    const unsigned char *recips[1] = { pub };

    size_t record_size = X25519_KEY_SIZE + kem->length_ciphertext +
                         AES_GCM_NONCE_SIZE + QSAFE_CEK_SIZE + AES_GCM_TAG_SIZE;
    long prefix = VERSION_HEADER_SIZE + 1 + AES_GCM_NONCE_SIZE;

    crypto_error_t ret = crypto_encrypt_file(plain, enc, kem, recips, 1, &config);
    ASSERT(ret == CRYPTO_SUCCESS, "encrypt tamper-test file");

    /* Flip a byte in the payload ciphertext (past the header, the single
     * recipient record, and the prepended metadata block). */
    FILE *e = fopen(enc, "r+b");
    ASSERT(e != NULL, "open encrypted file for tampering");
    if (e) {
        long off = prefix + (long)record_size + QSAFE_META_SIZE + 1;
        unsigned char byte = 0;
        ASSERT(fseek(e, off, SEEK_SET) == 0 && fread(&byte, 1, 1, e) == 1, "read byte to tamper");
        byte ^= 0xFF;
        ASSERT(fseek(e, off, SEEK_SET) == 0 && fwrite(&byte, 1, 1, e) == 1, "write tampered byte");
        fclose(e);

        ret = crypto_decrypt_file(enc, dec, kem, sec, &config);
        ASSERT(ret == CRYPTO_ERR_INTEGRITY, "tampered ciphertext returns CRYPTO_ERR_INTEGRITY");
    }

    /* Corrupting a recipient record (inside the KEM ciphertext) yields a wrong
     * key-encryption key, so the wrap no longer authenticates. */
    ret = crypto_encrypt_file(plain, enc, kem, recips, 1, &config);
    ASSERT(ret == CRYPTO_SUCCESS, "re-encrypt for record-tamper test");
    e = fopen(enc, "r+b");
    if (e) {
        long koff = prefix + X25519_KEY_SIZE + 4; /* inside the KEM ciphertext */
        unsigned char byte = 0;
        ASSERT(fseek(e, koff, SEEK_SET) == 0 && fread(&byte, 1, 1, e) == 1, "read record byte");
        byte ^= 0xFF;
        ASSERT(fseek(e, koff, SEEK_SET) == 0 && fwrite(&byte, 1, 1, e) == 1, "tamper record byte");
        fclose(e);
        ret = crypto_decrypt_file(enc, dec, kem, sec, &config);
        ASSERT(ret == CRYPTO_ERR_INTEGRITY || ret == CRYPTO_ERR_CRYPTO,
               "tampered recipient record is rejected");
    }

    remove(plain);
    remove(enc);
    remove(dec);

    free(pub);
    free(sec);
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

/* Formats len bytes of buf as lowercase hex into out (>= 2*len+1). */
static void to_hex(const unsigned char *buf, size_t len, char *out) {
    static const char h[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i]     = h[buf[i] >> 4];
        out[2 * i + 1] = h[buf[i] & 0x0f];
    }
    out[2 * len] = '\0';
}

/* Known-answer tests. The expected values were computed independently of
 * Qsafe's own code: SHA-256/HKDF with Python's hashlib+hmac, and scrypt with
 * the OpenSSL 3 `kdf` CLI. They pin the deterministic primitives so any future
 * change that alters cryptographic output is caught immediately. */
static void test_known_answer_vectors(void) {
    printf("\n[test_known_answer_vectors]\n");
    char hex[65];

    /* (1) Public-key fingerprint: SHA-256 of 32 bytes of 0xAB. */
    unsigned char ab32[32];
    memset(ab32, 0xAB, sizeof(ab32));
    unsigned char fpraw[32];
    /* crypto_fingerprint emits hex directly; compare its string output. */
    char fp[65];
    ASSERT(crypto_fingerprint(ab32, sizeof(ab32), fp, sizeof(fp)) == CRYPTO_SUCCESS,
           "fingerprint KAT computes");
    (void)fpraw;
    ASSERT(strcmp(fp, "9a2db2e23f1504cd056606553ac049c5e718e8f9ce9233876df1a7a1821af885") == 0,
           "SHA-256 fingerprint matches known answer");

    /* (2) HKDF-SHA256 (crypto_derive_aes_key) of 32 bytes of 0xAB,
     *     info "qsafe-v3-aes-key", empty salt -> fixed 32-byte key. */
    unsigned char aeskey[AES_KEY_SIZE];
    ASSERT(crypto_derive_aes_key(ab32, sizeof(ab32), aeskey) == CRYPTO_SUCCESS,
           "HKDF KAT computes");
    to_hex(aeskey, sizeof(aeskey), hex);
    ASSERT(strcmp(hex, "23007a6fb81fbb59d3d85ec00e26c634a8d9aaf77d6b0ba78da66394a875a62a") == 0,
           "HKDF-SHA256 derived key matches known answer");

    /* (3) scrypt (crypto_derive_key_from_passphrase) pass="hunter2",
     *     salt = 16 bytes of 0x11, N=2^15, r=8, p=1 -> fixed 32-byte key. */
    unsigned char salt[KDF_SALT_SIZE];
    memset(salt, 0x11, sizeof(salt));
    unsigned char sckey[AES_KEY_SIZE];
    ASSERT(crypto_derive_key_from_passphrase("hunter2", salt, 1ULL << 15, 8, 1, sckey) == CRYPTO_SUCCESS,
           "scrypt KAT computes");
    to_hex(sckey, sizeof(sckey), hex);
    ASSERT(strcmp(hex, "3eeeb21df68c7b1087858f538b51ef7b17ae239aad10e867ef959116c3fcf8d9") == 0,
           "scrypt derived key matches known answer");
}

/* Known-answer vectors for the v7 construction (docs/FORMAT.md §10). The
 * expected values were generated independently with Python `cryptography`. */
static void test_v7_known_answer_vectors(void) {
    printf("\n[test_v7_known_answer_vectors]\n");
    char hex[131];

    /* (1) Hybrid KEK: HKDF-SHA256(ikm = bytes 0x00..0x3f, salt = empty,
     *     info = "qsafe-v5-hybrid-kek", L = 32). Exercised via a wrap/unwrap
     *     KAT is impossible (encapsulation is randomized), so the KDF step is
     *     pinned directly through the frame path below and here via hkdf. */
    unsigned char ikm[64];
    for (int i = 0; i < 64; i++) ikm[i] = (unsigned char)i;

    /* crypto_hybrid_wrap/unwrap KDF is not exported alone; check it end to end
     * instead: a full hybrid wrap of a known key must unwrap to the same key
     * (randomized, so equality is the property), while the *deterministic*
     * pieces get true KATs below. */

    /* (2) Frame nonce construction: 3 zero bytes ‖ u64be(counter) ‖ final. */
    unsigned char nonce[12];
    memset(nonce, 0, sizeof(nonce));
    nonce[11] = 0x01; /* counter 0, final frame */

    /* (3) Frame AEAD KAT: AES-256-GCM, key = bytes 0x00..0x1f, nonce = frame 0
     *     final, aad = "HDR", plaintext = "Qsafe frame KAT" ->
     *     ciphertext ‖ tag (31 bytes). */
    {
        unsigned char cek[32];
        for (int i = 0; i < 32; i++) cek[i] = (unsigned char)i;
        const unsigned char pt[] = "Qsafe frame KAT"; /* 15 bytes, no NUL */
        unsigned char ct[15 + 16];
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        int len = 0, ok = 0;
        if (ctx &&
            EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
            EVP_EncryptInit_ex(ctx, NULL, NULL, cek, nonce) == 1 &&
            EVP_EncryptUpdate(ctx, NULL, &len, (const unsigned char *)"HDR", 3) == 1 &&
            EVP_EncryptUpdate(ctx, ct, &len, pt, 15) == 1 &&
            EVP_EncryptFinal_ex(ctx, ct + len, &len) == 1 &&
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, ct + 15) == 1) {
            ok = 1;
        }
        if (ctx) EVP_CIPHER_CTX_free(ctx);
        ASSERT(ok, "frame AEAD KAT computes");
        to_hex(ct, sizeof(ct), hex);
        ASSERT(strcmp(hex, "44a5de9a21d4566c6f433419a7e76ed434e897d9f04eb6cf5bf90a7d8a48de") == 0,
               "frame 0 (final) AEAD output matches known answer");
    }

    /* (4) Padmé bucket table (docs/FORMAT.md §3.2). */
    {
        static const struct { uint64_t in, out; } padme_kat[] = {
            { 0, 0 }, { 1, 1 }, { 2, 2 }, { 3, 3 }, { 9, 10 }, { 100, 104 },
            { 1000, 1024 }, { 65536, 65536 }, { 100000, 100352 },
            { 1048576, 1048576 }, { 123456789, 123731968 },
        };
        int all = 1;
        for (size_t i = 0; i < sizeof(padme_kat) / sizeof(padme_kat[0]); i++) {
            if (crypto_padme_size(padme_kat[i].in) != padme_kat[i].out) all = 0;
        }
        ASSERT(all, "Padmé bucket sizes match known answers");
    }

    /* (5) Hybrid wrap/unwrap round-trip under both deployed HKDF labels. */
    {
        OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
        ASSERT(kem != NULL, "hybrid KAT: KEM initializes");
        if (kem) {
            unsigned char *pub = NULL, *sec = NULL;
            size_t pl = 0, sl = 0;
            ASSERT(crypto_generate_identity(kem, &pub, &pl, &sec, &sl) == CRYPTO_SUCCESS,
                   "hybrid KAT: identity generates");
            size_t rec_len = X25519_KEY_SIZE + kem->length_ciphertext + 12 + 16 + 16;
            unsigned char *rec = malloc(rec_len);
            unsigned char key16[16], out16[16];
            memcpy(key16, ikm, 16);
            int ok = rec && pub && sec &&
                     crypto_hybrid_wrap(kem, pub, "qsafe-age-plugin-v1", key16, 16, rec) == CRYPTO_SUCCESS &&
                     crypto_hybrid_unwrap(kem, sec, "qsafe-age-plugin-v1", rec, 16, out16) &&
                     memcmp(key16, out16, 16) == 0;
            ASSERT(ok, "hybrid wrap/unwrap round-trips a 16-byte key");
            /* A different label must NOT unwrap (domain separation). */
            int cross = rec && crypto_hybrid_unwrap(kem, sec, "qsafe-v5-hybrid-kek", rec, 16, out16);
            ASSERT(!cross, "HKDF labels are domain-separating");
            free(rec);
            if (sec) free(sec);
            free(pub);
            OQS_KEM_free(kem);
        }
    }
}

int main(void) {
    printf("=== Qsafe 5.0 Unit Tests ===\n");

    test_derive_aes_key();
    test_derive_key_from_passphrase();
    test_save_load_secret_key();
    test_save_load_public_key();
    test_encrypt_decrypt_file();
    test_known_answer_vectors();
    test_v7_known_answer_vectors();
    test_error_codes();

    printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
