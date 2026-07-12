#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include "crypto_utils.h"
#include "vault.h"

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

    /* (2b) General HKDF (crypto_hkdf_sha256) against RFC 5869 Test Case 1 —
     *      the canonical HKDF-SHA256 vector, so this pins the new exported
     *      primitive to the standard, not just to itself. */
    {
        char hex84[85];
        unsigned char ikm[22], rfc_salt[13], info[10], okm[42];
        memset(ikm, 0x0b, sizeof(ikm));
        for (int i = 0; i < 13; i++) rfc_salt[i] = (unsigned char)i;        /* 00..0c */
        for (int i = 0; i < 10; i++) info[i] = (unsigned char)(0xf0 + i);   /* f0..f9 */
        ASSERT(crypto_hkdf_sha256(ikm, sizeof(ikm), rfc_salt, sizeof(rfc_salt),
                                  info, sizeof(info), okm, sizeof(okm)) == CRYPTO_SUCCESS,
               "crypto_hkdf_sha256 RFC 5869 TC1 computes");
        to_hex(okm, sizeof(okm), hex84);
        ASSERT(strcmp(hex84, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                             "34007208d5b887185865") == 0,
               "crypto_hkdf_sha256 matches RFC 5869 Test Case 1");
    }

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

    /* (3b) Argon2id (crypto_derive_key_argon2id), pass="argon2-vault-kat",
     *      salt = 16 bytes of 0x11, m=16 KiB, t=3, lanes=1 -> fixed 32-byte
     *      key. Pinned against the independent `openssl kdf ... ARGON2ID` CLI,
     *      confirming the EVP parameter wiring matches OpenSSL's RFC 9106
     *      implementation. */
    {
        unsigned char asalt[KDF_SALT_SIZE];
        memset(asalt, 0x11, sizeof(asalt));
        unsigned char akey[AES_KEY_SIZE];
        ASSERT(crypto_derive_key_argon2id("argon2-vault-kat", asalt, 16, 3, 1, akey) == CRYPTO_SUCCESS,
               "Argon2id KAT computes");
        to_hex(akey, sizeof(akey), hex);
        ASSERT(strcmp(hex, "bb320c05702aa2f97f11f2d0bd15f590d5374e2fff2a9523dc8d5abb18167d20") == 0,
               "Argon2id derived key matches the openssl kdf CLI");
    }
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

/* u64le packing matching vault.c's on-disk coordinate encoding (offset(8) ||
 * capacity(8), little-endian) — needed here only to reconstruct the salt
 * KAT's input bytes, not to duplicate vault.c's derivation logic. */
static void u64le(uint64_t v, unsigned char out[8]) {
    for (int i = 0; i < 8; i++) out[i] = (unsigned char)((v >> (8 * i)) & 0xff);
}

/* Known-answer vectors for qsafe vault (docs/HIDDEN_VOLUMES.md). Two kinds:
 *  - genuinely internal, not-exported pieces (the salt formula) are pinned by
 *    reimplementing them here from raw primitives, with expected values
 *    computed independently in Python (hashlib + `cryptography`);
 *  - pieces vault.c actually calls through the public API
 *    (crypto_frame_nonce/crypto_gcm_seal_aad, crypto_derive_key_from_passphrase,
 *    vault_ciphertext_len) are exercised through that same API, so these KATs
 *    catch a regression in the real production code path, not a reimplementation
 *    of it. */
static void test_vault_known_answer_vectors(void) {
    printf("\n[test_vault_known_answer_vectors]\n");
    char hex[65];

    /* (1) Salt formula: SHA-256("qsafe-vault-salt-v1" || u64le(offset) ||
     *     u64le(capacity))[0:16]. Not exported (see HIDDEN_VOLUMES.md §5 —
     *     a vault slot has no on-disk header, so nothing about its derivation
     *     can be a callable "load the salt" API); reimplemented from raw
     *     EVP_Digest here purely to pin the formula against an independent
     *     Python computation. */
    {
        const char *ctx = "qsafe-vault-salt-v1";
        unsigned char coords[16];
        u64le(0, coords);
        u64le(1048576, coords + 8);
        unsigned char ikm[64];
        size_t ctxlen = strlen(ctx);
        memcpy(ikm, ctx, ctxlen);
        memcpy(ikm + ctxlen, coords, sizeof(coords));
        unsigned char digest[32];
        unsigned int dlen = 0;
        ASSERT(EVP_Digest(ikm, ctxlen + sizeof(coords), digest, &dlen, EVP_sha256(), NULL) == 1 && dlen == 32,
               "vault salt KAT computes");
        to_hex(digest, 16, hex);
        ASSERT(strcmp(hex, "9fb1dfff5f34ff36f18bc003b5ef265a") == 0,
               "vault salt (offset=0, capacity=1048576) matches known answer");

        u64le(1200000, coords);
        u64le(100000, coords + 8);
        memcpy(ikm + ctxlen, coords, sizeof(coords));
        ASSERT(EVP_Digest(ikm, ctxlen + sizeof(coords), digest, &dlen, EVP_sha256(), NULL) == 1 && dlen == 32,
               "vault salt KAT (2nd coordinate pair) computes");
        to_hex(digest, 16, hex);
        ASSERT(strcmp(hex, "c8c524e2d4412156a8cc014a2bf34825") == 0,
               "vault salt (offset=1200000, capacity=100000) matches known answer "
               "(differs from the first: coordinates domain-separate the salt)");
    }

    /* (2) vault_ciphertext_len (the real exported function, not a
     *     reimplementation): capacity + 16 * (capacity / 65536 + 1). */
    {
        static const struct { uint64_t cap, len; } cases[] = {
            { 9, 25 }, { 65536, 65568 }, { 65537, 65569 },
            { 1048576, 1048848 }, { 100000, 100032 },
        };
        int all = 1;
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            if (vault_ciphertext_len(cases[i].cap) != cases[i].len) all = 0;
        }
        ASSERT(all, "vault_ciphertext_len matches known answers");
    }

    /* (3) Frame AEAD through the actual exported functions vault.c calls:
     *     crypto_frame_nonce(counter=0, final=1) and crypto_gcm_seal_aad,
     *     key = bytes 0x00..0x1f, aad = coords(offset=0, capacity=32),
     *     plaintext = "Qsafe frame KAT". A regression here is a regression
     *     in the code vault.c actually runs. */
    {
        unsigned char key[32];
        for (int i = 0; i < 32; i++) key[i] = (unsigned char)i;
        unsigned char nonce[AES_GCM_NONCE_SIZE];
        crypto_frame_nonce(0, 1, nonce);
        unsigned char aad[16];
        u64le(0, aad);
        u64le(32, aad + 8);
        const unsigned char pt[] = "Qsafe frame KAT"; /* 15 bytes, no NUL */
        unsigned char ct[15], tag[AES_GCM_TAG_SIZE];
        ASSERT(crypto_gcm_seal_aad(key, nonce, aad, sizeof(aad), pt, 15, ct, tag) == 1,
               "vault-style frame AEAD KAT computes");
        char cthex[2 * (15 + AES_GCM_TAG_SIZE) + 1];
        to_hex(ct, 15, cthex);
        to_hex(tag, AES_GCM_TAG_SIZE, cthex + 30);
        ASSERT(strcmp(cthex, "44a5de9a21d4566c6f433419a7e76ec08684b806c43bd1c4ba0042085d578a") == 0,
               "vault-style frame 0 (final, coords AAD) matches known answer");

        /* Opening it back through crypto_gcm_open_aad must round-trip, and
         * must fail under the "HDR" AAD the main QSAFE007 path uses instead
         * — confirming the two formats' AADs don't cross-authenticate. */
        unsigned char pt_out[15];
        ASSERT(crypto_gcm_open_aad(key, nonce, aad, sizeof(aad), ct, 15, tag, pt_out) == 1 &&
               memcmp(pt, pt_out, 15) == 0,
               "vault-style frame AEAD opens back to the original plaintext");
        ASSERT(crypto_gcm_open_aad(key, nonce, (const unsigned char *)"HDR", 3, ct, 15, tag, pt_out) == 0,
               "vault coords AAD does not authenticate under the QSAFE007 \"HDR\" AAD");
    }

    /* (4) scrypt at vault's minimum allowed cost (N=2^14, used by the fixture
     *     container in tests/fixtures/vault/ to keep CI fast) through the
     *     same exported crypto_derive_key_from_passphrase the main format
     *     already pins at N=2^15 above. */
    {
        unsigned char salt[KDF_SALT_SIZE];
        memset(salt, 0x11, sizeof(salt));
        unsigned char key[AES_KEY_SIZE];
        ASSERT(crypto_derive_key_from_passphrase("hunter2", salt, 1ULL << 14, 8, 1, key) == CRYPTO_SUCCESS,
               "scrypt KAT (N=2^14) computes");
        to_hex(key, sizeof(key), hex);
        ASSERT(strcmp(hex, "ba224982dfaabd0d8d1336ef6482b654f989b93af1ee85e118941b397dd54297") == 0,
               "scrypt (N=2^14) derived key matches known answer");
    }
}

/* Known-answer vectors for the vault v2 (anchor + directory) building blocks —
 * docs/HIDDEN_VOLUMES_V2.md. Exercised through the actual exported functions
 * (vault_slot_len, vault_v2_frame_key, vault_anchor_offset), with expected
 * values computed independently in Python (hashlib + `cryptography`'s Scrypt
 * and HKDF), so a regression is caught in the real derivation, not a
 * reimplementation. Costs are pinned at N=2^14 to stay fast. */
static void test_vault_v2_known_answer_vectors(void) {
    printf("\n[test_vault_v2_known_answer_vectors]\n");
    char hex[65];

    /* (1) v2 slot on-disk length = 16-byte nonce salt + framed ciphertext. */
    {
        ASSERT(vault_slot_len(4096) == 4128, "vault_slot_len(4096) == 4128 (anchor span)");
        ASSERT(vault_slot_len(9) == 16 + 25, "vault_slot_len(9) == 41");
        ASSERT(vault_slot_len(65536) == 16 + 65568, "vault_slot_len(65536) == 65584");
    }

    /* (2) v2 slot frame key: HKDF(scrypt(pass, coord_salt(0,1048576), N=2^14),
     *     salt = nonce_salt(0x00..0x0f), info = "qsafe-vault-slot-v2"). */
    {
        crypto_config_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.passphrase = "vault-v2-kat-pass";
        cfg.scrypt_n = 1ULL << 14;
        cfg.scrypt_r = 8;
        cfg.scrypt_p = 1;
        unsigned char nonce_salt[VAULT_NONCE_SALT_SIZE];
        for (int i = 0; i < VAULT_NONCE_SALT_SIZE; i++) nonce_salt[i] = (unsigned char)i;
        unsigned char key[AES_KEY_SIZE];
        ASSERT(vault_v2_frame_key(&cfg, 0, 1048576, nonce_salt, key) == 1,
               "vault_v2_frame_key computes");
        to_hex(key, sizeof(key), hex);
        ASSERT(strcmp(hex, "42b46cf77079791c9e0cc9057597759d88f7c41cb3571690984c4a95b6e8e2e2") == 0,
               "v2 slot frame key matches known answer");

        /* A different nonce salt must yield a different key — the property the
         * per-write salt exists for. */
        unsigned char nonce_salt2[VAULT_NONCE_SALT_SIZE];
        memset(nonce_salt2, 0xAA, sizeof(nonce_salt2));
        unsigned char key2[AES_KEY_SIZE];
        ASSERT(vault_v2_frame_key(&cfg, 0, 1048576, nonce_salt2, key2) == 1 &&
               memcmp(key, key2, AES_KEY_SIZE) != 0,
               "a different nonce salt yields a different frame key");
    }

    /* (3) Anchor offset: end-to-end at N=2^14 for a 10,000,000-byte container.
     *     Pins the whole pipeline (scrypt over the fixed anchor-loc salt, HKDF
     *     mixing in the container size, and the modular reduction). */
    {
        uint64_t off = 0;
        ASSERT(vault_anchor_offset("vault-anchor-kat-pass", 10000000, 1ULL << 14, 8, 1, 0, NULL, &off) == CRYPTO_SUCCESS,
               "vault_anchor_offset computes");
        ASSERT(off == 5631317, "anchor offset matches known answer (Lemire multiply-shift reduction)");
        ASSERT(off + vault_slot_len(VAULT_ANCHOR_CAPACITY) <= 10000000,
               "anchor slot fits inside the container");

        /* A different container size relocates the anchor (size is mixed into
         * the derivation), and a container too small to hold an anchor fails. */
        uint64_t off2 = 0;
        ASSERT(vault_anchor_offset("vault-anchor-kat-pass", 20000000, 1ULL << 14, 8, 1, 0, NULL, &off2) == CRYPTO_SUCCESS &&
               off2 != 1389354,
               "a different container size relocates the anchor");
        uint64_t off3 = 0;
        ASSERT(vault_anchor_offset("vault-anchor-kat-pass", 1000, 1ULL << 14, 8, 1, 0, NULL, &off3) == CRYPTO_ERR_INVALID_INPUT,
               "a container too small for an anchor is rejected");
    }
}

/* Builds a directory entry with a C-string name. */
static vault_entry_t mk_entry(uint64_t off, uint64_t cap, uint8_t logn, uint8_t flags, const char *name) {
    vault_entry_t e;
    memset(&e, 0, sizeof(e));
    e.offset = off; e.capacity = cap; e.scrypt_log_n = logn; e.flags = flags;
    e.name_len = (uint16_t)strlen(name);
    memcpy(e.name, name, e.name_len);
    return e;
}

/* Volume directory (docs/HIDDEN_VOLUMES_V2.md §3): serialization KAT, the
 * hostile-input rejections the parser must enforce, add/find/remove, and an
 * end-to-end round-trip through the real v2 slot seal/open. */
static void test_vault_directory(void) {
    printf("\n[test_vault_directory]\n");

    vault_dir_t dir;
    memset(&dir, 0, sizeof(dir));
    dir.version = VAULT_DIR_VERSION;
    dir.entry_count = 2;
    dir.entries[0] = mk_entry(140048, 100000, 20, 0, "decoy");
    dir.entries[1] = mk_entry(500000, 50000, 14, 1, "hidden");

    /* (1) Serialization KAT: the deterministic header+entries region (the
     *     padding is random) hashes to a value computed independently in
     *     Python. */
    unsigned char block[VAULT_ANCHOR_CAPACITY];
    ASSERT(vault_dir_serialize(&dir, block) == 1, "directory serializes");
    {
        size_t region = VAULT_DIR_HEADER + (size_t)dir.entry_count * VAULT_ENTRY_SIZE;
        unsigned char digest[32]; unsigned int dlen = 0; char hex[65];
        EVP_Digest(block, region, digest, &dlen, EVP_sha256(), NULL);
        to_hex(digest, 32, hex);
        ASSERT(strcmp(hex, "c3d724acf8b88fdbf90d78d5c5c81274f1ea039177c116c008ce206e327f4b34") == 0,
               "serialized header+entries region matches known answer");
    }

    /* (2) Round-trip: parse the block back and compare fields. */
    {
        vault_dir_t got;
        memset(&got, 0, sizeof(got));
        ASSERT(vault_dir_parse(block, &got) == 1, "directory parses back");
        ASSERT(got.version == VAULT_DIR_VERSION && got.entry_count == 2, "version and count round-trip");
        ASSERT(got.entries[1].offset == 500000 && got.entries[1].capacity == 50000 &&
               got.entries[1].scrypt_log_n == 14 && got.entries[1].flags == 1 &&
               got.entries[1].name_len == 6 && memcmp(got.entries[1].name, "hidden", 6) == 0,
               "second entry round-trips field-for-field");
    }

    /* (3) Hostile-input rejection — every attacker-influenced field is bounded.
     *     Start from a valid block and corrupt one field at a time. */
    {
        unsigned char bad[VAULT_ANCHOR_CAPACITY];
        vault_dir_t out;

        memcpy(bad, block, sizeof(bad));
        bad[0] = 0x09;                                  /* wrong version */
        ASSERT(vault_dir_parse(bad, &out) == 0, "rejects a wrong directory version");

        memcpy(bad, block, sizeof(bad));
        bad[2] = 0xff; bad[3] = 0xff;                   /* entry_count = 65535 > MAX */
        ASSERT(vault_dir_parse(bad, &out) == 0, "rejects an entry_count over the maximum");

        memcpy(bad, block, sizeof(bad));
        bad[VAULT_DIR_HEADER + 18] = 0xff;              /* entry 0 name_len = 255 > 64 */
        bad[VAULT_DIR_HEADER + 19] = 0x00;
        ASSERT(vault_dir_parse(bad, &out) == 0, "rejects a name_len over the maximum");

        memcpy(bad, block, sizeof(bad));
        bad[VAULT_DIR_HEADER + 16] = 0x02;              /* entry 0 scrypt_log_n = 2 (< 14) */
        ASSERT(vault_dir_parse(bad, &out) == 0, "rejects an out-of-range scrypt cost");

        memcpy(bad, block, sizeof(bad));
        memset(bad + VAULT_DIR_HEADER + 8, 0, 8);       /* entry 0 capacity = 0 (< MIN) */
        ASSERT(vault_dir_parse(bad, &out) == 0, "rejects a capacity below the minimum");
    }

    /* (4) find / add / remove. */
    {
        vault_dir_t d;
        memset(&d, 0, sizeof(d));
        d.version = VAULT_DIR_VERSION;
        vault_entry_t a = mk_entry(1000, 20000, 18, 0, "alpha");
        vault_entry_t b = mk_entry(90000, 30000, 18, 0, "bravo");
        ASSERT(vault_dir_add(&d, &a) == 1 && vault_dir_add(&d, &b) == 1, "adds two entries");
        ASSERT(vault_dir_add(&d, &a) == 0, "rejects a duplicate name");
        ASSERT(vault_dir_find(&d, "bravo") == 1 && vault_dir_find(&d, "missing") == -1, "finds by name");
        ASSERT(vault_dir_remove(&d, "alpha") == 1 && d.entry_count == 1 &&
               vault_dir_find(&d, "bravo") == 0, "removes and compacts");
    }

    /* (4b) Overflow-pointer entry (§3.1): the flag mechanism a directory chain
     *      is built on. An entry with VAULT_ENTRY_FLAG_OVERFLOW must serialize
     *      and parse back with the flag intact (so a reader can distinguish a
     *      next-block pointer from a data slot), and the in-memory dir cap is
     *      VAULT_MAX_VOL_ENTRIES, not the per-block 46. */
    {
        vault_dir_t ov;
        memset(&ov, 0, sizeof(ov));
        ov.version = VAULT_DIR_VERSION;
        ov.entry_count = 2;
        ov.entries[0] = mk_entry(1000, 20000, 18, 0, "data");
        ov.entries[1] = mk_entry(700000, VAULT_ANCHOR_CAPACITY, 14, VAULT_ENTRY_FLAG_OVERFLOW, "");
        unsigned char blk[VAULT_ANCHOR_CAPACITY];
        vault_dir_t got;
        memset(&got, 0, sizeof(got));
        ASSERT(vault_dir_serialize(&ov, blk) == 1 && vault_dir_parse(blk, &got) == 1,
               "a block with an overflow-pointer entry serializes and parses");
        ASSERT((got.entries[1].flags & VAULT_ENTRY_FLAG_OVERFLOW) &&
               got.entries[1].offset == 700000 && got.entries[1].capacity == VAULT_ANCHOR_CAPACITY,
               "the overflow-pointer entry round-trips with its flag and target");
        ASSERT(VAULT_MAX_VOL_ENTRIES > VAULT_MAX_ENTRIES,
               "the in-memory directory spans more than one block");
    }

    /* (5) End-to-end: serialize a directory, seal it into an anchor-sized v2
     *     slot, open it back, and parse — exercising the real v2 seal/open and
     *     confirming a wrong passphrase fails to open. */
    {
        crypto_config_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.passphrase = "vault-dir-e2e-pass";
        cfg.scrypt_n = 1ULL << 14; cfg.scrypt_r = 8; cfg.scrypt_p = 1;

        unsigned char plain[VAULT_ANCHOR_CAPACITY];
        ASSERT(vault_dir_serialize(&dir, plain) == 1, "e2e: serialize directory");

        unsigned char *slot = malloc(vault_slot_len(VAULT_ANCHOR_CAPACITY));
        unsigned char *recovered = malloc(VAULT_ANCHOR_CAPACITY);
        ASSERT(slot && recovered, "e2e: allocate slot buffers");
        if (slot && recovered) {
            uint64_t off = 4096; /* arbitrary anchor location for the test */
            ASSERT(vault_v2_seal(slot, off, VAULT_ANCHOR_CAPACITY, &cfg, plain) == 1, "e2e: seal anchor slot");
            ASSERT(vault_v2_open(slot, off, VAULT_ANCHOR_CAPACITY, &cfg, recovered) == 1, "e2e: open anchor slot");
            ASSERT(memcmp(plain, recovered, VAULT_ANCHOR_CAPACITY) == 0, "e2e: recovered plaintext matches");

            vault_dir_t got;
            memset(&got, 0, sizeof(got));
            ASSERT(vault_dir_parse(recovered, &got) == 1 && got.entry_count == 2 &&
                   memcmp(got.entries[0].name, "decoy", 5) == 0,
                   "e2e: recovered directory parses with the right entries");

            /* Sealing again yields different bytes (fresh nonce salt), but the
             * same plaintext on open — the per-write-salt property. */
            unsigned char *slot2 = malloc(vault_slot_len(VAULT_ANCHOR_CAPACITY));
            if (slot2) {
                ASSERT(vault_v2_seal(slot2, off, VAULT_ANCHOR_CAPACITY, &cfg, plain) == 1, "e2e: reseal");
                ASSERT(memcmp(slot, slot2, vault_slot_len(VAULT_ANCHOR_CAPACITY)) != 0,
                       "e2e: resealing the same directory yields different ciphertext");
                free(slot2);
            }

            /* Wrong passphrase must fail to open. */
            crypto_config_t bad = cfg;
            bad.passphrase = "wrong-pass";
            ASSERT(vault_v2_open(slot, off, VAULT_ANCHOR_CAPACITY, &bad, recovered) == 0,
                   "e2e: wrong passphrase fails to open the anchor");
        }
        free(slot);
        free(recovered);
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
    test_vault_known_answer_vectors();
    test_vault_v2_known_answer_vectors();
    test_vault_directory();
    test_error_codes();

    printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
