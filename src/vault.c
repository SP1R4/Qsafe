/* Deniable hidden-volume containers. See docs/HIDDEN_VOLUMES.md for the design
 * rationale and threat model. Deliberately symmetric/passphrase-only and
 * independent of the QSAFE007 recipient-record container — see that doc, §2,
 * for why (ML-KEM ciphertext is not proven indistinguishable from random).
 *
 * Reuses the same framed-AEAD convention QSAFE007 payloads use
 * (crypto_frame_nonce / crypto_gcm_seal_aad / crypto_gcm_open_aad) and the
 * existing scrypt passphrase KDF (crypto_derive_key_from_passphrase); no new
 * cryptographic primitive is introduced here. */

#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include "platform.h"
#include "crypto_utils.h"
#include "vault.h"

/* Default scrypt cost for vault slots: higher than the keyfile default
 * (2^15, SCRYPT_DEFAULT_LOG_N) because a slot's passphrase is the *only*
 * thing protecting it — there is no separate high-entropy secret key behind
 * it the way a passphrase-wrapped keyfile has. See HIDDEN_VOLUMES.md §3. */
#define VAULT_DEFAULT_LOG_N 20

/* v2 (anchor + directory) derivation labels — see docs/HIDDEN_VOLUMES_V2.md.
 * The coordinate salt (v1) is unchanged; these add the per-slot nonce-salt key
 * step and the passphrase-located anchor. */
#define VAULT_SLOT_KEY_INFO  "qsafe-vault-slot-v2"    /* HKDF info for a v2 slot frame key */
#define VAULT_ANCHOR_LOC_CTX "qsafe-vault-anchor-loc" /* scrypt salt seed for the anchor location */
#define VAULT_ANCHOR_INFO    "qsafe-vault-anchor-v2"  /* HKDF info prefix, then u64le(container_size) */

static void store_u64le(unsigned char *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (unsigned char)((v >> (8 * i)) & 0xff);
}

static uint64_t load_u64le(const unsigned char *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= ((uint64_t)p[i]) << (8 * i);
    return v;
}

static void store_u16le(unsigned char *p, uint16_t v) {
    p[0] = (unsigned char)(v & 0xff);
    p[1] = (unsigned char)((v >> 8) & 0xff);
}

static uint16_t load_u16le(const unsigned char *p) {
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static void store_u32le(unsigned char *p, uint32_t v) {
    for (int i = 0; i < 4; i++) p[i] = (unsigned char)((v >> (8 * i)) & 0xff);
}

/* offset(8 LE) || capacity(8 LE) — used both as the salt-derivation input and
 * as the AAD bound into frame 0, so a slot's ciphertext cannot be replayed
 * into a different (offset, capacity) pair. Not secret. */
static void store_coords(uint64_t offset, uint64_t capacity, unsigned char out[16]) {
    store_u64le(out, offset);
    store_u64le(out + 8, capacity);
}

/* SHA-256 of (data,len) truncated to 16 bytes — the shape of every
 * derived-but-never-stored 16-byte salt in this format. */
static int vault_sha256_16(const unsigned char *data, size_t len, unsigned char out16[16]) {
    unsigned char digest[32];
    unsigned int dlen = 0;
    if (EVP_Digest(data, len, digest, &dlen, EVP_sha256(), NULL) != 1 || dlen != 32) return 0;
    memcpy(out16, digest, 16);
    return 1;
}

/* salt = SHA-256("qsafe-vault-salt-v1" || coords)[0:16]. Deliberately not
 * random/stored: a vault slot carries no on-disk header at all (see
 * HIDDEN_VOLUMES.md §5), so the salt must be re-derivable from public
 * information (the coordinates the caller already supplies). */
static int vault_derive_salt(uint64_t offset, uint64_t capacity, unsigned char salt16[16]) {
    unsigned char coords[16];
    store_coords(offset, capacity, coords);
    const char *ctx = "qsafe-vault-salt-v1";
    unsigned char ikm[16 + 32];
    size_t ctxlen = strlen(ctx);
    memcpy(ikm, ctx, ctxlen);
    memcpy(ikm + ctxlen, coords, sizeof(coords));
    return vault_sha256_16(ikm, ctxlen + sizeof(coords), salt16);
}

/* Passphrase -> 32-byte key via the volume's chosen memory-hard KDF: scrypt by
 * default, or Argon2id when argon2 is set. In Argon2 mode `n` is reused as the
 * memory cost (KiB) and r/p are ignored (time cost 3, 1 lane fixed). */
static int vault_pw_key(const char *passphrase, const unsigned char *salt,
                        uint64_t n, uint32_t r, uint32_t p, int argon2,
                        unsigned char key_out[AES_KEY_SIZE]) {
    if (argon2) {
        uint32_t m_kib = (n > 0xFFFFFFFFULL) ? 0xFFFFFFFFu : (uint32_t)n;
        return crypto_derive_key_argon2id(passphrase, salt, m_kib, 3, 1, key_out) == CRYPTO_SUCCESS;
    }
    return crypto_derive_key_from_passphrase(passphrase, salt, n, r, p, key_out) == CRYPTO_SUCCESS;
}

static int vault_slot_key(const crypto_config_t *config, uint64_t offset, uint64_t capacity,
                          unsigned char key_out[AES_KEY_SIZE]) {
    unsigned char salt[16];
    if (!vault_derive_salt(offset, capacity, salt)) return 0;
    uint64_t n = config->scrypt_n ? config->scrypt_n : (1ULL << VAULT_DEFAULT_LOG_N);
    uint32_t r = config->scrypt_n ? config->scrypt_r : SCRYPT_DEFAULT_R;
    uint32_t p = config->scrypt_n ? config->scrypt_p : SCRYPT_DEFAULT_P;
    return vault_pw_key(config->passphrase, salt, n, r, p, config->vault_kdf_argon2, key_out);
}

uint64_t vault_ciphertext_len(uint64_t capacity) {
    return capacity + AES_GCM_TAG_SIZE * (capacity / QSAFE_FRAME_SIZE + 1);
}

/* --- v2 building blocks (anchor + directory; docs/HIDDEN_VOLUMES_V2.md) --- */

uint64_t vault_slot_len(uint64_t capacity) {
    return VAULT_NONCE_SALT_SIZE + vault_ciphertext_len(capacity);
}

/* v2 slot frame key:
 *   ikm = scrypt(passphrase, coord_salt(offset,capacity), config cost)   [v1 slot key]
 *   key = HKDF-SHA256(ikm, salt = nonce_salt, info = "qsafe-vault-slot-v2")
 * The scrypt step is the per-guess wall; the per-write nonce_salt makes every
 * seal of identical content produce different ciphertext (v2 §1), which is
 * what lets a whole-container rewrite (v2 §4) leak nothing on a snapshot diff. */
int vault_v2_frame_key(const crypto_config_t *config, uint64_t offset, uint64_t capacity,
                       const unsigned char *nonce_salt, unsigned char *key_out) {
    unsigned char scrypt_key[AES_KEY_SIZE];
    if (!vault_slot_key(config, offset, capacity, scrypt_key)) return 0;

    /* HKDF info = "qsafe-vault-slot-v2" [‖ keyfile_key(32)]. Appending the
     * keyfile only when present keeps the no-keyfile output byte-identical. */
    unsigned char info[sizeof(VAULT_SLOT_KEY_INFO) - 1 + 32];
    size_t ilen = strlen(VAULT_SLOT_KEY_INFO);
    memcpy(info, VAULT_SLOT_KEY_INFO, ilen);
    if (config->vault_keyfile_key) { memcpy(info + ilen, config->vault_keyfile_key, 32); ilen += 32; }

    int ok = crypto_hkdf_sha256(scrypt_key, sizeof(scrypt_key),
                                nonce_salt, VAULT_NONCE_SALT_SIZE,
                                info, ilen, key_out, AES_KEY_SIZE) == CRYPTO_SUCCESS;
    OPENSSL_cleanse(scrypt_key, sizeof(scrypt_key));
    return ok;
}

/* Passphrase-located anchor offset for a container of the given size:
 *   loc_salt   = SHA-256("qsafe-vault-anchor-loc")[0:16]        (fixed)
 *   anchor_ikm = scrypt(passphrase, loc_salt, cost)
 *   x          = HKDF-SHA256(anchor_ikm, info = "qsafe-vault-anchor-v2" ‖ u64le(size))[0:8]  (u64le)
 *   offset     = (x * m) >> 64,  m = container_size - slot_len(ANCHOR_CAPACITY) + 1
 * The reduction is Lemire's multiply-shift, NOT `x % m`: `x` is secret-derived
 * and a 64-bit modulo is data-dependent in timing on most CPUs, whereas a
 * 128-bit multiply + shift is constant-time. It maps `x` uniformly into
 * [0, m) with bias <= m / 2^64 (negligible here). Cost is a parameter so
 * tests can run cheaply; production opens pass n = 1 << VAULT_ANCHOR_LOG_N
 * (fixed, so the passphrase alone locates the anchor). */
crypto_error_t vault_anchor_offset(const char *passphrase, uint64_t container_size,
                                   uint64_t n, uint32_t r, uint32_t p, int argon2,
                                   const unsigned char *keyfile_key, uint64_t *offset_out) {
    uint64_t span = vault_slot_len(VAULT_ANCHOR_CAPACITY);
    if (container_size < span) return CRYPTO_ERR_INVALID_INPUT; /* too small to hold an anchor */

    unsigned char loc_salt[16];
    if (!vault_sha256_16((const unsigned char *)VAULT_ANCHOR_LOC_CTX, strlen(VAULT_ANCHOR_LOC_CTX), loc_salt))
        return CRYPTO_ERR_CRYPTO;

    unsigned char anchor_ikm[AES_KEY_SIZE];
    if (!vault_pw_key(passphrase, loc_salt, n, r, p, argon2, anchor_ikm))
        return CRYPTO_ERR_CRYPTO;

    /* info = "qsafe-vault-anchor-v2" ‖ u64le(size) [‖ keyfile_key(32)], so a
     * keyfile changes *where* the anchor is — the passphrase alone can't even
     * locate it. Absent a keyfile the info is unchanged. */
    unsigned char info[sizeof(VAULT_ANCHOR_INFO) - 1 + 8 + 32];
    size_t infolen = strlen(VAULT_ANCHOR_INFO);
    memcpy(info, VAULT_ANCHOR_INFO, infolen);
    store_u64le(info + infolen, container_size);
    infolen += 8;
    if (keyfile_key) { memcpy(info + infolen, keyfile_key, 32); infolen += 32; }

    unsigned char out8[8];
    int ok = crypto_hkdf_sha256(anchor_ikm, sizeof(anchor_ikm), NULL, 0,
                                info, infolen, out8, sizeof(out8)) == CRYPTO_SUCCESS;
    OPENSSL_cleanse(anchor_ikm, sizeof(anchor_ikm));
    if (!ok) return CRYPTO_ERR_CRYPTO;

    uint64_t x = load_u64le(out8);
    uint64_t m = container_size - span + 1;
    *offset_out = (uint64_t)(((unsigned __int128)x * m) >> 64);
    return CRYPTO_SUCCESS;
}

/* Seal an exactly-`capacity`-byte plaintext blob into a v2 slot: a fresh
 * 16-byte nonce salt, then the blob as framed AES-256-GCM (§2.3 FORMAT.md
 * convention, keyed by vault_v2_frame_key). `slot` receives slot_len(capacity)
 * bytes. The coordinates are bound as AAD on frame 0 (like v1), so a slot's
 * bytes cannot be lifted to a different (offset, capacity). */
int vault_v2_seal(unsigned char *slot, uint64_t offset, uint64_t capacity,
                  const crypto_config_t *config, const unsigned char *plaintext) {
    unsigned char nonce_salt[VAULT_NONCE_SALT_SIZE];
    unsigned char key[AES_KEY_SIZE];
    if (RAND_bytes(nonce_salt, sizeof(nonce_salt)) != 1) return 0;
    if (!vault_v2_frame_key(config, offset, capacity, nonce_salt, key)) {
        OPENSSL_cleanse(nonce_salt, sizeof(nonce_salt));
        return 0;
    }
    memcpy(slot, nonce_salt, VAULT_NONCE_SALT_SIZE);
    unsigned char *w = slot + VAULT_NONCE_SALT_SIZE;

    unsigned char aad[16];
    store_coords(offset, capacity, aad);
    uint64_t full = capacity / QSAFE_FRAME_SIZE;
    uint64_t rem = capacity % QSAFE_FRAME_SIZE;
    uint64_t nframes = full + 1, pt_off = 0;
    int ret = 1;
    for (uint64_t ctr = 0; ctr < nframes; ctr++) {
        int last = (ctr == nframes - 1);
        size_t want = last ? (size_t)rem : (size_t)QSAFE_FRAME_SIZE;
        unsigned char nonce[AES_GCM_NONCE_SIZE], tag[AES_GCM_TAG_SIZE];
        crypto_frame_nonce(ctr, last, nonce);
        const unsigned char *a = (ctr == 0) ? aad : NULL;
        size_t alen = (ctr == 0) ? sizeof(aad) : 0;
        if (!crypto_gcm_seal_aad(key, nonce, a, alen, plaintext + pt_off, (int)want, w, tag)) { ret = 0; break; }
        w += want;
        memcpy(w, tag, AES_GCM_TAG_SIZE);
        w += AES_GCM_TAG_SIZE;
        pt_off += want;
    }
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(nonce_salt, sizeof(nonce_salt));
    return ret;
}

/* Inverse of vault_v2_seal: recover the exactly-`capacity`-byte plaintext.
 * Returns 1 only if every frame's GCM tag verifies (right passphrase, right
 * coordinates, intact bytes); 0 otherwise — the caller treats 0 as the same
 * indistinguishable "no data here" as any wrong-passphrase read. */
int vault_v2_open(const unsigned char *slot, uint64_t offset, uint64_t capacity,
                  const crypto_config_t *config, unsigned char *plaintext_out) {
    unsigned char key[AES_KEY_SIZE];
    if (!vault_v2_frame_key(config, offset, capacity, slot /* nonce_salt */, key)) return 0;
    const unsigned char *rd = slot + VAULT_NONCE_SALT_SIZE;

    unsigned char aad[16];
    store_coords(offset, capacity, aad);
    uint64_t full = capacity / QSAFE_FRAME_SIZE;
    uint64_t rem = capacity % QSAFE_FRAME_SIZE;
    uint64_t nframes = full + 1, pt_off = 0;
    int ret = 1;
    for (uint64_t ctr = 0; ctr < nframes; ctr++) {
        int last = (ctr == nframes - 1);
        size_t want = last ? (size_t)rem : (size_t)QSAFE_FRAME_SIZE;
        unsigned char nonce[AES_GCM_NONCE_SIZE];
        crypto_frame_nonce(ctr, last, nonce);
        const unsigned char *a = (ctr == 0) ? aad : NULL;
        size_t alen = (ctr == 0) ? sizeof(aad) : 0;
        const unsigned char *ct = rd;
        const unsigned char *tag = rd + want;
        if (!crypto_gcm_open_aad(key, nonce, a, alen, ct, (int)want, tag, plaintext_out + pt_off)) { ret = 0; break; }
        rd += want + AES_GCM_TAG_SIZE;
        pt_off += want;
    }
    OPENSSL_cleanse(key, sizeof(key));
    return ret;
}

/* --- volume directory (docs/HIDDEN_VOLUMES_V2.md §3) --- */

int vault_dir_serialize(const vault_dir_t *dir, unsigned char *out) {
    if (dir->entry_count > VAULT_MAX_ENTRIES) return 0;
    /* Fill the whole block with random first, so the padding after the entries
     * is indistinguishable from an unused slot's filler; then lay the header
     * and entries over the front. */
    if (RAND_bytes(out, VAULT_ANCHOR_CAPACITY) != 1) return 0;
    store_u16le(out, dir->version);
    store_u16le(out + 2, dir->entry_count);
    store_u32le(out + 4, 0);
    unsigned char *p = out + VAULT_DIR_HEADER;
    for (uint16_t i = 0; i < dir->entry_count; i++) {
        const vault_entry_t *e = &dir->entries[i];
        if (e->name_len > VAULT_MAX_NAME_LEN) return 0;
        store_u64le(p, e->offset);
        store_u64le(p + 8, e->capacity);
        p[16] = e->scrypt_log_n;
        p[17] = e->flags;
        store_u16le(p + 18, e->name_len);
        memset(p + 20, 0, VAULT_MAX_NAME_LEN);
        memcpy(p + 20, e->name, e->name_len);
        store_u32le(p + 84, 0);
        p += VAULT_ENTRY_SIZE;
    }
    return 1;
}

int vault_dir_parse(const unsigned char *in, vault_dir_t *dir) {
    uint16_t version = load_u16le(in);
    uint16_t count = load_u16le(in + 2);
    if (version != VAULT_DIR_VERSION) return 0;
    if (count > VAULT_MAX_ENTRIES) return 0;
    dir->version = version;
    dir->entry_count = count;
    const unsigned char *p = in + VAULT_DIR_HEADER;
    for (uint16_t i = 0; i < count; i++) {
        vault_entry_t *e = &dir->entries[i];
        e->offset = load_u64le(p);
        e->capacity = load_u64le(p + 8);
        e->scrypt_log_n = p[16];
        e->flags = p[17];
        e->name_len = load_u16le(p + 18);
        /* Every field below is attacker-influenced once an anchor decrypts —
         * bound them all before this directory is trusted to locate slots. */
        if (e->name_len > VAULT_MAX_NAME_LEN) return 0;
        if (e->capacity < VAULT_MIN_CAPACITY || e->capacity > VAULT_MAX_CAPACITY) return 0;
        if (e->offset > VAULT_MAX_OFFSET) return 0;
        if (e->scrypt_log_n < 14 || e->scrypt_log_n > 22) return 0;
        memcpy(e->name, p + 20, VAULT_MAX_NAME_LEN);
        p += VAULT_ENTRY_SIZE;
    }
    return 1;
}

/* Compares a directory entry's name (name_len bytes) against a C string. */
static int entry_name_eq(const vault_entry_t *e, const char *name) {
    size_t nlen = strlen(name);
    return nlen == e->name_len && memcmp(e->name, name, nlen) == 0;
}

int vault_dir_find(const vault_dir_t *dir, const char *name) {
    for (uint16_t i = 0; i < dir->entry_count; i++)
        if (entry_name_eq(&dir->entries[i], name)) return (int)i;
    return -1;
}

int vault_dir_add(vault_dir_t *dir, const vault_entry_t *entry) {
    if (dir->entry_count >= VAULT_MAX_VOL_ENTRIES) return 0;
    if (entry->name_len > VAULT_MAX_NAME_LEN) return 0;
    char name[VAULT_MAX_NAME_LEN + 1];
    memcpy(name, entry->name, entry->name_len);
    name[entry->name_len] = '\0';
    if (vault_dir_find(dir, name) >= 0) return 0; /* duplicate name */
    dir->entries[dir->entry_count++] = *entry;
    return 1;
}

int vault_dir_remove(vault_dir_t *dir, const char *name) {
    int idx = vault_dir_find(dir, name);
    if (idx < 0) return 0;
    for (uint16_t i = (uint16_t)idx; i + 1 < dir->entry_count; i++)
        dir->entries[i] = dir->entries[i + 1];
    dir->entry_count--;
    return 1;
}

static FILE *vault_open_output(const char *path) {
    if (strcmp(path, "-") == 0) return stdout;
    return fopen(path, "wb");
}

static void vault_close_stream(FILE *f) {
    if (f && f != stdin && f != stdout) fclose(f);
}

crypto_error_t vault_init(const char *path, uint64_t size, int force) {
    if (size == 0) {
        fprintf(stderr, "Error: --size must be greater than 0\n");
        return CRYPTO_ERR_INVALID_INPUT;
    }
    if (!force) {
        FILE *probe = fopen(path, "rb");
        if (probe) {
            fclose(probe);
            fprintf(stderr, "Error: '%s' already exists (use --force to overwrite)\n", path);
            return CRYPTO_ERR_INVALID_INPUT;
        }
    }
    FILE *out = fopen(path, "wb");
    if (!out) { perror("Error creating container"); return CRYPTO_ERR_FILE_IO; }

    unsigned char buf[65536];
    crypto_error_t ret = CRYPTO_SUCCESS;
    uint64_t left = size;
    while (left > 0) {
        size_t take = (left < sizeof(buf)) ? (size_t)left : sizeof(buf);
        if (RAND_bytes(buf, (int)take) != 1) {
            fprintf(stderr, "Error: failed to generate random bytes\n");
            ret = CRYPTO_ERR_CRYPTO;
            break;
        }
        if (fwrite(buf, 1, take, out) != take) {
            ret = CRYPTO_ERR_FILE_IO;
            break;
        }
        left -= take;
    }
    fclose(out);
    OPENSSL_cleanse(buf, sizeof(buf));
    if (ret == CRYPTO_SUCCESS) {
        printf("Container created: %s (%llu bytes, all random)\n", path, (unsigned long long)size);
    } else {
        remove(path);
    }
    return ret;
}

crypto_error_t vault_write(const char *path, uint64_t offset, uint64_t capacity,
                          const char *input_path, const crypto_config_t *config) {
    if (capacity < VAULT_MIN_CAPACITY || capacity > VAULT_MAX_CAPACITY) {
        fprintf(stderr, "Error: --capacity must be between %d and %llu bytes\n",
                VAULT_MIN_CAPACITY, (unsigned long long)VAULT_MAX_CAPACITY);
        return CRYPTO_ERR_INVALID_INPUT;
    }
    if (offset > VAULT_MAX_OFFSET) {
        fprintf(stderr, "Error: --offset must be at most %llu bytes\n", (unsigned long long)VAULT_MAX_OFFSET);
        return CRYPTO_ERR_INVALID_INPUT;
    }
    if (!config->passphrase) {
        fprintf(stderr, "Error: vault write requires a passphrase\n");
        return CRYPTO_ERR_INVALID_INPUT;
    }
    if (strcmp(input_path, "-") == 0) {
        fprintf(stderr, "Error: vault write requires a regular input file (stdin length is unknown, "
                        "and the slot's capacity must be fixed up front)\n");
        return CRYPTO_ERR_INVALID_INPUT;
    }

    FILE *in = fopen(input_path, "rb");
    if (!in) { perror("Error opening input file"); return CRYPTO_ERR_FILE_IO; }
    if (qsafe_fseek64(in, 0, SEEK_END) != 0) { fclose(in); return CRYPTO_ERR_FILE_IO; }
    long long in_size = qsafe_ftell64(in);
    if (in_size < 0 || qsafe_fseek64(in, 0, SEEK_SET) != 0) { fclose(in); return CRYPTO_ERR_FILE_IO; }
    uint64_t content_len = (uint64_t)in_size;

    if (content_len > capacity - 8) {
        fprintf(stderr, "Error: input is %llu bytes; this slot's capacity only fits %llu\n",
                (unsigned long long)content_len, (unsigned long long)(capacity - 8));
        fclose(in);
        return CRYPTO_ERR_INVALID_INPUT;
    }

    FILE *out = fopen(path, "r+b");
    if (!out) { perror("Error opening container"); fclose(in); return CRYPTO_ERR_FILE_IO; }
    if (qsafe_fseek64(out, 0, SEEK_END) != 0) { fclose(out); fclose(in); return CRYPTO_ERR_FILE_IO; }
    long long container_size = qsafe_ftell64(out);
    uint64_t need = offset + vault_ciphertext_len(capacity);
    if (container_size < 0 || (uint64_t)container_size < need) {
        fprintf(stderr, "Error: container is too small for this slot (have %lld bytes, need %llu)\n",
                container_size, (unsigned long long)need);
        fclose(out); fclose(in);
        return CRYPTO_ERR_INVALID_INPUT;
    }
    if (qsafe_fseek64(out, (long long)offset, SEEK_SET) != 0) {
        fclose(out); fclose(in);
        return CRYPTO_ERR_FILE_IO;
    }

    unsigned char slot_key[AES_KEY_SIZE];
    if (!vault_slot_key(config, offset, capacity, slot_key)) {
        fclose(out); fclose(in);
        return CRYPTO_ERR_CRYPTO;
    }
    unsigned char aad[16];
    store_coords(offset, capacity, aad);

    uint64_t full_frames = capacity / QSAFE_FRAME_SIZE;
    uint64_t rem = capacity % QSAFE_FRAME_SIZE;
    uint64_t nframes = full_frames + 1;

    unsigned char lenhdr[8];
    store_u64le(lenhdr, content_len);
    uint64_t lenhdr_left = 8, content_left = content_len;
    uint64_t pad_left = capacity - 8 - content_len;

    unsigned char *frame_pt = malloc(QSAFE_FRAME_SIZE);
    unsigned char *frame_ct = malloc(QSAFE_FRAME_SIZE);
    crypto_error_t ret = CRYPTO_SUCCESS;
    if (!frame_pt || !frame_ct) {
        ret = CRYPTO_ERR_MEMORY;
        goto cleanup;
    }

    for (uint64_t ctr = 0; ctr < nframes; ctr++) {
        int last = (ctr == nframes - 1);
        size_t want = last ? (size_t)rem : (size_t)QSAFE_FRAME_SIZE;
        size_t filled = 0;
        while (filled < want) {
            if (lenhdr_left > 0) {
                size_t take = lenhdr_left;
                if (take > want - filled) take = want - filled;
                memcpy(frame_pt + filled, lenhdr + (8 - lenhdr_left), take);
                lenhdr_left -= take;
                filled += take;
            } else if (content_left > 0) {
                size_t take = (content_left < (uint64_t)(want - filled)) ? (size_t)content_left : (want - filled);
                size_t got = fread(frame_pt + filled, 1, take, in);
                if (got != take) { ret = CRYPTO_ERR_FILE_IO; goto cleanup; }
                content_left -= got;
                filled += got;
            } else {
                size_t take = want - filled;
                if ((uint64_t)take > pad_left) take = (size_t)pad_left;
                if (take > 0 && RAND_bytes(frame_pt + filled, (int)take) != 1) {
                    ret = CRYPTO_ERR_CRYPTO; goto cleanup;
                }
                pad_left -= take;
                filled += take;
            }
        }

        unsigned char nonce[AES_GCM_NONCE_SIZE], tag[AES_GCM_TAG_SIZE];
        crypto_frame_nonce(ctr, last, nonce);
        const unsigned char *frame_aad = (ctr == 0) ? aad : NULL;
        size_t frame_aadlen = (ctr == 0) ? sizeof(aad) : 0;
        if (!crypto_gcm_seal_aad(slot_key, nonce, frame_aad, frame_aadlen, frame_pt, (int)filled, frame_ct, tag)) {
            ret = CRYPTO_ERR_CRYPTO; goto cleanup;
        }
        if ((filled > 0 && fwrite(frame_ct, 1, filled, out) != filled) ||
            fwrite(tag, 1, AES_GCM_TAG_SIZE, out) != AES_GCM_TAG_SIZE) {
            ret = CRYPTO_ERR_FILE_IO; goto cleanup;
        }
    }

    printf("Wrote %llu bytes into slot [%llu, %llu) of %s\n",
           (unsigned long long)content_len, (unsigned long long)offset,
           (unsigned long long)(offset + vault_ciphertext_len(capacity)), path);

cleanup:
    OPENSSL_cleanse(slot_key, sizeof(slot_key));
    free(frame_pt);
    free(frame_ct);
    fclose(out);
    fclose(in);
    return ret;
}

crypto_error_t vault_read(const char *path, uint64_t offset, uint64_t capacity,
                         const char *output_path, const crypto_config_t *config) {
    if (capacity < VAULT_MIN_CAPACITY || capacity > VAULT_MAX_CAPACITY) {
        fprintf(stderr, "Error: --capacity must be between %d and %llu bytes\n",
                VAULT_MIN_CAPACITY, (unsigned long long)VAULT_MAX_CAPACITY);
        return CRYPTO_ERR_INVALID_INPUT;
    }
    if (offset > VAULT_MAX_OFFSET) {
        fprintf(stderr, "Error: --offset must be at most %llu bytes\n", (unsigned long long)VAULT_MAX_OFFSET);
        return CRYPTO_ERR_INVALID_INPUT;
    }
    if (!config->passphrase) {
        fprintf(stderr, "Error: vault read requires a passphrase\n");
        return CRYPTO_ERR_INVALID_INPUT;
    }

    FILE *in = fopen(path, "rb");
    if (!in) { perror("Error opening container"); return CRYPTO_ERR_FILE_IO; }
    if (qsafe_fseek64(in, 0, SEEK_END) != 0) { fclose(in); return CRYPTO_ERR_FILE_IO; }
    long long container_size = qsafe_ftell64(in);
    uint64_t need = offset + vault_ciphertext_len(capacity);
    /* Deliberately the same message/status as an auth failure below — an
     * out-of-range slot must be indistinguishable from a wrong passphrase.
     * See HIDDEN_VOLUMES.md §3. */
    if (container_size < 0 || (uint64_t)container_size < need) {
        fprintf(stderr, "Error: no data at this location for this passphrase\n");
        fclose(in);
        return CRYPTO_ERR_INTEGRITY;
    }
    if (qsafe_fseek64(in, (long long)offset, SEEK_SET) != 0) { fclose(in); return CRYPTO_ERR_FILE_IO; }

    unsigned char slot_key[AES_KEY_SIZE];
    if (!vault_slot_key(config, offset, capacity, slot_key)) {
        fclose(in);
        return CRYPTO_ERR_CRYPTO;
    }
    unsigned char aad[16];
    store_coords(offset, capacity, aad);

    uint64_t full_frames = capacity / QSAFE_FRAME_SIZE;
    uint64_t rem = capacity % QSAFE_FRAME_SIZE;
    uint64_t nframes = full_frames + 1;

    unsigned char *cbuf = malloc(QSAFE_FRAME_SIZE);
    unsigned char *pbuf = malloc(QSAFE_FRAME_SIZE);
    crypto_error_t ret = CRYPTO_SUCCESS;
    FILE *out = NULL;
    int opened_out = 0;
    uint64_t content_len = 0, content_emitted = 0;
    int have_content_len = 0;

    if (!cbuf || !pbuf) { ret = CRYPTO_ERR_MEMORY; goto cleanup; }

    for (uint64_t ctr = 0; ctr < nframes; ctr++) {
        int last = (ctr == nframes - 1);
        size_t want = last ? (size_t)rem : (size_t)QSAFE_FRAME_SIZE;
        unsigned char tag[AES_GCM_TAG_SIZE];
        size_t got_ct = want ? fread(cbuf, 1, want, in) : 0;
        size_t got_tag = fread(tag, 1, AES_GCM_TAG_SIZE, in);
        if (got_ct != want || got_tag != AES_GCM_TAG_SIZE) {
            fprintf(stderr, "Error: no data at this location for this passphrase\n");
            ret = CRYPTO_ERR_INTEGRITY; goto cleanup;
        }

        unsigned char nonce[AES_GCM_NONCE_SIZE];
        crypto_frame_nonce(ctr, last, nonce);
        const unsigned char *frame_aad = (ctr == 0) ? aad : NULL;
        size_t frame_aadlen = (ctr == 0) ? sizeof(aad) : 0;
        if (!crypto_gcm_open_aad(slot_key, nonce, frame_aad, frame_aadlen, cbuf, (int)want, tag, pbuf)) {
            fprintf(stderr, "Error: no data at this location for this passphrase\n");
            ret = CRYPTO_ERR_INTEGRITY; goto cleanup;
        }

        size_t frame_off = 0;
        if (!have_content_len) {
            /* want >= VAULT_MIN_CAPACITY - 8 + 8 on frame 0 since capacity >=
             * VAULT_MIN_CAPACITY, so the 8-byte length prefix is always
             * fully inside this first frame. */
            content_len = load_u64le(pbuf);
            have_content_len = 1;
            if (content_len > capacity - 8) {
                fprintf(stderr, "Error: no data at this location for this passphrase\n");
                ret = CRYPTO_ERR_INTEGRITY; goto cleanup;
            }
            frame_off = 8;
            out = vault_open_output(output_path);
            if (!out) { ret = CRYPTO_ERR_FILE_IO; goto cleanup; }
            opened_out = 1;
        }

        uint64_t remaining_content = content_len - content_emitted;
        if (remaining_content > 0 && frame_off < want) {
            size_t avail = want - frame_off;
            size_t take = (remaining_content < (uint64_t)avail) ? (size_t)remaining_content : avail;
            if (take > 0 && fwrite(pbuf + frame_off, 1, take, out) != take) {
                ret = CRYPTO_ERR_FILE_IO; goto cleanup;
            }
            content_emitted += take;
        }
        /* Rest of the slot is random padding — no need to authenticate it
         * further than what we've already verified for this reader's own
         * purposes; stop as soon as the declared content is fully emitted. */
        if (content_emitted >= content_len) break;
    }

cleanup:
    OPENSSL_cleanse(slot_key, sizeof(slot_key));
    free(cbuf);
    free(pbuf);
    fclose(in);
    if (opened_out) vault_close_stream(out);
    if (ret == CRYPTO_SUCCESS && have_content_len) {
        fprintf(stderr, "Recovered %llu bytes\n", (unsigned long long)content_len);
    }
    if (ret != CRYPTO_SUCCESS && opened_out && strcmp(output_path, "-") != 0) {
        remove(output_path);
    }
    return ret;
}

/* ===================================================================== */
/* v2 volume layer: whole-container rewrite + commands                    */
/* (docs/HIDDEN_VOLUMES_V2.md §4-5)                                       */
/* ===================================================================== */

/* Fills buf with CSPRNG bytes in int-sized chunks (RAND_bytes takes an int
 * length, so a >2 GiB buffer must be chunked). Returns 1 on success. */
static int vault_fill_random(unsigned char *buf, uint64_t len) {
    uint64_t off = 0;
    while (off < len) {
        uint64_t chunk = len - off;
        if (chunk > (1u << 20)) chunk = (1u << 20);
        if (RAND_bytes(buf + off, (int)chunk) != 1) return 0;
        off += chunk;
    }
    return 1;
}

/* The scrypt cost a volume's anchor uses: config's override, else the fixed
 * VAULT_ANCHOR_LOG_N so a passphrase alone locates it. */
static void vault_anchor_cost(const crypto_config_t *base, uint64_t *n, uint32_t *r, uint32_t *p) {
    *n = base->scrypt_n ? base->scrypt_n : (1ULL << VAULT_ANCHOR_LOG_N);
    *r = base->scrypt_r ? base->scrypt_r : SCRYPT_DEFAULT_R;
    *p = base->scrypt_p ? base->scrypt_p : SCRYPT_DEFAULT_P;
}

/* Builds a config for deriving a slot/anchor key at cost n (r,p from base). */
static void vault_cost_config(crypto_config_t *cfg, const char *passphrase,
                              uint64_t n, uint32_t r, uint32_t p,
                              const unsigned char *keyfile_key, int argon2) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->passphrase = passphrase;
    cfg->scrypt_n = n;
    cfg->scrypt_r = r;
    cfg->scrypt_p = p;
    cfg->vault_keyfile_key = keyfile_key; /* so the keyfile gates slot keys, not just the anchor location */
    cfg->vault_kdf_argon2 = argon2;
}

static int vault_container_size(const char *path, uint64_t *size_out) {
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    if (qsafe_fseek64(f, 0, SEEK_END) != 0) { fclose(f); return 0; }
    long long s = qsafe_ftell64(f);
    fclose(f);
    if (s < 0) return 0;
    *size_out = (uint64_t)s;
    return 1;
}

/* Reads `len` bytes at `offset` from an open file into buf. Returns 1 on a
 * full read. */
static int vault_read_at(FILE *f, uint64_t offset, unsigned char *buf, uint64_t len) {
    if (qsafe_fseek64(f, (long long)offset, SEEK_SET) != 0) return 0;
    return fread(buf, 1, len, f) == len;
}

/* Opens a volume and its full directory, following the overflow chain from the
 * anchor (§3.1). *dir receives the data entries flattened across all blocks and
 * the overflow block offsets; *a_off is the anchor offset. Returns
 * CRYPTO_ERR_INTEGRITY (indistinguishable) if the anchor does not open/parse or
 * the chain is malformed. */
static crypto_error_t vault_open_volume(FILE *f, uint64_t size, const char *passphrase,
                                        const crypto_config_t *base, vault_dir_t *dir, uint64_t *a_off) {
    uint64_t an; uint32_t ar, ap;
    vault_anchor_cost(base, &an, &ar, &ap);
    if (vault_anchor_offset(passphrase, size, an, ar, ap, base->vault_kdf_argon2, base->vault_keyfile_key, a_off) != CRYPTO_SUCCESS)
        return CRYPTO_ERR_INTEGRITY;

    memset(dir, 0, sizeof(*dir));
    dir->version = VAULT_DIR_VERSION;

    uint64_t span = vault_slot_len(VAULT_ANCHOR_CAPACITY);
    unsigned char *slot = malloc(span);
    unsigned char *blockbuf = malloc(VAULT_ANCHOR_CAPACITY);
    vault_dir_t *blk = malloc(sizeof(*blk));
    crypto_config_t acfg;
    vault_cost_config(&acfg, passphrase, an, ar, ap, base->vault_keyfile_key, base->vault_kdf_argon2);
    crypto_error_t ret = CRYPTO_ERR_INTEGRITY;
    if (!slot || !blockbuf || !blk) { ret = CRYPTO_ERR_MEMORY; goto done; }

    uint64_t block_off = *a_off;
    for (int b = 0; b < VAULT_MAX_BLOCKS; b++) {
        if (block_off + span > size) { ret = CRYPTO_ERR_INTEGRITY; goto done; }
        if (!vault_read_at(f, block_off, slot, span) ||
            !vault_v2_open(slot, block_off, VAULT_ANCHOR_CAPACITY, &acfg, blockbuf) ||
            !vault_dir_parse(blockbuf, blk)) {
            ret = CRYPTO_ERR_INTEGRITY; goto done;
        }
        uint64_t next = 0;
        int have_next = 0;
        for (uint16_t i = 0; i < blk->entry_count; i++) {
            if (blk->entries[i].flags & VAULT_ENTRY_FLAG_OVERFLOW) {
                if (have_next) { ret = CRYPTO_ERR_INTEGRITY; goto done; } /* at most one per block */
                next = blk->entries[i].offset;
                have_next = 1;
            } else {
                if (dir->entry_count >= VAULT_MAX_VOL_ENTRIES) { ret = CRYPTO_ERR_INTEGRITY; goto done; }
                dir->entries[dir->entry_count++] = blk->entries[i];
            }
        }
        if (!have_next) { ret = CRYPTO_SUCCESS; goto done; }
        if (dir->noverflow >= VAULT_MAX_BLOCKS - 1) { ret = CRYPTO_ERR_INTEGRITY; goto done; }
        dir->overflow_off[dir->noverflow++] = next;
        block_off = next;
    }
    /* Ran out of blocks without a terminal (no-overflow) one. */
    ret = CRYPTO_ERR_INTEGRITY;

done:
    free(slot);
    free(blockbuf);
    free(blk);
    return ret;
}

/* Atomically replaces `path` with `size` bytes of `data` via a temp file in the
 * same directory + rename (POSIX-atomic; a remove+rename fallback covers
 * platforms whose rename won't clobber). */
static crypto_error_t vault_atomic_write(const char *path, const unsigned char *data, uint64_t size) {
    char tmp[PATH_MAX];
    if ((size_t)snprintf(tmp, sizeof(tmp), "%s.qsftmp", path) >= sizeof(tmp)) return CRYPTO_ERR_INVALID_INPUT;
    FILE *f = fopen(tmp, "wb");
    if (!f) { perror("Error creating temp container"); return CRYPTO_ERR_FILE_IO; }
    uint64_t off = 0;
    while (off < size) {
        uint64_t chunk = size - off;
        if (chunk > (1u << 20)) chunk = (1u << 20);
        if (fwrite(data + off, 1, chunk, f) != chunk) { fclose(f); remove(tmp); return CRYPTO_ERR_FILE_IO; }
        off += chunk;
    }
    if (fclose(f) != 0) { remove(tmp); return CRYPTO_ERR_FILE_IO; }
    if (rename(tmp, path) != 0) {
        if (remove(path) != 0 || rename(tmp, path) != 0) { remove(tmp); return CRYPTO_ERR_FILE_IO; }
    }
    return CRYPTO_SUCCESS;
}

/* Rewrite plan: for each volume to preserve/write, its passphrase, the final
 * directory to seal, and — for entries whose content is new (not yet in the old
 * container) — a plaintext blob to seal instead of reading the old slot.
 *
 * read_passphrase, when set, is used to *open* the old slots and anchor while
 * the (new) passphrase is used to *seal* them — that's what `vault passwd` needs
 * to re-key a volume in place. NULL means read and write under the same
 * passphrase (every other command). */
typedef struct {
    const char *passphrase;
    const char *read_passphrase;
    vault_dir_t dir;
    const unsigned char *new_blob[VAULT_MAX_VOL_ENTRIES]; /* NULL => read from old container */
} vault_plan_t;

typedef struct { uint64_t start, end; } vault_range_t;

/* True if any two of the n ranges overlap (O(n^2); n is tiny). */
static int vault_ranges_overlap(const vault_range_t *r, int n) {
    for (int i = 0; i < n; i++)
        for (int j = i + 1; j < n; j++)
            if (r[i].start < r[j].end && r[j].start < r[i].end) return 1;
    return 0;
}

/* Appends a volume's occupied ranges (its anchor slot, every overflow directory
 * block, and every data slot) to `out`, starting at *n, up to `cap`. Returns 1
 * on success, 0 if out of room. */
static int vault_collect_ranges(uint64_t a_off, const vault_dir_t *dir,
                                vault_range_t *out, int *n, int cap) {
    uint64_t aspan = vault_slot_len(VAULT_ANCHOR_CAPACITY);
    if (*n >= cap) return 0;
    out[*n].start = a_off;
    out[*n].end = a_off + aspan;
    (*n)++;
    for (int b = 0; b < dir->noverflow; b++) {
        if (*n >= cap) return 0;
        out[*n].start = dir->overflow_off[b];
        out[*n].end = dir->overflow_off[b] + aspan;
        (*n)++;
    }
    for (uint16_t i = 0; i < dir->entry_count; i++) {
        if (*n >= cap) return 0;
        out[*n].start = dir->entries[i].offset;
        out[*n].end = dir->entries[i].offset + vault_slot_len(dir->entries[i].capacity);
        (*n)++;
    }
    return 1;
}

static int cmp_range(const void *a, const void *b) {
    uint64_t sa = ((const vault_range_t *)a)->start, sb = ((const vault_range_t *)b)->start;
    return (sa > sb) - (sa < sb);
}

/* First-fit free-space placement: finds the lowest offset where a `need`-byte
 * slot fits in [0, size) without overlapping any of the n occupied ranges.
 * Placement location does not leak (every container byte is random-looking; a
 * slot is indistinguishable from filler), so first-fit is as safe as any other
 * policy and is deterministic. Only ranges from volumes whose passphrase the
 * caller holds are visible — a slot can still land on an unknown volume, the
 * same inherent limit as everything else here. Returns 1 with *off set, or 0. */
static int vault_find_free(vault_range_t *r, int n, uint64_t size, uint64_t need, uint64_t *off) {
    qsort(r, (size_t)n, sizeof(*r), cmp_range);
    uint64_t cursor = 0;
    for (int i = 0; i < n; i++) {
        if (r[i].start > cursor && r[i].start - cursor >= need) { *off = cursor; return 1; }
        if (r[i].end > cursor) cursor = r[i].end;
    }
    if (size > cursor && size - cursor >= need) { *off = cursor; return 1; }
    return 0;
}

/* Number of directory blocks needed to hold `count` data entries: one block
 * up to VAULT_MAX_ENTRIES (46), then VAULT_DATA_PER_INNER_BLOCK (45) more per
 * added block (a slot spent on the overflow pointer). */
static int vault_required_blocks(int count) {
    if (count <= VAULT_MAX_ENTRIES) return 1;
    return 1 + (count - VAULT_MAX_ENTRIES + VAULT_DATA_PER_INNER_BLOCK - 1) / VAULT_DATA_PER_INNER_BLOCK;
}

/* The whole-container rewrite (§4). Builds a fresh random image of `size`
 * bytes, seals every plan's directory chain and data slots into it (reading
 * preserved content from the old container, sealing new content from the plan),
 * verifies no two placed slots overlap, then atomically replaces the container. */
static crypto_error_t vault_rewrite(const char *container, uint64_t size,
                                    vault_plan_t *plans, int nplans, const crypto_config_t *base) {
    uint64_t an; uint32_t ar, ap;
    vault_anchor_cost(base, &an, &ar, &ap);

    unsigned char *img = malloc(size);
    if (!img) return CRYPTO_ERR_MEMORY;
    if (!vault_fill_random(img, size)) { free(img); return CRYPTO_ERR_CRYPTO; }

    int max_claims = nplans * (VAULT_MAX_VOL_ENTRIES + VAULT_MAX_BLOCKS);
    vault_range_t *claims = malloc((size_t)max_claims * sizeof(*claims));
    if (!claims) { free(img); return CRYPTO_ERR_MEMORY; }
    int nclaims = 0;

    FILE *old = fopen(container, "rb"); /* may be NULL when creating fresh */
    crypto_error_t ret = CRYPTO_SUCCESS;

    for (int v = 0; v < nplans && ret == CRYPTO_SUCCESS; v++) {
        vault_plan_t *P = &plans[v];
        uint64_t a_off;
        if (vault_anchor_offset(P->passphrase, size, an, ar, ap, base->vault_kdf_argon2, base->vault_keyfile_key, &a_off) != CRYPTO_SUCCESS) {
            ret = CRYPTO_ERR_INVALID_INPUT; break;
        }

        for (uint16_t i = 0; i < P->dir.entry_count && ret == CRYPTO_SUCCESS; i++) {
            vault_entry_t *e = &P->dir.entries[i];
            uint64_t slen = vault_slot_len(e->capacity);
            if (e->offset + slen > size) { ret = CRYPTO_ERR_INVALID_INPUT; break; }
            /* Read old slots under read_passphrase (for `passwd`), seal under
             * the new passphrase; identical when read_passphrase is NULL. */
            crypto_config_t rcfg, wcfg;
            const char *rpass = P->read_passphrase ? P->read_passphrase : P->passphrase;
            vault_cost_config(&rcfg, rpass, 1ULL << e->scrypt_log_n, ar, ap, base->vault_keyfile_key, base->vault_kdf_argon2);
            vault_cost_config(&wcfg, P->passphrase, 1ULL << e->scrypt_log_n, ar, ap, base->vault_keyfile_key, base->vault_kdf_argon2);

            unsigned char *blob = malloc(e->capacity);
            if (!blob) { ret = CRYPTO_ERR_MEMORY; break; }
            if (P->new_blob[i]) {
                memcpy(blob, P->new_blob[i], e->capacity);
            } else if (old) {
                unsigned char *sbuf = malloc(slen);
                if (!sbuf) { free(blob); ret = CRYPTO_ERR_MEMORY; break; }
                if (!vault_read_at(old, e->offset, sbuf, slen) ||
                    !vault_v2_open(sbuf, e->offset, e->capacity, &rcfg, blob)) {
                    /* Can't recover a slot we were told to preserve. */
                    free(sbuf); free(blob); ret = CRYPTO_ERR_INTEGRITY; break;
                }
                free(sbuf);
            } else {
                free(blob); ret = CRYPTO_ERR_INTEGRITY; break;
            }
            int ok = vault_v2_seal(img + e->offset, e->offset, e->capacity, &wcfg, blob);
            OPENSSL_cleanse(blob, e->capacity);
            free(blob);
            if (!ok) { ret = CRYPTO_ERR_CRYPTO; break; }
            claims[nclaims].start = e->offset;
            claims[nclaims].end = e->offset + slen;
            nclaims++;
        }
        if (ret != CRYPTO_SUCCESS) break;

        /* Seal the directory as a chain of blocks (§3.1): the anchor at a_off,
         * then overflow blocks at P->dir.overflow_off[]. Non-terminal blocks
         * hold VAULT_DATA_PER_INNER_BLOCK data entries plus one overflow-pointer
         * entry; the terminal block holds the remainder. */
        uint64_t aspan = vault_slot_len(VAULT_ANCHOR_CAPACITY);
        int nblocks = vault_required_blocks(P->dir.entry_count);
        if (nblocks - 1 > P->dir.noverflow) { ret = CRYPTO_ERR_INVALID_INPUT; break; }
        crypto_config_t acfg;
        vault_cost_config(&acfg, P->passphrase, an, ar, ap, base->vault_keyfile_key, base->vault_kdf_argon2);
        uint8_t anchor_log = (uint8_t)__builtin_ctzll(an);

        for (int b = 0; b < nblocks && ret == CRYPTO_SUCCESS; b++) {
            uint64_t boff = (b == 0) ? a_off : P->dir.overflow_off[b - 1];
            if (boff + aspan > size) { ret = CRYPTO_ERR_INVALID_INPUT; break; }
            vault_dir_t blk;
            memset(&blk, 0, sizeof(blk));
            blk.version = VAULT_DIR_VERSION;
            int start = VAULT_DATA_PER_INNER_BLOCK * b;
            int dcnt = (b < nblocks - 1) ? VAULT_DATA_PER_INNER_BLOCK
                                         : (P->dir.entry_count - VAULT_DATA_PER_INNER_BLOCK * b);
            for (int i = 0; i < dcnt; i++) {
                blk.entries[blk.entry_count] = P->dir.entries[start + i];
                blk.entries[blk.entry_count].flags &= (uint8_t)~VAULT_ENTRY_FLAG_OVERFLOW;
                blk.entry_count++;
            }
            if (b < nblocks - 1) { /* append the overflow pointer to the next block */
                vault_entry_t *ov = &blk.entries[blk.entry_count++];
                memset(ov, 0, sizeof(*ov));
                ov->offset = P->dir.overflow_off[b];
                ov->capacity = VAULT_ANCHOR_CAPACITY;
                ov->scrypt_log_n = anchor_log;
                ov->flags = VAULT_ENTRY_FLAG_OVERFLOW;
            }
            unsigned char dirblk[VAULT_ANCHOR_CAPACITY];
            if (!vault_dir_serialize(&blk, dirblk) ||
                !vault_v2_seal(img + boff, boff, VAULT_ANCHOR_CAPACITY, &acfg, dirblk)) {
                ret = CRYPTO_ERR_CRYPTO; break;
            }
            claims[nclaims].start = boff;
            claims[nclaims].end = boff + aspan;
            nclaims++;
        }
    }

    if (old) fclose(old);

    if (ret == CRYPTO_SUCCESS && vault_ranges_overlap(claims, nclaims)) {
        fprintf(stderr, "Error: slot/anchor placement collision — nothing written\n");
        ret = CRYPTO_ERR_INVALID_INPUT;
    }
    if (ret == CRYPTO_SUCCESS) ret = vault_atomic_write(container, img, size);

    OPENSSL_cleanse(img, size);
    free(img);
    free(claims);
    return ret;
}

/* Builds a data slot's plaintext blob: u64le(content_len) ‖ content ‖ random
 * padding, totalling `capacity` bytes. Returns 1 on success. */
static int vault_make_data_blob(const unsigned char *content, uint64_t content_len,
                                uint64_t capacity, unsigned char *blob) {
    if (content_len > capacity - 8) return 0;
    store_u64le(blob, content_len);
    memcpy(blob + 8, content, content_len);
    uint64_t pad = capacity - 8 - content_len;
    if (pad > 0 && !vault_fill_random(blob + 8 + content_len, pad)) return 0;
    return 1;
}

/* Reads an entire regular file into a malloc'd buffer. Caller frees *out. */
static int vault_read_file(const char *path, unsigned char **out, uint64_t *len_out) {
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    if (qsafe_fseek64(f, 0, SEEK_END) != 0) { fclose(f); return 0; }
    long long s = qsafe_ftell64(f);
    if (s < 0 || qsafe_fseek64(f, 0, SEEK_SET) != 0) { fclose(f); return 0; }
    unsigned char *buf = malloc((size_t)s + 1);
    if (!buf) { fclose(f); return 0; }
    size_t got = (s > 0) ? fread(buf, 1, (size_t)s, f) : 0;
    fclose(f);
    if (got != (size_t)s) { free(buf); return 0; }
    *out = buf;
    *len_out = (uint64_t)s;
    return 1;
}

crypto_error_t vault_keyfile_from_file(const char *path, unsigned char out[32]) {
    unsigned char *data = NULL;
    uint64_t len = 0;
    if (!vault_read_file(path, &data, &len)) return CRYPTO_ERR_FILE_IO;
    const char *ctx = "qsafe-vault-keyfile-v1";
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    unsigned int dlen = 0;
    int ok = c &&
             EVP_DigestInit_ex(c, EVP_sha256(), NULL) == 1 &&
             EVP_DigestUpdate(c, ctx, strlen(ctx)) == 1 &&
             EVP_DigestUpdate(c, data, (size_t)len) == 1 &&
             EVP_DigestFinal_ex(c, out, &dlen) == 1 && dlen == 32;
    if (c) EVP_MD_CTX_free(c);
    OPENSSL_cleanse(data, (size_t)len);
    free(data);
    return ok ? CRYPTO_SUCCESS : CRYPTO_ERR_CRYPTO;
}

crypto_error_t vault_volume_create(const char *container, uint64_t size,
                                   const crypto_config_t *config, int force,
                                   const char *const *keep_passphrases, int n_keep) {
    if (!config->passphrase) { fprintf(stderr, "Error: vault create requires a passphrase\n"); return CRYPTO_ERR_INVALID_INPUT; }

    uint64_t container_size;
    if (size > 0) {
        if (size < vault_slot_len(VAULT_ANCHOR_CAPACITY)) {
            fprintf(stderr, "Error: --size must be at least %llu bytes to hold an anchor\n",
                    (unsigned long long)vault_slot_len(VAULT_ANCHOR_CAPACITY));
            return CRYPTO_ERR_INVALID_INPUT;
        }
        if (!force) {
            FILE *probe = fopen(container, "rb");
            if (probe) { fclose(probe); fprintf(stderr, "Error: '%s' already exists (use --force)\n", container); return CRYPTO_ERR_INVALID_INPUT; }
        }
        container_size = size;
        if (n_keep > 0) { fprintf(stderr, "Error: --keep is only for adding a volume to an existing container (omit --size)\n"); return CRYPTO_ERR_INVALID_INPUT; }
    } else {
        if (!vault_container_size(container, &container_size)) {
            fprintf(stderr, "Error: cannot read existing container '%s' (use --size to create one)\n", container);
            return CRYPTO_ERR_FILE_IO;
        }
    }

    int nplans = 1 + n_keep;
    vault_plan_t *plans = calloc((size_t)nplans, sizeof(*plans));
    if (!plans) return CRYPTO_ERR_MEMORY;
    crypto_error_t ret = CRYPTO_SUCCESS;

    /* Target: a new empty volume. */
    plans[0].passphrase = config->passphrase;
    plans[0].dir.version = VAULT_DIR_VERSION;
    plans[0].dir.entry_count = 0;

    /* Keeps: load their existing directories to preserve them. */
    FILE *old = (size == 0) ? fopen(container, "rb") : NULL;
    for (int k = 0; k < n_keep && ret == CRYPTO_SUCCESS; k++) {
        uint64_t a_off;
        if (!old || vault_open_volume(old, container_size, keep_passphrases[k], config,
                                      &plans[1 + k].dir, &a_off) != CRYPTO_SUCCESS) {
            fprintf(stderr, "Error: cannot open a --keep volume (wrong passphrase?)\n");
            ret = CRYPTO_ERR_INTEGRITY;
        } else {
            plans[1 + k].passphrase = keep_passphrases[k];
        }
    }
    if (old) fclose(old);

    if (ret == CRYPTO_SUCCESS)
        ret = vault_rewrite(container, container_size, plans, nplans, config);
    if (ret == CRYPTO_SUCCESS)
        printf("Volume created in %s (%llu bytes)\n", container, (unsigned long long)container_size);
    free(plans);
    return ret;
}

crypto_error_t vault_volume_ls(const char *container, const crypto_config_t *config) {
    if (!config->passphrase) { fprintf(stderr, "Error: vault ls requires a passphrase\n"); return CRYPTO_ERR_INVALID_INPUT; }
    uint64_t size;
    if (!vault_container_size(container, &size)) { fprintf(stderr, "Error: cannot read container\n"); return CRYPTO_ERR_FILE_IO; }
    FILE *f = fopen(container, "rb");
    if (!f) { fprintf(stderr, "Error: cannot open container\n"); return CRYPTO_ERR_FILE_IO; }
    vault_dir_t dir; uint64_t a_off;
    crypto_error_t ret = vault_open_volume(f, size, config->passphrase, config, &dir, &a_off);
    fclose(f);
    if (ret != CRYPTO_SUCCESS) { fprintf(stderr, "Error: no volume here for this passphrase\n"); return CRYPTO_ERR_INTEGRITY; }

    printf("Volume (%u %s):\n", dir.entry_count, dir.entry_count == 1 ? "entry" : "entries");
    for (uint16_t i = 0; i < dir.entry_count; i++) {
        vault_entry_t *e = &dir.entries[i];
        char name[VAULT_MAX_NAME_LEN + 1];
        memcpy(name, e->name, e->name_len);
        name[e->name_len] = '\0';
        printf("  %-24s offset=%-12llu capacity=%-10llu cost=2^%u\n",
               name, (unsigned long long)e->offset, (unsigned long long)e->capacity, e->scrypt_log_n);
    }
    return CRYPTO_SUCCESS;
}

crypto_error_t vault_volume_extract(const char *container, const char *name,
                                    const char *outfile, const crypto_config_t *config) {
    if (!config->passphrase) { fprintf(stderr, "Error: vault extract requires a passphrase\n"); return CRYPTO_ERR_INVALID_INPUT; }
    uint64_t size;
    if (!vault_container_size(container, &size)) { fprintf(stderr, "Error: cannot read container\n"); return CRYPTO_ERR_FILE_IO; }
    FILE *f = fopen(container, "rb");
    if (!f) { fprintf(stderr, "Error: cannot open container\n"); return CRYPTO_ERR_FILE_IO; }
    vault_dir_t dir; uint64_t a_off;
    crypto_error_t ret = vault_open_volume(f, size, config->passphrase, config, &dir, &a_off);
    if (ret != CRYPTO_SUCCESS) { fclose(f); fprintf(stderr, "Error: no volume here for this passphrase\n"); return CRYPTO_ERR_INTEGRITY; }

    int idx = vault_dir_find(&dir, name);
    if (idx < 0) { fclose(f); fprintf(stderr, "Error: no entry named '%s'\n", name); return CRYPTO_ERR_INVALID_INPUT; }
    vault_entry_t *e = &dir.entries[idx];

    uint64_t slen = vault_slot_len(e->capacity);
    unsigned char *slot = malloc(slen);
    unsigned char *blob = malloc(e->capacity);
    ret = CRYPTO_ERR_INTEGRITY;
    if (slot && blob && vault_read_at(f, e->offset, slot, slen)) {
        crypto_config_t scfg;
        vault_cost_config(&scfg, config->passphrase, 1ULL << e->scrypt_log_n,
                          config->scrypt_r ? config->scrypt_r : SCRYPT_DEFAULT_R,
                          config->scrypt_p ? config->scrypt_p : SCRYPT_DEFAULT_P,
                          config->vault_keyfile_key, config->vault_kdf_argon2);
        if (vault_v2_open(slot, e->offset, e->capacity, &scfg, blob)) {
            uint64_t content_len = load_u64le(blob);
            if (content_len <= e->capacity - 8) {
                FILE *out = (strcmp(outfile, "-") == 0) ? stdout : fopen(outfile, "wb");
                if (out) {
                    if (content_len == 0 || fwrite(blob + 8, 1, content_len, out) == content_len) ret = CRYPTO_SUCCESS;
                    if (out != stdout) fclose(out);
                    if (ret == CRYPTO_SUCCESS) fprintf(stderr, "Extracted %llu bytes\n", (unsigned long long)content_len);
                }
            }
        }
    }
    fclose(f);
    if (slot) { free(slot); }
    if (blob) { OPENSSL_cleanse(blob, e->capacity); free(blob); }
    if (ret != CRYPTO_SUCCESS) fprintf(stderr, "Error: could not extract '%s'\n", name);
    return ret;
}

/* Shared body for add/rm: load the target volume, mutate its directory, load
 * any keep volumes, and rewrite. `add_blob` (when non-NULL) is the content for
 * a freshly-added last entry. */
static crypto_error_t vault_mutate(const char *container, const crypto_config_t *config,
                                   const char *const *keep_passphrases, int n_keep,
                                   vault_dir_t *target_dir,
                                   const unsigned char *add_blob) {
    uint64_t size;
    if (!vault_container_size(container, &size)) { fprintf(stderr, "Error: cannot read container\n"); return CRYPTO_ERR_FILE_IO; }

    int nplans = 1 + n_keep;
    vault_plan_t *plans = calloc((size_t)nplans, sizeof(*plans));
    if (!plans) return CRYPTO_ERR_MEMORY;
    crypto_error_t ret = CRYPTO_SUCCESS;

    plans[0].passphrase = config->passphrase;
    plans[0].dir = *target_dir;
    if (add_blob) plans[0].new_blob[target_dir->entry_count - 1] = add_blob;

    FILE *old = fopen(container, "rb");
    for (int k = 0; k < n_keep && ret == CRYPTO_SUCCESS; k++) {
        uint64_t a_off;
        if (!old || vault_open_volume(old, size, keep_passphrases[k], config,
                                      &plans[1 + k].dir, &a_off) != CRYPTO_SUCCESS) {
            fprintf(stderr, "Error: cannot open a --keep volume (wrong passphrase?)\n");
            ret = CRYPTO_ERR_INTEGRITY;
        } else {
            plans[1 + k].passphrase = keep_passphrases[k];
        }
    }
    if (old) fclose(old);

    if (ret == CRYPTO_SUCCESS) ret = vault_rewrite(container, size, plans, nplans, config);
    free(plans);
    return ret;
}

crypto_error_t vault_volume_add(const char *container, const char *name, const char *infile,
                                uint64_t offset, int have_offset,
                                uint64_t capacity, int have_capacity, const crypto_config_t *config,
                                const char *const *keep_passphrases, int n_keep) {
    if (!config->passphrase) { fprintf(stderr, "Error: vault add requires a passphrase\n"); return CRYPTO_ERR_INVALID_INPUT; }
    if (have_capacity && (capacity < VAULT_MIN_CAPACITY || capacity > VAULT_MAX_CAPACITY)) { fprintf(stderr, "Error: --capacity out of range\n"); return CRYPTO_ERR_INVALID_INPUT; }
    if (have_offset && offset > VAULT_MAX_OFFSET) { fprintf(stderr, "Error: --offset out of range\n"); return CRYPTO_ERR_INVALID_INPUT; }
    if (strlen(name) > VAULT_MAX_NAME_LEN) { fprintf(stderr, "Error: name too long (max %d)\n", VAULT_MAX_NAME_LEN); return CRYPTO_ERR_INVALID_INPUT; }

    uint64_t size;
    if (!vault_container_size(container, &size)) { fprintf(stderr, "Error: cannot read container\n"); return CRYPTO_ERR_FILE_IO; }
    FILE *f = fopen(container, "rb");
    if (!f) return CRYPTO_ERR_FILE_IO;
    vault_dir_t dir; uint64_t a_off;
    crypto_error_t ret = vault_open_volume(f, size, config->passphrase, config, &dir, &a_off);
    fclose(f);
    if (ret != CRYPTO_SUCCESS) { fprintf(stderr, "Error: no volume here for this passphrase\n"); return CRYPTO_ERR_INTEGRITY; }
    if (vault_dir_find(&dir, name) >= 0) { fprintf(stderr, "Error: an entry named '%s' already exists\n", name); return CRYPTO_ERR_INVALID_INPUT; }

    unsigned char *content = NULL; uint64_t content_len = 0;
    if (!vault_read_file(infile, &content, &content_len)) { fprintf(stderr, "Error: cannot read '%s'\n", infile); return CRYPTO_ERR_FILE_IO; }

    /* Default capacity: an exact fit for the content plus its 8-byte length
     * prefix (bounded below by the minimum). */
    if (!have_capacity) {
        capacity = content_len + 8;
        if (capacity < VAULT_MIN_CAPACITY) capacity = VAULT_MIN_CAPACITY;
        if (capacity > VAULT_MAX_CAPACITY) { free(content); fprintf(stderr, "Error: input too large for a slot\n"); return CRYPTO_ERR_INVALID_INPUT; }
    }
    if (content_len > capacity - 8) {
        fprintf(stderr, "Error: '%s' is %llu bytes; slot capacity holds at most %llu\n",
                infile, (unsigned long long)content_len, (unsigned long long)(capacity - 8));
        free(content); return CRYPTO_ERR_INVALID_INPUT;
    }

    /* Collect the occupied ranges of every volume we can see (this volume's
     * anchor, overflow blocks and data slots, plus each --keep volume's). Used
     * to auto-place the new data slot and any new overflow directory block. */
    int rcap = (1 + n_keep) * (VAULT_MAX_VOL_ENTRIES + VAULT_MAX_BLOCKS) + VAULT_MAX_BLOCKS + 1;
    vault_range_t *ranges = malloc((size_t)rcap * sizeof(*ranges));
    if (!ranges) { free(content); return CRYPTO_ERR_MEMORY; }
    int nr = 0;
    vault_collect_ranges(a_off, &dir, ranges, &nr, rcap);
    {
        FILE *kf = fopen(container, "rb");
        for (int k = 0; k < n_keep && kf; k++) {
            vault_dir_t kd; uint64_t ka;
            if (vault_open_volume(kf, size, keep_passphrases[k], config, &kd, &ka) != CRYPTO_SUCCESS) {
                fclose(kf); free(ranges); free(content);
                fprintf(stderr, "Error: cannot open a --keep volume for placement (wrong passphrase?)\n");
                return CRYPTO_ERR_INTEGRITY;
            }
            vault_collect_ranges(ka, &kd, ranges, &nr, rcap);
        }
        if (kf) fclose(kf);
    }

    if (!have_offset && !vault_find_free(ranges, nr, size, vault_slot_len(capacity), &offset)) {
        free(ranges); free(content);
        fprintf(stderr, "Error: no free space for a %llu-byte slot in the visible volumes\n",
                (unsigned long long)vault_slot_len(capacity));
        return CRYPTO_ERR_INVALID_INPUT;
    }
    /* Reserve the data slot so a new overflow block won't be placed on top of it. */
    ranges[nr].start = offset; ranges[nr].end = offset + vault_slot_len(capacity); nr++;

    unsigned char *blob = malloc(capacity);
    if (!blob || !vault_make_data_blob(content, content_len, capacity, blob)) {
        free(ranges); free(content); free(blob); return CRYPTO_ERR_CRYPTO;
    }
    free(content);

    uint32_t log_n = config->scrypt_n ? (uint32_t)__builtin_ctzll(config->scrypt_n) : VAULT_DEFAULT_LOG_N;
    vault_entry_t e;
    memset(&e, 0, sizeof(e));
    e.offset = offset; e.capacity = capacity; e.scrypt_log_n = (uint8_t)log_n; e.flags = 0;
    e.name_len = (uint16_t)strlen(name);
    memcpy(e.name, name, e.name_len);
    if (!vault_dir_add(&dir, &e)) {
        free(ranges); OPENSSL_cleanse(blob, capacity); free(blob);
        fprintf(stderr, "Error: volume is full (max %d slots)\n", VAULT_MAX_VOL_ENTRIES);
        return CRYPTO_ERR_INVALID_INPUT;
    }

    /* If the volume now spans another directory block, auto-place it too. */
    int need = vault_required_blocks(dir.entry_count);
    while (dir.noverflow < need - 1) {
        uint64_t boff;
        if (!vault_find_free(ranges, nr, size, vault_slot_len(VAULT_ANCHOR_CAPACITY), &boff)) {
            free(ranges); OPENSSL_cleanse(blob, capacity); free(blob);
            fprintf(stderr, "Error: no room for an overflow directory block\n");
            return CRYPTO_ERR_INVALID_INPUT;
        }
        ranges[nr].start = boff; ranges[nr].end = boff + vault_slot_len(VAULT_ANCHOR_CAPACITY); nr++;
        dir.overflow_off[dir.noverflow++] = boff;
    }
    free(ranges);

    ret = vault_mutate(container, config, keep_passphrases, n_keep, &dir, blob);
    OPENSSL_cleanse(blob, capacity);
    free(blob);
    if (ret == CRYPTO_SUCCESS)
        printf("Added '%s' (%llu bytes) at offset %llu\n", name, (unsigned long long)content_len, (unsigned long long)offset);
    return ret;
}

crypto_error_t vault_volume_rm(const char *container, const char *name,
                               const crypto_config_t *config,
                               const char *const *keep_passphrases, int n_keep) {
    if (!config->passphrase) { fprintf(stderr, "Error: vault rm requires a passphrase\n"); return CRYPTO_ERR_INVALID_INPUT; }
    uint64_t size;
    if (!vault_container_size(container, &size)) { fprintf(stderr, "Error: cannot read container\n"); return CRYPTO_ERR_FILE_IO; }
    FILE *f = fopen(container, "rb");
    if (!f) return CRYPTO_ERR_FILE_IO;
    vault_dir_t dir; uint64_t a_off;
    crypto_error_t ret = vault_open_volume(f, size, config->passphrase, config, &dir, &a_off);
    fclose(f);
    if (ret != CRYPTO_SUCCESS) { fprintf(stderr, "Error: no volume here for this passphrase\n"); return CRYPTO_ERR_INTEGRITY; }
    if (!vault_dir_remove(&dir, name)) { fprintf(stderr, "Error: no entry named '%s'\n", name); return CRYPTO_ERR_INVALID_INPUT; }

    ret = vault_mutate(container, config, keep_passphrases, n_keep, &dir, NULL);
    if (ret == CRYPTO_SUCCESS) printf("Removed '%s'\n", name);
    return ret;
}

crypto_error_t vault_volume_passwd(const char *container, const crypto_config_t *config,
                                   const char *new_passphrase,
                                   const char *const *keep_passphrases, int n_keep) {
    if (!config->passphrase || !new_passphrase) {
        fprintf(stderr, "Error: vault passwd needs the current and a new passphrase\n");
        return CRYPTO_ERR_INVALID_INPUT;
    }
    uint64_t size;
    if (!vault_container_size(container, &size)) { fprintf(stderr, "Error: cannot read container\n"); return CRYPTO_ERR_FILE_IO; }

    FILE *f = fopen(container, "rb");
    if (!f) return CRYPTO_ERR_FILE_IO;
    vault_dir_t dir; uint64_t a_off;
    crypto_error_t ret = vault_open_volume(f, size, config->passphrase, config, &dir, &a_off);
    fclose(f);
    if (ret != CRYPTO_SUCCESS) { fprintf(stderr, "Error: no volume here for this passphrase\n"); return CRYPTO_ERR_INTEGRITY; }

    int nplans = 1 + n_keep;
    vault_plan_t *plans = calloc((size_t)nplans, sizeof(*plans));
    if (!plans) return CRYPTO_ERR_MEMORY;

    /* Target: re-key in place — read old slots/anchor under the current
     * passphrase, re-seal them (and place the anchor anew) under the new one.
     * The old anchor's location just becomes fresh filler. */
    plans[0].passphrase = new_passphrase;
    plans[0].read_passphrase = config->passphrase;
    plans[0].dir = dir;

    FILE *old = fopen(container, "rb");
    for (int k = 0; k < n_keep && ret == CRYPTO_SUCCESS; k++) {
        uint64_t ka;
        if (!old || vault_open_volume(old, size, keep_passphrases[k], config,
                                      &plans[1 + k].dir, &ka) != CRYPTO_SUCCESS) {
            fprintf(stderr, "Error: cannot open a --keep volume (wrong passphrase?)\n");
            ret = CRYPTO_ERR_INTEGRITY;
        } else {
            plans[1 + k].passphrase = keep_passphrases[k];
        }
    }
    if (old) fclose(old);

    if (ret == CRYPTO_SUCCESS) ret = vault_rewrite(container, size, plans, nplans, config);
    free(plans);
    if (ret == CRYPTO_SUCCESS) printf("Passphrase changed for the volume in %s\n", container);
    return ret;
}
