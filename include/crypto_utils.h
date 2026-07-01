#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <stddef.h>
#include <stdint.h>
#include <oqs/oqs.h>

#define AES_KEY_SIZE 32
#define AES_GCM_NONCE_SIZE 12
#define AES_GCM_TAG_SIZE 16
#define AES_BLOCK_SIZE 16
#define KDF_SALT_SIZE 16
#define BUFFER_SIZE 4096
#define MAX_PATH_LENGTH 1024
#define DEFAULT_SECRET_KEY_FILE "secret_key.bin"
#define PUBLIC_KEY_SUFFIX ".pub"

/* On-disk magic for Qsafe v5 files.
 *
 * v5 changes versus v4:
 *   - Hybrid key establishment: every identity carries BOTH an X25519 keypair
 *     and an ML-KEM-1024 keypair. A file is protected only if an attacker breaks
 *     *both* the classical and the post-quantum layer.
 *   - Multi-recipient: the payload is encrypted under a random content key (CEK)
 *     that is independently wrapped to each recipient, so one ciphertext can be
 *     opened by any one of several secret keys.
 *   - The metadata block (original name, mode, mtime) is still prepended to the
 *     plaintext, and decryption still streams (tag held back from the tail).
 *
 * v5 is intentionally incompatible with older QSAFE004/003 files. */
#define VERSION_HEADER "QSAFE005"
#define VERSION_HEADER_SIZE 8

/* v6 (QSAFE006) is a framed-AEAD format: the payload is a sequence of
 * independently authenticated frames, each verified before its plaintext is
 * released, giving constant-memory streaming AND verify-before-release (no need
 * to buffer the whole payload). encrypt always writes v6; decrypt reads both v5
 * and v6. The v6 header drops the single payload nonce (frames use per-frame
 * counter nonces):  magic(8) | recipient_count(1) | record[0..R-1].
 *
 * Each frame on the wire is: ciphertext(plaintext_len) | tag(16). Non-final
 * frames carry exactly QSAFE_FRAME_SIZE plaintext; the single final frame
 * carries 0..QSAFE_FRAME_SIZE-1 (so the final frame is always strictly shorter
 * on the wire, which is how the reader detects it without a length prefix). */
#define VERSION_HEADER_V6 "QSAFE006"
#define QSAFE_FRAME_SIZE 65536

/* v7 (QSAFE007) keeps the v6 header and framing but extends the encrypted
 * metadata block (§META v7) with a content length and a padding length, which
 * enables two optional, individually-flagged features:
 *   - embedded sender authentication: an ML-DSA-87 public key + signature over
 *     (header ‖ META ‖ contents) travels INSIDE the encrypted payload as a
 *     fixed-size trailer, so decrypt can verify who encrypted the file without
 *     a separate detached signature — and the signer identity stays hidden
 *     from anyone who cannot decrypt;
 *   - Padmé size-hiding padding: random bytes appended after the trailer so
 *     the ciphertext length only reveals a bucketed size, not the exact one.
 * encrypt always writes v7; decrypt reads v7, v6 and v5. */
#define VERSION_HEADER_V7 "QSAFE007"

/* ML-DSA-87 sizes (FIPS 204); asserted against liboqs at runtime. */
#define QSAFE_SIG_PUB_SIZE 2592
#define QSAFE_SIG_MAX_SIZE 4627

/* Signed-sender trailer: signer_pub(2592) | u16 sig_len | signature zero-padded
 * to QSAFE_SIG_MAX_SIZE. Fixed size so a streaming reader can hold it back. */
#define QSAFE_TRAILER_SIZE (QSAFE_SIG_PUB_SIZE + 2 + QSAFE_SIG_MAX_SIZE) /* 7221 */

/* Domain-separation prefix hashed before (header ‖ META ‖ contents) for the
 * embedded signature, so it can never be confused with a detached signature. */
#define QSAFE_SIGNED_CONTEXT "qsafe-v7-signed"

/* content_len value meaning "unknown" (stdin input). */
#define QSAFE_LEN_UNKNOWN UINT64_MAX

/* X25519 raw key size and the random content-encryption key wrapped per
 * recipient. A v5 recipient record is, in order:
 *   ephemeral_x25519_pub(32) | kem_ciphertext | wrap_nonce(12) |
 *   wrapped_cek(32) | wrap_tag(16)
 * (kem_ciphertext length is the runtime OQS_KEM ciphertext size.) */
#define X25519_KEY_SIZE 32
#define QSAFE_CEK_SIZE 32
#define QSAFE_MAX_RECIPIENTS 16

/* Fixed-size metadata block prepended to the plaintext before encryption.
 * Layout (little-endian, total QSAFE_META_SIZE bytes):
 *   u8   flags        (bit 0: metadata present)
 *   u8   reserved
 *   u16  name_len     (<= QSAFE_MAX_NAME)
 *   u8   name[256]    (name_len valid bytes; remainder zero)
 *   u32  mode         (st_mode & 0777)
 *   u64  mtime        (seconds since epoch) */
#define QSAFE_MAX_NAME 255
#define QSAFE_META_NAME_FIELD 256
#define QSAFE_META_SIZE (1 + 1 + 2 + QSAFE_META_NAME_FIELD + 4 + 8) /* 272 */

/* v7 metadata block appends, after the v5/v6 fields:
 *   u64 content_len  (bytes of file contents; QSAFE_LEN_UNKNOWN for streams)
 *   u64 pad_len      (bytes of random padding appended at the very end)
 * Total 288 bytes. The flags byte gains bit 1 (signed trailer present) and
 * bit 2 (padding present). */
#define QSAFE_META_SIZE_V7 (QSAFE_META_SIZE + 8 + 8) /* 288 */

#define QSAFE_META_FLAG_PRESENT 0x01
#define QSAFE_META_FLAG_SIGNED  0x02
#define QSAFE_META_FLAG_PADDED  0x04

/* Secret-key file format.
 *
 * Legacy (v4.0) layout had no header:  nonce | salt | ciphertext | tag, with
 * fixed scrypt cost N=2^15, r=8, p=1. To make the KDF cost configurable and
 * self-describing we prepend an authenticated header identified by this magic:
 *
 *   "QSAFEK01" | u64 N | u32 r | u32 p | nonce(12) | salt(16) | ciphertext | tag(16)
 *
 * The magic + parameters are fed to AES-GCM as additional data, so altering the
 * advertised cost is detected. Files without the magic are read as legacy. */
#define KEYFILE_MAGIC "QSAFEK01"
#define KEYFILE_MAGIC_SIZE 8

/* Default scrypt cost: N=2^15 (~32 MiB), r=8, p=1 — matches legacy v4 keys. */
#define SCRYPT_DEFAULT_LOG_N 15
#define SCRYPT_DEFAULT_R 8
#define SCRYPT_DEFAULT_P 1

typedef enum {
    CRYPTO_SUCCESS = 0,
    CRYPTO_ERR_FILE_IO = 1,
    CRYPTO_ERR_MEMORY = 2,
    CRYPTO_ERR_CRYPTO = 3,
    CRYPTO_ERR_INVALID_INPUT = 4,
    CRYPTO_ERR_INTEGRITY = 5
} crypto_error_t;

typedef struct {
    int verbose;
    int force_overwrite;
    int check_only;            /* decrypt: authenticate only, never write plaintext */
    int armor;                 /* encrypt: emit base64 text; decrypt: expect base64 text */
    uint64_t scrypt_n;         /* scrypt cost N (power of two) used when writing keys */
    uint32_t scrypt_r;
    uint32_t scrypt_p;
    const char *secret_key_file;
    const char *public_key_file;
    const char *passphrase;
    int use_keychain;          /* derive/store the key passphrase in the OS keychain */

    /* v7 signed-sender mode. encrypt: when sign_sk_file is set, embed an
     * ML-DSA-87 signature (signer public key read from sign_pk_file) in the
     * payload. decrypt: when signer_pk_file is set, additionally require the
     * embedded signer key to equal its contents. */
    const char *sign_sk_file;
    const char *sign_pk_file;
    const char *signer_pk_file;
    int pad;                   /* encrypt: append Padmé size-hiding padding */
} crypto_config_t;

void crypto_handle_errors(void);
void crypto_print_progress_bar(size_t current, size_t total);

/* Writes a lowercase hex SHA-256 fingerprint of (data,len) into out (needs >= 65
 * bytes). Used to give public keys a short human-verifiable identity. */
crypto_error_t crypto_fingerprint(const unsigned char *data, size_t len, char *out, size_t outsz);

/* Base64 "armor": wrap a binary file in PEM-style text, and the reverse. Both
 * accept "-" for stdin/stdout. dearmor buffers no more than one line at a time. */
crypto_error_t crypto_armor(const char *in_path, const char *out_path);
crypto_error_t crypto_dearmor(const char *in_path, const char *out_path);

/* Prints, on stdout, what can be learned about a file without the secret key:
 * key files report their type + fingerprint; QSAFE files report version and the
 * encrypted payload size. Never decrypts. */
crypto_error_t crypto_inspect_file(const char *filename, OQS_KEM *kem, const crypto_config_t *config);

/* HKDF-SHA256: derive a 32-byte AES key from a high-entropy KEM shared secret. */
crypto_error_t crypto_derive_aes_key(const unsigned char *shared_secret, size_t secret_len, unsigned char *aes_key);

/* scrypt: derive a 32-byte key-wrapping key from a user passphrase + random salt.
 * Unlike HKDF this is deliberately slow/memory-hard to resist passphrase guessing. */
crypto_error_t crypto_derive_key_from_passphrase(const char *passphrase, const unsigned char *salt,
                                                 uint64_t n, uint32_t r, uint32_t p, unsigned char *out_key);

crypto_error_t crypto_save_secret_key(const char *filename, const unsigned char *secret_key, size_t length, const crypto_config_t *config);
unsigned char *crypto_load_secret_key(const char *filename, size_t *length, const crypto_config_t *config);

/* Public keys are stored in the clear (raw bytes); no passphrase is involved. */
crypto_error_t crypto_save_public_key(const char *filename, const unsigned char *public_key, size_t length, const crypto_config_t *config);
unsigned char *crypto_load_public_key(const char *filename, size_t expected_length, const crypto_config_t *config);

/* Generates a hybrid identity. Returns malloc'd public and secret blobs:
 *   public_blob = x25519_pub(32) || mlkem_pub
 *   secret_blob = x25519_sec(32) || mlkem_sec
 * The caller owns both and must cleanse+free the secret blob. */
crypto_error_t crypto_generate_identity(OQS_KEM *kem,
                                        unsigned char **public_blob, size_t *public_len,
                                        unsigned char **secret_blob, size_t *secret_len);

/* Hybrid (X25519 + ML-KEM) wrap/unwrap of an arbitrary small key into a
 * recipient record: e_pk(32) | kem_ct | nonce(12) | wrapped_key(key_len) |
 * tag(16). `label` is the HKDF info string (domain separation per consuming
 * format — the QSAFE container uses "qsafe-v5-hybrid-kek"). Exposed for the
 * age plugin, which wraps age's 16-byte file key with a distinct label. */
crypto_error_t crypto_hybrid_wrap(OQS_KEM *kem, const unsigned char *recipient_pub,
                                  const char *label, const unsigned char *key,
                                  size_t key_len, unsigned char *rec);
int crypto_hybrid_unwrap(OQS_KEM *kem, const unsigned char *secret_blob,
                         const char *label, const unsigned char *rec,
                         size_t key_len, unsigned char *key_out);

/* Encrypts to one or more recipients. recipient_pubs is an array of n_recipients
 * public blobs, each X25519_KEY_SIZE + kem->length_public_key bytes. */
crypto_error_t crypto_encrypt_file(const char *input_filename, const char *output_filename, OQS_KEM *kem,
                                   const unsigned char *const *recipient_pubs, size_t n_recipients,
                                   const crypto_config_t *config);

/* Decrypts using a hybrid secret blob (x25519_sec || mlkem_sec). */
crypto_error_t crypto_decrypt_file(const char *input_filename, const char *output_filename, OQS_KEM *kem,
                                   const unsigned char *secret_blob, const crypto_config_t *config);

crypto_error_t crypto_process_directory(const char *dir_path, const char *output_dir, const char *operation,
                                        OQS_KEM *kem, const unsigned char *const *recipient_pubs,
                                        size_t n_recipients, const unsigned char *secret_blob,
                                        const crypto_config_t *config);

/* --- Detached signatures (ML-DSA-87 / Dilithium Level 5) --- */

/* Generates an ML-DSA signing keypair; secret key is passphrase-wrapped. */
crypto_error_t crypto_sig_keygen(const char *sk_file, const char *pk_file, const crypto_config_t *config);

/* Signs input_filename, writing a detached signature (raw ML-DSA signature
 * bytes) to sig_file. Uses the passphrase-wrapped signing secret key. */
crypto_error_t crypto_sign_file(const char *input_filename, const char *sig_file,
                                const char *sig_sk_file, const crypto_config_t *config);

/* Verifies a detached signature against input_filename using sig_pk_file.
 * Returns CRYPTO_SUCCESS only if the signature is valid. */
crypto_error_t crypto_verify_signature(const char *input_filename, const char *sig_file,
                                       const char *sig_pk_file, const crypto_config_t *config);

#endif
