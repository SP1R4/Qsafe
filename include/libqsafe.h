#ifndef LIBQSAFE_H
#define LIBQSAFE_H

/* libqsafe — a stable C API around the Qsafe engine, so Qsafe can be embedded
 * rather than shelled out to. All functions operate on file paths (the engine
 * is streaming and file-oriented); language bindings layer byte-buffer helpers
 * on top (see python/qsafe.py). Thread-compatible: no global state beyond what
 * OpenSSL/liboqs keep. */

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    QSAFE_OK = 0,
    QSAFE_ERR_IO = 1,       /* file open/read/write failed */
    QSAFE_ERR_MEMORY = 2,
    QSAFE_ERR_CRYPTO = 3,   /* a primitive failed unexpectedly */
    QSAFE_ERR_INPUT = 4,    /* bad argument / malformed file */
    QSAFE_ERR_AUTH = 5      /* authentication / signature verification failed */
} qsafe_status;

/* Library version string, e.g. "7.0.0". */
const char *qsafe_version(void);

/* Human-readable message for a status code. */
const char *qsafe_strerror(qsafe_status status);

/* Generate a hybrid X25519 + ML-KEM-1024 identity. Writes a passphrase-wrapped
 * secret key to secret_path and the public key to public_path (overwriting). */
qsafe_status qsafe_keygen(const char *secret_path, const char *public_path,
                          const char *passphrase);

/* Encrypt in_path to out_path for one or more recipients (paths to public-key
 * files). Encryption needs no passphrase. */
qsafe_status qsafe_encrypt(const char *in_path, const char *out_path,
                           const char *const *recipient_public_paths,
                           size_t n_recipients);

/* Decrypt in_path to out_path using a passphrase-wrapped secret key. */
qsafe_status qsafe_decrypt(const char *in_path, const char *out_path,
                           const char *secret_path, const char *passphrase);

/* Authenticate in_path without writing plaintext (returns QSAFE_OK if intact). */
qsafe_status qsafe_verify(const char *in_path, const char *secret_path,
                          const char *passphrase);

/* --- detached signatures (ML-DSA-87) --- */

/* Generate an ML-DSA-87 signing keypair (secret passphrase-wrapped). */
qsafe_status qsafe_sign_keygen(const char *secret_path, const char *public_path,
                               const char *passphrase);

/* Sign in_path, writing a detached signature to sig_path. */
qsafe_status qsafe_sign(const char *in_path, const char *sig_path,
                        const char *sign_secret_path, const char *passphrase);

/* Verify a detached signature (returns QSAFE_OK only if valid). */
qsafe_status qsafe_verify_signature(const char *in_path, const char *sig_path,
                                    const char *sign_public_path);

/* --- vault v2: deniable passphrase-addressed volumes (experimental) ---
 *
 * A thin embedding surface over the `vault create/add/extract/rm` commands (see
 * docs/HIDDEN_VOLUMES_V2.md). Each call is a whole-container rewrite for the
 * mutating operations. `scrypt_log_n` sets the KDF cost as log2(N) in [14, 22];
 * pass 0 for the (higher) vault default. These wrap the single-volume,
 * no-keyfile case — multi-volume `--keep` and `--keyfile` are CLI-only for now.
 * Progress text may be written to stdout/stderr. */

/* Create a container of `size` bytes holding one empty volume under passphrase
 * (overwrites any existing file at container_path). */
qsafe_status qsafe_vault_create(const char *container_path, const char *passphrase,
                                unsigned long long size, unsigned scrypt_log_n);

/* Add in_path as an auto-placed, exact-fit named slot in the volume. */
qsafe_status qsafe_vault_add(const char *container_path, const char *passphrase,
                             const char *name, const char *in_path, unsigned scrypt_log_n);

/* Recover a named slot to out_path. */
qsafe_status qsafe_vault_extract(const char *container_path, const char *passphrase,
                                 const char *name, const char *out_path, unsigned scrypt_log_n);

/* Remove a named slot. */
qsafe_status qsafe_vault_remove(const char *container_path, const char *passphrase,
                                const char *name, unsigned scrypt_log_n);

#ifdef __cplusplus
}
#endif

#endif /* LIBQSAFE_H */
