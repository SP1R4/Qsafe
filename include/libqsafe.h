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

#ifdef __cplusplus
}
#endif

#endif /* LIBQSAFE_H */
