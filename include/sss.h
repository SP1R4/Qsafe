#ifndef QSAFE_SSS_H
#define QSAFE_SSS_H

/* Shamir secret sharing over GF(256) for secret-key recovery.
 *
 * `qsafe split-key` splits the *unwrapped* secret blob into n shares such that
 * any t of them reconstruct it — and t-1 reveal nothing (information-
 * theoretically). Shares are an offline recovery path for a lost passphrase or
 * keychain: each share file must be protected like a fragment of the key.
 *
 * Share file layout ("QSAFES01", little-endian):
 *   offset  size  field
 *   0       8     magic = "QSAFES01"
 *   8       16    set_id      (random per split; shares only combine within a set)
 *   24      1     index       (x coordinate, 1..255)
 *   25      1     threshold t (2..16)
 *   26      4     data_len    (u32, length of the shared secret)
 *   30      32    digest      (SHA-256 of the original secret, to verify joins)
 *   62      var   share bytes (data_len bytes, y_i per secret byte)
 */

#include <stddef.h>
#include <stdint.h>

#define SSS_MAGIC "QSAFES01"
#define SSS_MAGIC_SIZE 8
#define SSS_SET_ID_SIZE 16
#define SSS_HEADER_SIZE (SSS_MAGIC_SIZE + SSS_SET_ID_SIZE + 1 + 1 + 4 + 32) /* 62 */
#define SSS_MIN_THRESHOLD 2
#define SSS_MAX_THRESHOLD 16
#define SSS_MAX_SHARES 255

typedef enum {
    SSS_OK = 0,
    SSS_ERR_INPUT = 1,    /* bad parameters or malformed share file */
    SSS_ERR_IO = 2,
    SSS_ERR_MEMORY = 3,
    SSS_ERR_CRYPTO = 4,   /* RNG failure */
    SSS_ERR_MISMATCH = 5  /* shares from different sets, or digest mismatch */
} sss_status;

/* Splits secret into n share files "<prefix>.share<i>" (i = 1..n), any t of
 * which reconstruct it. */
sss_status sss_split_to_files(const unsigned char *secret, size_t secret_len,
                              unsigned int t, unsigned int n, const char *prefix);

/* Joins share files back into the secret. On success *out is malloc'd (caller
 * cleanses+frees) and *out_len set. Fails closed on any inconsistency. */
sss_status sss_join_files(const char *const *paths, size_t n_paths,
                          unsigned char **out, size_t *out_len);

const char *sss_strerror(sss_status s);

#endif /* QSAFE_SSS_H */
