#ifndef QSAFE_AGE_H
#define QSAFE_AGE_H

/* Interoperability with the age encryption format (https://age-encryption.org),
 * v1, X25519 recipients only. Lets Qsafe read and write files that the `age`
 * tool (and other v1 implementations) can decrypt, and vice versa.
 *
 * Note: age is a *classical* X25519 format — it carries no post-quantum
 * protection. This is an ecosystem-compatibility feature, not a PQ one. */

#include <stddef.h>

typedef enum {
    AGE_OK = 0,
    AGE_ERR_IO = 1,
    AGE_ERR_FORMAT = 2,   /* malformed age file or key */
    AGE_ERR_CRYPTO = 3,   /* MAC/AEAD failure, or no matching recipient */
    AGE_ERR_INPUT = 4
} age_status;

/* Generate an X25519 age keypair. Writes the Bech32 public key ("age1…") into
 * pub and the secret key ("AGE-SECRET-KEY-1…") into sec (both NUL-terminated). */
age_status age_keygen(char *pub, size_t pub_sz, char *sec, size_t sec_sz);

/* Encrypt in_path -> out_path for one or more "age1…" recipients. */
age_status age_encrypt_file(const char *in_path, const char *out_path,
                            const char *const *recipients, size_t n_recipients);

/* Decrypt an age file in_path -> out_path using an "AGE-SECRET-KEY-1…" string. */
age_status age_decrypt_file(const char *in_path, const char *out_path,
                            const char *identity);

const char *age_strerror(age_status s);

#endif /* QSAFE_AGE_H */
