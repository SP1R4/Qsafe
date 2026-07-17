#ifndef QSAFE_GROUP_H
#define QSAFE_GROUP_H

/* Sender-key group ratchet — the group-messaging layer for veil
 * (veil/docs/GROUP_MESSAGING.md). Each member has a sender key: a symmetric hash-
 * ratchet chain plus an ML-DSA signature keypair. Outgoing messages advance the
 * chain and are AES-256-GCM encrypted under a per-message key and signed; other
 * members hold a receiving chain per sender (installed from a distribution message
 * carried over the pairwise PQXDH channel) and verify the signature before
 * decrypting. The signature is what stops one member forging another's messages,
 * since all members share the chain key. */

#include <stddef.h>
#include <stdint.h>
#include "crypto_utils.h"   /* crypto_error_t, QSAFE_SIG_* sizes, AES_KEY_SIZE, AES_GCM_TAG_SIZE */

#define GROUP_KEY_SIZE  AES_KEY_SIZE
#define GROUP_MAX_SKIP  1000

/* Sender-key distribution message: chain key || u32 index || ML-DSA public key. Sent
 * once to each other member over the (confidential, PQ) pairwise channel. */
#define GROUP_SKDM_SIZE (GROUP_KEY_SIZE + 4 + QSAFE_SIG_PUB_SIZE)

/* Per-message wire overhead: index(4) | u16 siglen | sig | GCM tag. Callers size the
 * ciphertext buffer as GROUP_OVERHEAD + plaintext_len. */
#define GROUP_OVERHEAD  (4 + 2 + QSAFE_SIG_MAX_SIZE + AES_GCM_TAG_SIZE)

/* A member's own sending key. Holds secret material; zeroise with group_sender_free. */
typedef struct {
    unsigned char ck[GROUP_KEY_SIZE];
    uint32_t      index;
    unsigned char sig_pk[QSAFE_SIG_PUB_SIZE];
    unsigned char sig_sk[QSAFE_SIG_SEC_SIZE];
} group_sender_t;

typedef struct { uint32_t index; unsigned char mk[GROUP_KEY_SIZE]; } group_skipped_t;

/* A receiving chain for one other member. */
typedef struct {
    unsigned char   ck[GROUP_KEY_SIZE];
    uint32_t        index;
    unsigned char   sig_pk[QSAFE_SIG_PUB_SIZE];
    group_skipped_t skipped[GROUP_MAX_SKIP];
    uint32_t        n_skipped;
} group_receiver_t;

/* Create a fresh sender key (random chain key + ML-DSA keypair). */
crypto_error_t group_sender_init(group_sender_t *out);

/* Write this sender's distribution message (its current chain state + public key). */
void group_sender_distribution(const group_sender_t *s, unsigned char out[GROUP_SKDM_SIZE]);

/* Initialise a receiving chain from a sender's distribution message. */
crypto_error_t group_receiver_init(group_receiver_t *out, const unsigned char skdm[GROUP_SKDM_SIZE]);

/* Encrypt one group message. `out` needs GROUP_OVERHEAD + pt_len bytes; the produced
 * frame (index | siglen | sig | ct+tag) length is written to *out_len. Advances the
 * sending chain and zeroises the message key. */
crypto_error_t group_encrypt(group_sender_t *s, const unsigned char *pt, size_t pt_len,
                             unsigned char *out, size_t *out_len);

/* Decrypt a group frame on `r` (the sender's receiving chain): verify the ML-DSA
 * signature, derive/skip to the message index, open the AEAD. State changes commit
 * only after the tag authenticates. Returns CRYPTO_ERR_INTEGRITY on a bad signature,
 * tag, or replay; CRYPTO_ERR_INVALID_INPUT if the gap exceeds GROUP_MAX_SKIP. */
crypto_error_t group_decrypt(group_receiver_t *r, const unsigned char *in, size_t in_len,
                             unsigned char *pt, size_t *pt_len);

/* State at rest: seal/open sender and receiver chains under a passphrase (Argon2id +
 * the key-committing AES-GCM envelope). *blob is malloc'd; the caller frees it.
 * deserialize returns CRYPTO_ERR_INTEGRITY on a wrong passphrase or tampered blob. */
crypto_error_t group_sender_serialize(const group_sender_t *s, const char *passphrase,
                                      unsigned char **blob, size_t *blob_len);
crypto_error_t group_sender_deserialize(const unsigned char *blob, size_t blob_len,
                                        const char *passphrase, group_sender_t *out);
crypto_error_t group_receiver_serialize(const group_receiver_t *r, const char *passphrase,
                                        unsigned char **blob, size_t *blob_len);
crypto_error_t group_receiver_deserialize(const unsigned char *blob, size_t blob_len,
                                          const char *passphrase, group_receiver_t *out);

/* Zeroise secret material. Safe on NULL. */
void group_sender_free(group_sender_t *s);
void group_receiver_free(group_receiver_t *r);

#endif /* QSAFE_GROUP_H */
