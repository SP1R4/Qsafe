#ifndef QSAFE_PQXDH_H
#define QSAFE_PQXDH_H

/* PQXDH handshake — post-quantum Extended Diffie-Hellman session establishment,
 * per veil/docs/SPEC.md §2. Produces the shared secret SK that seeds the Double
 * Ratchet (include/ratchet.h), so a captured session is protected against
 * harvest-now-decrypt-later.
 *
 * Clean PQXDH: four X25519 DH legs bind the identity/prekeys, and an independent
 * ML-KEM-1024 leg (liboqs OQS_KEM_encaps/decaps) provides the PQ secret; the five
 * secrets are concatenated and fed once to HKDF-SHA256. Bundle prekeys are
 * ML-DSA-87 signed and MUST verify before use (fail closed).
 *
 * These calls return a ready ratchet_session_t; the initiator additionally emits
 * the initial message the responder needs. All secret-bearing structs must be
 * released with pqxdh_identity_free(), which zeroises. */

#include <stddef.h>
#include "crypto_utils.h"   /* QSAFE_SIG_* sizes, X25519_KEY_SIZE, AES_KEY_SIZE */
#include "ratchet.h"        /* ratchet_session_t */

/* ML-KEM-1024 sizes (FIPS 203); asserted against liboqs at runtime. */
#define PQXDH_MLKEM_PUB 1568
#define PQXDH_MLKEM_SEC 3168
#define PQXDH_MLKEM_CT  1568

#define PQXDH_LABEL_SK  "Veil-PQXDH-v1"   /* final HKDF info */
#define PQXDH_LABEL_SPK "Veil-SPK-v1"     /* signed-prekey signature context */
#define PQXDH_LABEL_PQK "Veil-PQK-v1"     /* KEM-prekey signature context */
#define PQXDH_LABEL_OPK "Veil-OPK-v1"     /* one-time-prekey signature context */

/* One-time prekeys generated per identity. Each is used at most once (the relay
 * hands out a distinct one per fetch; the receiver tracks consumption), which is
 * what gives replay resistance and full pre-first-ratchet forward secrecy. */
#define PQXDH_OPK_POOL 64

/* A party's long-term identity and prekeys (secret side). Holds ML-DSA identity,
 * X25519 identity + signed prekey, ML-KEM prekey, and a pool of one-time prekeys
 * each with a random 4-byte id (stable for the identity's life; survives at-rest
 * serialization, so the consumed-set never collides across restarts). */
typedef struct {
    unsigned char ik_sig_pk[QSAFE_SIG_PUB_SIZE];
    unsigned char ik_sig_sk[QSAFE_SIG_SEC_SIZE];
    unsigned char ik_dh_pk[X25519_KEY_SIZE], ik_dh_sk[X25519_KEY_SIZE];
    unsigned char spk_pk[X25519_KEY_SIZE],   spk_sk[X25519_KEY_SIZE];
    unsigned char pqk_pk[PQXDH_MLKEM_PUB],   pqk_sk[PQXDH_MLKEM_SEC];
    uint32_t      opk_id[PQXDH_OPK_POOL];
    unsigned char opk_pk[PQXDH_OPK_POOL][X25519_KEY_SIZE];
    unsigned char opk_sk[PQXDH_OPK_POOL][X25519_KEY_SIZE];
    uint32_t      n_opk;
} pqxdh_identity_t;

/* The single-OPK bundle an initiator consumes: base prekeys plus (at most) one
 * one-time prekey the relay handed out. Prekeys carry ML-DSA signatures under the
 * identity signing key. */
typedef struct {
    unsigned char ik_sig_pk[QSAFE_SIG_PUB_SIZE];
    unsigned char ik_dh_pk[X25519_KEY_SIZE];
    unsigned char spk_pk[X25519_KEY_SIZE];
    unsigned char spk_sig[QSAFE_SIG_MAX_SIZE]; size_t spk_sig_len;
    unsigned char pqk_pk[PQXDH_MLKEM_PUB];
    unsigned char pqk_sig[QSAFE_SIG_MAX_SIZE]; size_t pqk_sig_len;
    int           have_opk;
    uint32_t      opk_id;
    unsigned char opk_pk[X25519_KEY_SIZE];
    unsigned char opk_sig[QSAFE_SIG_MAX_SIZE]; size_t opk_sig_len;
} pqxdh_bundle_t;

/* The initiator's opening message. `opk_id` names the one-time prekey used, or is
 * -1 when the peer's pool was empty. `sig` is an ML-DSA-87 signature by ik_sig
 * over the other fields (SPEC §2.5). */
typedef struct {
    unsigned char ik_sig_pk[QSAFE_SIG_PUB_SIZE];
    unsigned char ik_dh_pk[X25519_KEY_SIZE];
    unsigned char ek_pk[X25519_KEY_SIZE];
    unsigned char pq_ct[PQXDH_MLKEM_CT];
    int64_t       opk_id;   /* >=0 = OPK id used; -1 = none */
    int           pq;       /* 1 = use the continuous PQ ratchet; signed, so a MITM can't downgrade */
    unsigned char sig[QSAFE_SIG_MAX_SIZE]; size_t sig_len;
} pqxdh_initial_t;

/* Generate a fresh identity + prekeys and self-sign the signed/KEM prekeys. */
crypto_error_t pqxdh_identity_generate(pqxdh_identity_t *id);

/* Zeroise all secret key material. Safe on NULL. */
void pqxdh_identity_free(pqxdh_identity_t *id);

/* Encrypt/decrypt the identity (including its secret keys) at rest under a
 * passphrase (Argon2id + AES-256-GCM via crypto_seal_at_rest). serialize mallocs
 * *blob (caller frees); deserialize returns CRYPTO_ERR_INTEGRITY on a wrong
 * passphrase or tampered blob. */
crypto_error_t pqxdh_identity_serialize(const pqxdh_identity_t *id, const char *passphrase,
                                        unsigned char **blob, size_t *blob_len);
crypto_error_t pqxdh_identity_deserialize(const unsigned char *blob, size_t blob_len,
                                          const char *passphrase, pqxdh_identity_t *out);

/* Build the base prekey bundle to publish (identity, signed prekey, KEM prekey;
 * have_opk=0). One-time prekeys are published separately via pqxdh_opk_public and
 * handed out one at a time by the relay. */
crypto_error_t pqxdh_publish_bundle(const pqxdh_identity_t *id, pqxdh_bundle_t *out);

/* Fill in one signed one-time-prekey entry (index < id->n_opk): its id, public
 * key, and an ML-DSA signature over (LABEL_OPK || id || pk). Used to publish the
 * pool. */
crypto_error_t pqxdh_opk_public(const pqxdh_identity_t *id, uint32_t index,
                                uint32_t *opk_id, unsigned char opk_pk[X25519_KEY_SIZE],
                                unsigned char *opk_sig, size_t *opk_sig_len);

/* Initiator: verify `peer`'s prekey signatures (fail closed), run PQXDH, and
 * return a ready session plus the opening message to send. */
crypto_error_t pqxdh_initiator(const pqxdh_identity_t *self, const pqxdh_bundle_t *peer,
                               int pq, pqxdh_initial_t *msg_out, ratchet_session_t **session_out);

/* Responder: reproduce PQXDH from the initiator's opening message using own
 * prekeys, and return a ready session. Returns CRYPTO_ERR_INTEGRITY if the PQ
 * decapsulation or leg reconstruction is inconsistent. */
crypto_error_t pqxdh_responder(const pqxdh_identity_t *self, const pqxdh_initial_t *msg,
                               ratchet_session_t **session_out);

#endif /* QSAFE_PQXDH_H */
