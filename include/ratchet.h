#ifndef QSAFE_RATCHET_H
#define QSAFE_RATCHET_H

/* Double Ratchet session layer over qsafe's crypto primitives.
 *
 * qsafe's file mode is encrypt-to-a-long-term-key and has no forward secrecy
 * (see THREAT_MODEL.md). This module adds the stateful ratchet that a messaging
 * transport needs: forward secrecy and post-compromise security. The wire
 * protocol built on top of it lives in a separate project (veil); see that
 * project's docs/SPEC.md for the full construction. This header is the contract.
 *
 * We reuse the public Signal Double Ratchet structure and swap in qsafe's
 * primitives (HKDF-SHA256, AES-256-GCM with AAD, X25519, ML-KEM-1024). We do NOT
 * invent a new key schedule. Nothing here is trusted until the test vectors and
 * the crypto-review pass (SPEC.md §8).
 *
 * Lifecycle contract: every ratchet_session_t MUST be closed with
 * ratchet_session_free(), which zeroises all key material. Message keys are
 * zeroised immediately after use inside encrypt/decrypt — that is what makes the
 * forward secrecy real, so callers never see a raw message key. */

#include <stddef.h>
#include <stdint.h>
#include "crypto_utils.h"   /* crypto_error_t, AES/X25519 size constants, OQS_KEM */

/* Bound on out-of-order / dropped messages we retain keys for. Receiving a
 * message that would require skipping more than this many keys fails closed
 * rather than letting a peer force unbounded key derivation (DoS guard). */
#define RATCHET_MAX_SKIP 1000

/* Domain-separation labels for the key schedule (SPEC.md §3). Centralised here
 * so the vectors and the review pin exact bytes. */
#define RATCHET_LABEL_PQXDH   "Veil-PQXDH-v1"
#define RATCHET_LABEL_RK      "Veil-RK-v1"
#define RATCHET_LABEL_CK_NEXT "Veil-CK-next"
#define RATCHET_LABEL_CK_MSG  "Veil-CK-msg"

/* Wire header, authenticated as AAD on every ratchet message (SPEC.md §3.1):
 *   ver(1) | type(1) | dh_pub(32) | PN(4,BE) | N(4,BE)  = 42 bytes.
 * type 0x02 = classical message, 0x03 = PQ-ratchet message. */
#define RATCHET_HDR_SIZE (1 + 1 + X25519_KEY_SIZE + 4 + 4)

/* Continuous PQ ratchet (veil/docs/PQ_RATCHET.md): an ML-KEM-1024 shared secret is
 * mixed into KDF_RK at each DH ratchet step, so root-key advances are PQ-protected.
 * A PQ message header additionally carries our current ML-KEM encapsulation key and
 * a ciphertext to the peer's advertised key. Sizes are FIPS 203 ML-KEM-1024. */
#define RATCHET_MLKEM_PK 1568
#define RATCHET_MLKEM_SK 3168
#define RATCHET_MLKEM_CT 1568
#define RATCHET_MLKEM_SS AES_KEY_SIZE   /* 32 */
/* PQ-full header appends: kem_pk(1568) | have_ct(1) | kem_ct(1568). The have_ct
 * flag (authenticated as AAD) says whether kem_ct is a real ciphertext or bootstrap
 * padding. */
#define RATCHET_PQ_HDR_SIZE (RATCHET_HDR_SIZE + RATCHET_MLKEM_PK + 1 + RATCHET_MLKEM_CT)

/* Periodic PQ ratchet (veil/docs/PQ_RATCHET_PERIODIC.md): a PQ sender re-rotates
 * its ML-KEM secret every RATCHET_KEM_EVERY ratchet steps and carries the ~3.1 KB
 * of KEM material only on those "full" (type 0x03) messages; the others are "lite"
 * (type 0x04, classical-size header) and reuse the last KEM secret. K=1 reproduces
 * the per-step ratchet. Post-compromise security heals within K steps. */
#define RATCHET_KEM_EVERY 8

/* Header type bytes (hdr[1]). */
#define RATCHET_TYPE_CLASSICAL 0x02
#define RATCHET_TYPE_PQ_FULL   0x03
#define RATCHET_TYPE_PQ_LITE   0x04

/* Actual on-wire header size for a message, from its type byte (hdr[1]). A caller
 * that received or produced a header uses this to locate the ciphertext; a PQ
 * session's header size varies per message (full vs lite). */
static inline size_t ratchet_hdr_size_of(const unsigned char *hdr) {
    return (hdr[1] == RATCHET_TYPE_PQ_FULL) ? RATCHET_PQ_HDR_SIZE : RATCHET_HDR_SIZE;
}

/* Opaque session state. Holds root key, sending/receiving chain keys, the
 * current DH ratchet keypair and peer ratchet pubkey, message counters, and the
 * bounded skipped-message-key store. Definition is private to ratchet.c so the
 * layout can change without breaking callers; always heap-allocate via the
 * init functions and release via ratchet_session_free(). */
typedef struct ratchet_session ratchet_session_t;

/* --- Session establishment (after the PQXDH handshake, SPEC.md §2) --- */

/* Initiator side. `sk` is the 32-byte shared secret from PQXDH. `peer_dh_pub` is
 * the responder's initial ratchet public key (their signed prekey). Generates
 * the initiator's first ratchet keypair and primes the sending chain. On success
 * *out is a heap session the caller must free. */
crypto_error_t ratchet_init_initiator(const unsigned char sk[AES_KEY_SIZE],
                                      const unsigned char peer_dh_pub[X25519_KEY_SIZE],
                                      ratchet_session_t **out);

/* Responder side. `sk` is the same PQXDH shared secret. `self_dh` is the
 * responder's initial ratchet keypair (the signed prekey it published), whose
 * public half the initiator already used. The first inbound message performs the
 * initial DH ratchet step. On success *out is a heap session the caller frees. */
crypto_error_t ratchet_init_responder(const unsigned char sk[AES_KEY_SIZE],
                                       const unsigned char self_dh_pub[X25519_KEY_SIZE],
                                       const unsigned char self_dh_sec[X25519_KEY_SIZE],
                                       ratchet_session_t **out);

/* --- PQ ratchet establishment (veil/docs/PQ_RATCHET.md) ---
 * Same as the classical inits but PQ-enabled: also generate an ML-KEM ratchet
 * keypair; the peer's ML-KEM key is learned from the first inbound message
 * (bootstrap), so no extra handshake input is needed. Messages then carry ~3.1 KB
 * of ML-KEM material and every ratchet step mixes an ML-KEM secret into the root. */
crypto_error_t ratchet_pq_init_initiator(const unsigned char sk[AES_KEY_SIZE],
                                         const unsigned char peer_dh_pub[X25519_KEY_SIZE],
                                         ratchet_session_t **out);
crypto_error_t ratchet_pq_init_responder(const unsigned char sk[AES_KEY_SIZE],
                                          const unsigned char self_dh_pub[X25519_KEY_SIZE],
                                          const unsigned char self_dh_sec[X25519_KEY_SIZE],
                                          ratchet_session_t **out);

/* Header size for a session (classical RATCHET_HDR_SIZE or PQ RATCHET_PQ_HDR_SIZE).
 * Callers size header buffers and locate the ciphertext (after the header) by it. */
size_t ratchet_hdr_size(const ratchet_session_t *s);

/* --- Messaging --- */

/* Encrypt one message. Writes the header (ratchet_hdr_size(s) bytes — classical or
 * PQ) into `hdr` and the AES-256-GCM ciphertext+tag into `out` (room for
 * pt_len + AES_GCM_TAG_SIZE). `hdr` must have room for ratchet_hdr_size(s) bytes.
 * Steps the sending chain and zeroises the derived message key. The whole header
 * is fed to the AEAD as AAD, so any tampering with it fails the open. */
crypto_error_t ratchet_encrypt(ratchet_session_t *s,
                               const unsigned char *pt, size_t pt_len,
                               unsigned char *hdr,
                               unsigned char *out, size_t *out_len);

/* Decrypt one message given its header and ciphertext+tag. Performs a DH ratchet
 * step if the header carries a new peer ratchet key, derives (and stores, up to
 * RATCHET_MAX_SKIP) any skipped message keys, opens the AEAD with the header as
 * AAD, and zeroises the message key. Returns CRYPTO_ERR_INTEGRITY on a bad tag,
 * tampered header, or replay; CRYPTO_ERR_INVALID_INPUT if the gap exceeds
 * RATCHET_MAX_SKIP. On success writes pt_len plaintext into `out` (room for
 * ct_len - AES_GCM_TAG_SIZE). */
/* CONTRACT: `hdr` MUST point to at least ratchet_hdr_size(s) readable bytes — the
 * function reads the whole header (classical or PQ) as AAD. A network caller must
 * bound-check the received frame has that many header bytes BEFORE calling, or it
 * risks an out-of-bounds read. (veil's recv loop already gates on the header size
 * for classical sessions; PQ wiring must use ratchet_hdr_size likewise.) */
crypto_error_t ratchet_decrypt(ratchet_session_t *s,
                               const unsigned char *hdr,
                               const unsigned char *ct, size_t ct_len,
                               unsigned char *out, size_t *out_len);

/* --- State at rest (SPEC.md §7) --- */

/* Serialise the full session state to a malloc'd buffer, encrypted under an
 * Argon2id key derived from `passphrase` (never plaintext on disk). Caller owns
 * and must free *blob. */
crypto_error_t ratchet_session_serialize(const ratchet_session_t *s,
                                         const char *passphrase,
                                         unsigned char **blob, size_t *blob_len);

/* Inverse of ratchet_session_serialize. Returns CRYPTO_ERR_INTEGRITY on a wrong
 * passphrase or tampered blob. */
crypto_error_t ratchet_session_deserialize(const unsigned char *blob, size_t blob_len,
                                           const char *passphrase,
                                           ratchet_session_t **out);

/* Zeroise all key material and free. Safe on NULL. */
void ratchet_session_free(ratchet_session_t *s);

#endif /* QSAFE_RATCHET_H */
