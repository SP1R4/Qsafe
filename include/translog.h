#ifndef QSAFE_TRANSLOG_H
#define QSAFE_TRANSLOG_H

/* Transparency log over the RFC 6962 Merkle tree (merkle.h) — the second layer of
 * veil's key transparency (veil/docs/KEY_TRANSPARENCY.md). Provides:
 *   - a Signed Tree Head (STH): the log operator's ML-DSA commitment to (size, root),
 *   - an append-only operator-side log that serves inclusion/consistency proofs,
 *   - client-side verification of a binding's inclusion under a signed STH and of
 *     append-only consistency between two STHs,
 *   - split-view (equivocation) detection: two STHs both validly signed by the same
 *     log key that are incompatible are non-repudiable proof the log forked its view.
 *
 * The Merkle layer proves statements about one root; this layer binds roots to the
 * operator's signature and to each other over time, which is what actually deprives
 * an untrusted relay of the ability to equivocate undetectably. */

#include <stddef.h>
#include <stdint.h>

#include "crypto_utils.h"   /* crypto_error_t, QSAFE_SIG_* sizes */
#include "merkle.h"         /* MERKLE_HASH_SIZE, MERKLE_MAX_PROOF */

/* The log's commitment to its state at a point in time. */
typedef struct {
    uint64_t      size;
    unsigned char root[MERKLE_HASH_SIZE];
    uint64_t      timestamp;
} translog_sth_t;

typedef enum {
    TRANSLOG_CONSISTENT = 0,   /* the two STHs are compatible (one extends the other) */
    TRANSLOG_FORK       = 1,   /* incompatible: proof of equivocation / split view */
    TRANSLOG_BADSIG     = 2    /* an STH signature did not verify */
} translog_verdict_t;

/* --- Signed Tree Head --- */

/* Sign / verify an STH with the log operator's ML-DSA key. The signed bytes are
 * "Veil-STH-v1" || u64be(size) || root || u64be(timestamp) (domain-separated). */
crypto_error_t translog_sth_sign(const unsigned char sk[QSAFE_SIG_SEC_SIZE],
                                 const translog_sth_t *sth,
                                 unsigned char *sig_out, size_t *sig_len);
crypto_error_t translog_sth_verify(const unsigned char pk[QSAFE_SIG_PUB_SIZE],
                                   const translog_sth_t *sth,
                                   const unsigned char *sig, size_t sig_len);

/* --- Client verification --- */

/* Verify that `leaf_data` sits at `index` in the tree committed by `sth`. The STH's
 * signature MUST already have been checked with translog_sth_verify. Returns 1/0. */
int translog_verify_inclusion(const translog_sth_t *sth, uint64_t index,
                              const unsigned char *leaf_data, size_t leaf_len,
                              const unsigned char proof[][MERKLE_HASH_SIZE], size_t proof_len);

/* Verify that STH `b` is an append-only extension of STH `a` (a->size <= b->size)
 * via a consistency proof. Returns 1/0. */
int translog_verify_consistency(const translog_sth_t *a, const translog_sth_t *b,
                                const unsigned char proof[][MERKLE_HASH_SIZE], size_t proof_len);

/* Gossip / split-view check: given two STHs both claimed from the same log, verify
 * both signatures and decide whether they are consistent or fork evidence. `proof`
 * is the consistency proof from the smaller to the larger STH (ignored when sizes
 * are equal). */
translog_verdict_t translog_gossip_check(const unsigned char log_pk[QSAFE_SIG_PUB_SIZE],
                                         const translog_sth_t *a, const unsigned char *sig_a, size_t sig_a_len,
                                         const translog_sth_t *b, const unsigned char *sig_b, size_t sig_b_len,
                                         const unsigned char proof[][MERKLE_HASH_SIZE], size_t proof_len);

/* --- Operator-side append-only log --- */

typedef struct translog translog_t;

translog_t *translog_new(void);
void        translog_free(translog_t *log);

/* Append a binding (raw leaf data). Returns its 0-based index, or (uint64_t)-1 on OOM. */
uint64_t translog_append(translog_t *log, const unsigned char *leaf_data, size_t len);
uint64_t translog_size(const translog_t *log);
void     translog_root(const translog_t *log, unsigned char out[MERKLE_HASH_SIZE]);

/* Fill an STH for the current head (caller supplies the timestamp). */
void translog_head(const translog_t *log, uint64_t timestamp, translog_sth_t *out);

/* Serve proofs. Return 0 on success, -1 on bad args. */
int translog_prove_inclusion(const translog_t *log, uint64_t index,
                             unsigned char proof_out[][MERKLE_HASH_SIZE], size_t *proof_len);
int translog_prove_consistency(const translog_t *log, uint64_t old_size,
                               unsigned char proof_out[][MERKLE_HASH_SIZE], size_t *proof_len);

#endif /* QSAFE_TRANSLOG_H */
