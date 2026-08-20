#ifndef QSAFE_MERKLE_H
#define QSAFE_MERKLE_H

/* RFC 6962 Merkle tree — the append-only-log primitive behind veil's key
 * transparency (veil/docs/KEY_TRANSPARENCY.md). Hashing is fixed by RFC 6962:
 *   leaf  hash = SHA-256(0x00 || data)
 *   node  hash = SHA-256(0x01 || left || right)
 *   empty tree = SHA-256("")
 *   internal split at the largest power of two strictly less than n.
 *
 * This module is pure/stateless: callers hold the array of leaf hashes and ask for
 * a root, an inclusion (audit) proof, or a consistency proof, and verify proofs
 * without the leaves. Nothing here allocates; proof buffers are caller-provided and
 * bounded by MERKLE_MAX_PROOF. All values are public, so comparisons are plain. */

#include <stddef.h>

#define MERKLE_HASH_SIZE 32
/* Bounds the proof path length. An audit path is ceil(log2 n) hashes and a
 * consistency proof at most ceil(log2 n)+1, so 128 covers any n up to 2^64 with
 * comfortable headroom — far beyond any real log. */
#define MERKLE_MAX_PROOF 128

/* RFC 6962 leaf hash of arbitrary data: SHA-256(0x00 || data). */
void merkle_hash_leaf(const unsigned char *data, size_t len,
                      unsigned char out[MERKLE_HASH_SIZE]);

/* Merkle Tree Hash (root) over n leaf hashes. n == 0 yields SHA-256(""). */
void merkle_root(const unsigned char leaves[][MERKLE_HASH_SIZE], size_t n,
                 unsigned char out[MERKLE_HASH_SIZE]);

/* Inclusion (audit) proof that leaf index m is in a tree of n leaf hashes. Writes up
 * to MERKLE_MAX_PROOF sibling hashes into proof_out and the count into *proof_len.
 * Returns 0 on success, -1 if m >= n. */
int merkle_inclusion_proof(const unsigned char leaves[][MERKLE_HASH_SIZE], size_t n, size_t m,
                           unsigned char proof_out[][MERKLE_HASH_SIZE], size_t *proof_len);

/* Verify an inclusion proof: recompute the size-n root from leaf_hash at index m and
 * compare to `root`. Returns 1 if valid, 0 otherwise. */
int merkle_verify_inclusion(size_t m, size_t n,
                            const unsigned char leaf_hash[MERKLE_HASH_SIZE],
                            const unsigned char proof[][MERKLE_HASH_SIZE], size_t proof_len,
                            const unsigned char root[MERKLE_HASH_SIZE]);

/* Consistency proof that the size-m prefix is an append-only prefix of the size-n
 * tree (0 < m <= n). m == n yields an empty proof. Returns 0 on success, -1 on bad
 * args (m == 0 or m > n). */
int merkle_consistency_proof(const unsigned char leaves[][MERKLE_HASH_SIZE], size_t n, size_t m,
                             unsigned char proof_out[][MERKLE_HASH_SIZE], size_t *proof_len);

/* Verify a consistency proof between the size-m root (first_root) and the size-n root
 * (second_root), m <= n. Returns 1 if the size-n tree is a valid append-only extension
 * of the size-m tree, 0 otherwise. */
int merkle_verify_consistency(size_t m, size_t n,
                              const unsigned char first_root[MERKLE_HASH_SIZE],
                              const unsigned char second_root[MERKLE_HASH_SIZE],
                              const unsigned char proof[][MERKLE_HASH_SIZE], size_t proof_len);

#endif /* QSAFE_MERKLE_H */
