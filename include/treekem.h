#ifndef QSAFE_TREEKEM_H
#define QSAFE_TREEKEM_H

/* PQ-TreeKEM — the ratchet tree behind an MLS-style group with O(log N) re-keys and
 * post-compromise security (veil/docs/TREEKEM.md). Perfect binary tree, N = 2^k
 * leaves, one ML-KEM-1024 keypair per node; a member's commit re-keys only its path
 * to the root and heals the group secret. This is the tree/KEM core — MLS proposals,
 * framing, and the epoch key schedule are separate layers. */

#include <stddef.h>
#include <stdint.h>
#include "crypto_utils.h"   /* crypto_error_t */

#define TREEKEM_MLKEM_PK   1568
#define TREEKEM_MLKEM_SK   3168
#define TREEKEM_MLKEM_CT   1568
#define TREEKEM_SECRET     32
#define TREEKEM_MAX_LEAVES 16                 /* depth <= 4 */
#define TREEKEM_MAX_NODES  (2 * TREEKEM_MAX_LEAVES)
#define TREEKEM_MAX_PATH   5                  /* leaf..root, log2(16)+1 */
#define TREEKEM_MAX_RES    (TREEKEM_MAX_LEAVES / 2)

typedef struct treekem treekem_t;

/* One node on a committer's update path: its new public key, and the path secret
 * sealed (ML-KEM ct + AEAD) to each resolution node of the copath. */
typedef struct {
    uint32_t      node;
    unsigned char pub[TREEKEM_MLKEM_PK];
    uint32_t      n_enc;
    struct {
        uint32_t      recipient;                          /* node index the ct is for */
        unsigned char ct[TREEKEM_MLKEM_CT];
        unsigned char sealed[TREEKEM_SECRET + AES_GCM_TAG_SIZE];
    } enc[TREEKEM_MAX_RES];
} treekem_step_t;

/* A commit: the sender's new leaf public key plus its update path. */
typedef struct {
    uint32_t       sender_leaf;
    unsigned char  leaf_pub[TREEKEM_MLKEM_PK];
    uint32_t       n_steps;
    treekem_step_t step[TREEKEM_MAX_PATH];
} treekem_commit_t;

/* A public snapshot of the ratchet tree (no secrets) — the core of an MLS Welcome:
 * what a joining member needs to build its view before processing the add commit. */
typedef struct {
    uint32_t n_leaves;
    struct { int has_pub; unsigned char pub[TREEKEM_MLKEM_PK]; } node[TREEKEM_MAX_NODES + 1];
} treekem_public_t;

/* Generate a random ML-KEM-1024 leaf keypair (helper for group bootstrap / KeyPackage). */
crypto_error_t treekem_keygen(unsigned char pub[TREEKEM_MLKEM_PK], unsigned char priv[TREEKEM_MLKEM_SK]);

/* Build member `me`'s view of an N-leaf group: every leaf's public key is known, and
 * this member holds its own leaf secret key. Internal nodes start blank. */
crypto_error_t treekem_init(treekem_t **out, uint32_t n_leaves, uint32_t me,
                            const unsigned char leaf_pubs[][TREEKEM_MLKEM_PK],
                            const unsigned char my_leaf_priv[TREEKEM_MLKEM_SK]);

/* Commit an update from this member: re-key its path to the root, producing `out` and
 * setting this member's root secret. */
crypto_error_t treekem_commit(treekem_t *t, treekem_commit_t *out);

/* Process another member's commit: install the new keys, recover the path secret, and
 * derive the new root secret (which equals the committer's). */
crypto_error_t treekem_process(treekem_t *t, const treekem_commit_t *c);

/* Current 32-byte root (group) secret, or NULL if none has been established yet. */
const unsigned char *treekem_root_secret(const treekem_t *t);

/* --- dynamic membership (Add / Remove) --- */

/* Index of a free (blank) leaf to seat a new member, or -1 if the group is full. */
int treekem_free_leaf(const treekem_t *t);

/* Add a member: install the joiner's leaf public key (from their KeyPackage) into a
 * blank leaf and blank that leaf's direct path so the next commit re-keys toward the
 * joiner. Call before treekem_commit; the commit's sealed secrets then reach the
 * joiner via its leaf, and treekem_export gives the joiner the tree it needs. */
crypto_error_t treekem_add_leaf(treekem_t *t, uint32_t leaf, const unsigned char pub[TREEKEM_MLKEM_PK]);

/* Blank a member's leaf (removal); the next commit re-keys around it, so the removed
 * member cannot derive the new group secret (forward secrecy on removal). */
void treekem_blank_leaf(treekem_t *t, uint32_t leaf);

/* Public tree snapshot (the Welcome payload) / build a joiner's view from one. The
 * joiner supplies its own leaf secret key; then it processes the add commit. */
void treekem_export(const treekem_t *t, treekem_public_t *out);
crypto_error_t treekem_import(treekem_t **out, const treekem_public_t *pub, uint32_t my_leaf,
                              const unsigned char my_leaf_priv[TREEKEM_MLKEM_SK]);

void treekem_free(treekem_t *t);

#endif /* QSAFE_TREEKEM_H */
