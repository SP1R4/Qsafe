/* PQ-TreeKEM — see include/treekem.h and veil/docs/TREEKEM.md.
 *
 * Perfect binary tree, heap indexing: root = 1, node i has children 2i/2i+1, sibling
 * i^1, parent i>>1; member m's leaf = N + m (leaves are N..2N-1). One ML-KEM-1024
 * keypair per node, derived deterministically from a path secret so an update sends
 * O(log N) secrets, not O(N). */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <oqs/oqs.h>
#include <oqs/kem_ml_kem.h>

#include "treekem.h"
#include "crypto_utils.h"

#define PK TREEKEM_MLKEM_PK
#define SK TREEKEM_MLKEM_SK
#define CT TREEKEM_MLKEM_CT
#define SEED 64
#define SEC TREEKEM_SECRET

static void zero(void *p, size_t n) { OPENSSL_cleanse(p, n); }

typedef struct {
    int           has_pub, has_priv;
    unsigned char pub[PK];
    unsigned char priv[SK];
} node_t;

struct treekem {
    uint32_t n_leaves;                 /* N (power of two) */
    uint32_t my_leaf;                  /* our leaf node index = N + member */
    node_t   node[TREEKEM_MAX_NODES + 1];   /* 1..2N-1 */
    unsigned char root_secret[SEC];
    int      have_root;
};

/* --- tree math (heap) --- */
static uint32_t parent(uint32_t i)  { return i >> 1; }
static uint32_t sibling(uint32_t i) { return i ^ 1u; }
static int is_ancestor(uint32_t a, uint32_t leaf) {   /* a ancestor-or-self of leaf */
    while (leaf > a) leaf >>= 1;
    return leaf == a;
}

/* --- KEM (ML-KEM-1024, direct liboqs) --- */
static int kem_derand(const unsigned char seed[SEED], unsigned char pub[PK], unsigned char priv[SK]) {
    return OQS_KEM_ml_kem_1024_keypair_derand(pub, priv, seed) == OQS_SUCCESS;
}
static int kem_encaps(const unsigned char pub[PK], unsigned char ct[CT], unsigned char ss[SEC]) {
    return OQS_KEM_ml_kem_1024_encaps(ct, ss, pub) == OQS_SUCCESS;
}
static int kem_decaps(const unsigned char priv[SK], const unsigned char ct[CT], unsigned char ss[SEC]) {
    return OQS_KEM_ml_kem_1024_decaps(ss, ct, priv) == OQS_SUCCESS;
}

/* --- KDF --- */
static crypto_error_t kdf(const unsigned char *secret, size_t slen, const char *label,
                          unsigned char *out, size_t outlen) {
    return crypto_hkdf_sha256(secret, slen, NULL, 0,
                              (const unsigned char *)label, strlen(label), out, outlen);
}

/* Derive a node's keypair from its path secret; store pub (+ priv iff with_priv). */
static int node_from_ps(node_t *nd, const unsigned char ps[SEC], int with_priv) {
    unsigned char seed[SEED];
    if (kdf(ps, SEC, "node", seed, SEED) != CRYPTO_SUCCESS) return 0;
    unsigned char pub[PK], priv[SK];
    int ok = kem_derand(seed, pub, priv);
    zero(seed, sizeof seed);
    if (!ok) { zero(priv, sizeof priv); return 0; }
    memcpy(nd->pub, pub, PK); nd->has_pub = 1;
    if (with_priv) { memcpy(nd->priv, priv, SK); nd->has_priv = 1; }
    zero(priv, sizeof priv);
    return 1;
}

/* Resolution of a subtree: highest populated nodes (leaves if internal is blank). */
static void resolution(const treekem_t *t, uint32_t v, uint32_t *out, uint32_t *n) {
    if (v > 2 * t->n_leaves - 1) return;
    if (t->node[v].has_pub) { out[(*n)++] = v; return; }
    if (v >= t->n_leaves) return;              /* blank leaf */
    resolution(t, 2 * v, out, n);
    resolution(t, 2 * v + 1, out, n);
}

/* Seal a path secret to a recipient node's public key: ML-KEM ct + AEAD(HKDF(ss)). */
static int seal_ps(const unsigned char pub[PK], const unsigned char ps[SEC],
                   unsigned char ct[CT], unsigned char sealed[SEC + AES_GCM_TAG_SIZE]) {
    unsigned char ss[SEC], key[SEC], nonce[AES_GCM_NONCE_SIZE] = {0};
    if (!kem_encaps(pub, ct, ss)) return 0;
    int ok = (kdf(ss, SEC, "enc", key, SEC) == CRYPTO_SUCCESS) &&
             crypto_gcm_seal_aad(key, nonce, NULL, 0, ps, SEC, sealed, sealed + SEC);
    zero(ss, sizeof ss); zero(key, sizeof key);
    return ok;
}
static int open_ps(const unsigned char priv[SK], const unsigned char ct[CT],
                   const unsigned char sealed[SEC + AES_GCM_TAG_SIZE], unsigned char ps[SEC]) {
    unsigned char ss[SEC], key[SEC], nonce[AES_GCM_NONCE_SIZE] = {0};
    if (!kem_decaps(priv, ct, ss)) return 0;
    int ok = (kdf(ss, SEC, "enc", key, SEC) == CRYPTO_SUCCESS) &&
             crypto_gcm_open_aad(key, nonce, NULL, 0, sealed, SEC, sealed + SEC, ps);
    zero(ss, sizeof ss); zero(key, sizeof key);
    return ok;
}

crypto_error_t treekem_keygen(unsigned char pub[PK], unsigned char priv[SK]) {
    return OQS_KEM_ml_kem_1024_keypair(pub, priv) == OQS_SUCCESS ? CRYPTO_SUCCESS : CRYPTO_ERR_CRYPTO;
}

static int is_pow2(uint32_t x) { return x && !(x & (x - 1)); }

crypto_error_t treekem_init(treekem_t **out, uint32_t n_leaves, uint32_t me,
                            const unsigned char leaf_pubs[][PK],
                            const unsigned char my_leaf_priv[SK]) {
    if (!out || !leaf_pubs || !my_leaf_priv || me >= n_leaves ||
        n_leaves < 2 || n_leaves > TREEKEM_MAX_LEAVES || !is_pow2(n_leaves))
        return CRYPTO_ERR_INVALID_INPUT;
    treekem_t *t = calloc(1, sizeof *t);
    if (!t) return CRYPTO_ERR_MEMORY;
    t->n_leaves = n_leaves;
    t->my_leaf = n_leaves + me;
    for (uint32_t m = 0; m < n_leaves; m++) {
        node_t *nd = &t->node[n_leaves + m];
        memcpy(nd->pub, leaf_pubs[m], PK); nd->has_pub = 1;
    }
    memcpy(t->node[t->my_leaf].priv, my_leaf_priv, SK);
    t->node[t->my_leaf].has_priv = 1;
    *out = t;
    return CRYPTO_SUCCESS;
}

crypto_error_t treekem_commit(treekem_t *t, treekem_commit_t *out) {
    if (!t || !out) return CRYPTO_ERR_INVALID_INPUT;
    memset(out, 0, sizeof *out);

    unsigned char leaf_secret[SEC], ps[SEC];
    if (RAND_bytes(leaf_secret, SEC) != 1) return CRYPTO_ERR_CRYPTO;

    /* fresh leaf keypair (we hold its private key) */
    if (!node_from_ps(&t->node[t->my_leaf], leaf_secret, 1)) { zero(leaf_secret, SEC); return CRYPTO_ERR_CRYPTO; }
    out->sender_leaf = t->my_leaf;
    memcpy(out->leaf_pub, t->node[t->my_leaf].pub, PK);

    crypto_error_t rc = kdf(leaf_secret, SEC, "path", ps, SEC);
    zero(leaf_secret, SEC);
    if (rc != CRYPTO_SUCCESS) return rc;

    uint32_t child = t->my_leaf, v = parent(t->my_leaf), step = 0;
    for (;;) {
        if (!node_from_ps(&t->node[v], ps, 1)) { rc = CRYPTO_ERR_CRYPTO; goto out; }
        treekem_step_t *st = &out->step[step];
        st->node = v;
        memcpy(st->pub, t->node[v].pub, PK);

        uint32_t res[TREEKEM_MAX_RES]; uint32_t nres = 0;
        resolution(t, sibling(child), res, &nres);
        st->n_enc = 0;
        for (uint32_t i = 0; i < nres && st->n_enc < TREEKEM_MAX_RES; i++) {
            st->enc[st->n_enc].recipient = res[i];
            if (!seal_ps(t->node[res[i]].pub, ps, st->enc[st->n_enc].ct, st->enc[st->n_enc].sealed)) { rc = CRYPTO_ERR_CRYPTO; goto out; }
            st->n_enc++;
        }
        step++;
        if (v == 1) {                                     /* root: set the group secret */
            rc = kdf(ps, SEC, "root", t->root_secret, SEC);
            if (rc != CRYPTO_SUCCESS) goto out;
            t->have_root = 1;
            break;
        }
        child = v; v = parent(v);
        unsigned char nps[SEC];
        rc = kdf(ps, SEC, "path", nps, SEC);
        memcpy(ps, nps, SEC); zero(nps, sizeof nps);
        if (rc != CRYPTO_SUCCESS) goto out;
    }
    out->n_steps = step;
    rc = CRYPTO_SUCCESS;
out:
    zero(ps, sizeof ps);
    return rc;
}

crypto_error_t treekem_process(treekem_t *t, const treekem_commit_t *c) {
    if (!t || !c || c->n_steps == 0 || c->n_steps > TREEKEM_MAX_PATH) return CRYPTO_ERR_INVALID_INPUT;
    if (c->sender_leaf < t->n_leaves || c->sender_leaf >= 2 * t->n_leaves) return CRYPTO_ERR_INVALID_INPUT;
    if (c->sender_leaf == t->my_leaf) return CRYPTO_ERR_INVALID_INPUT;   /* not our own commit */

    /* 1. Install the committer's new public keys (their private halves are stale to us). */
    memcpy(t->node[c->sender_leaf].pub, c->leaf_pub, PK);
    t->node[c->sender_leaf].has_pub = 1; t->node[c->sender_leaf].has_priv = 0;
    for (uint32_t s = 0; s < c->n_steps; s++) {
        uint32_t v = c->step[s].node;
        if (v < 1 || v > 2 * t->n_leaves - 1) return CRYPTO_ERR_INVALID_INPUT;
        memcpy(t->node[v].pub, c->step[s].pub, PK);
        t->node[v].has_pub = 1; t->node[v].has_priv = 0;
    }

    /* 2. Find the step whose copath covers our leaf, and a sealed secret we can open. */
    unsigned char ps[SEC]; int got = 0;
    uint32_t child = c->sender_leaf, isv = 0;
    for (uint32_t s = 0; s < c->n_steps && !got; s++) {
        uint32_t v = c->step[s].node;
        uint32_t cop = sibling(child);
        if (is_ancestor(cop, t->my_leaf)) {
            for (uint32_t i = 0; i < c->step[s].n_enc; i++) {
                uint32_t r = c->step[s].enc[i].recipient;
                if (is_ancestor(r, t->my_leaf) && t->node[r].has_priv &&
                    open_ps(t->node[r].priv, c->step[s].enc[i].ct, c->step[s].enc[i].sealed, ps)) {
                    isv = v; got = 1; break;
                }
            }
        }
        child = v;
    }
    if (!got) return CRYPTO_ERR_INTEGRITY;

    /* 3. From the intersection node up to the root, re-derive our node secrets and the
     * group secret (the same path the committer walked). */
    uint32_t v = isv;
    crypto_error_t rc = CRYPTO_SUCCESS;
    for (;;) {
        if (!node_from_ps(&t->node[v], ps, 1)) { rc = CRYPTO_ERR_CRYPTO; break; }
        if (v == 1) { rc = kdf(ps, SEC, "root", t->root_secret, SEC); if (rc == CRYPTO_SUCCESS) t->have_root = 1; break; }
        unsigned char nps[SEC];
        rc = kdf(ps, SEC, "path", nps, SEC);
        memcpy(ps, nps, SEC); zero(nps, sizeof nps);
        if (rc != CRYPTO_SUCCESS) break;
        v = parent(v);
    }
    zero(ps, sizeof ps);
    return rc;
}

const unsigned char *treekem_root_secret(const treekem_t *t) {
    return (t && t->have_root) ? t->root_secret : NULL;
}

void treekem_blank_leaf(treekem_t *t, uint32_t leaf) {
    if (!t || leaf < t->n_leaves || leaf >= 2 * t->n_leaves) return;
    zero(&t->node[leaf], sizeof t->node[leaf]);
    /* also blank the internal nodes on that leaf's path (their secrets are compromised
     * once the member is removed); the next commit re-keys them. */
    for (uint32_t v = parent(leaf); v >= 1; v = parent(v)) {
        zero(&t->node[v], sizeof t->node[v]);
        if (v == 1) break;
    }
}

void treekem_free(treekem_t *t) {
    if (!t) return;
    zero(t, sizeof *t);
    free(t);
}
