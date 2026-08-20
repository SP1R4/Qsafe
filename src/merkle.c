/* RFC 6962 Merkle tree — see include/merkle.h and veil/docs/KEY_TRANSPARENCY.md.
 * Recursive Merkle Tree Hash / audit path (RFC 6962 §2.1.1), consistency proof
 * (§2.1.2), and the RFC 6962-bis iterative consistency verifier (§2.1.4.2). */

#include <string.h>

#include <openssl/sha.h>
#include <openssl/evp.h>

#include "merkle.h"

#define H MERKLE_HASH_SIZE

/* node hash = SHA-256(0x01 || left || right). */
static void hash_children(const unsigned char l[H], const unsigned char r[H], unsigned char out[H]) {
    unsigned char buf[1 + 2 * H];
    buf[0] = 0x01;
    memcpy(buf + 1, l, H);
    memcpy(buf + 1 + H, r, H);
    SHA256(buf, sizeof buf, out);
}

void merkle_hash_leaf(const unsigned char *data, size_t len, unsigned char out[H]) {
    /* SHA-256(0x00 || data) — streamed so arbitrarily large leaves need no buffer. */
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    unsigned char pfx = 0x00;
    unsigned int outlen = 0;
    EVP_DigestInit_ex(c, EVP_sha256(), NULL);
    EVP_DigestUpdate(c, &pfx, 1);
    if (len) EVP_DigestUpdate(c, data, len);
    EVP_DigestFinal_ex(c, out, &outlen);
    EVP_MD_CTX_free(c);
}

/* Largest power of two strictly less than n (n >= 2). */
static size_t split(size_t n) {
    size_t k = 1;
    while (k * 2 < n) k *= 2;
    return k;
}

/* Merkle Tree Hash of the leaf-hash slice [lo, hi). */
static void mth(const unsigned char leaves[][H], size_t lo, size_t hi, unsigned char out[H]) {
    size_t n = hi - lo;
    if (n == 0) { SHA256((const unsigned char *)"", 0, out); return; }
    if (n == 1) { memcpy(out, leaves[lo], H); return; }
    size_t k = split(n);
    unsigned char l[H], r[H];
    mth(leaves, lo, lo + k, l);
    mth(leaves, lo + k, hi, r);
    hash_children(l, r, out);
}

void merkle_root(const unsigned char leaves[][H], size_t n, unsigned char out[H]) {
    mth(leaves, 0, n, out);
}

/* Audit path for absolute leaf index m within slice [lo, hi). Siblings are appended
 * deepest-first (post-order), matching the verifier's consumption order. */
static void path(const unsigned char leaves[][H], size_t lo, size_t hi, size_t m,
                 unsigned char proof[][H], size_t *plen) {
    size_t n = hi - lo;
    if (n <= 1) return;
    size_t k = split(n);
    if (m < lo + k) {
        path(leaves, lo, lo + k, m, proof, plen);
        mth(leaves, lo + k, hi, proof[(*plen)++]);
    } else {
        path(leaves, lo + k, hi, m, proof, plen);
        mth(leaves, lo, lo + k, proof[(*plen)++]);
    }
}

int merkle_inclusion_proof(const unsigned char leaves[][H], size_t n, size_t m,
                           unsigned char proof_out[][H], size_t *proof_len) {
    if (m >= n) return -1;
    *proof_len = 0;
    path(leaves, 0, n, m, proof_out, proof_len);
    return 0;
}

/* Recompute the root from a leaf and its audit path, mirroring `path`'s structure. */
static int rebuild(size_t lo, size_t hi, size_t m, const unsigned char leaf[H],
                   const unsigned char proof[][H], size_t plen, size_t *pidx, unsigned char out[H]) {
    size_t n = hi - lo;
    if (n == 1) { memcpy(out, leaf, H); return 1; }
    size_t k = split(n);
    unsigned char sub[H], node[H];
    if (m < lo + k) {
        if (!rebuild(lo, lo + k, m, leaf, proof, plen, pidx, sub)) return 0;
        if (*pidx >= plen) return 0;
        hash_children(sub, proof[(*pidx)++], node);
    } else {
        if (!rebuild(lo + k, hi, m, leaf, proof, plen, pidx, sub)) return 0;
        if (*pidx >= plen) return 0;
        hash_children(proof[(*pidx)++], sub, node);
    }
    memcpy(out, node, H);
    return 1;
}

int merkle_verify_inclusion(size_t m, size_t n, const unsigned char leaf_hash[H],
                            const unsigned char proof[][H], size_t proof_len,
                            const unsigned char root[H]) {
    if (m >= n) return 0;
    size_t pidx = 0;
    unsigned char computed[H];
    if (!rebuild(0, n, m, leaf_hash, proof, proof_len, &pidx, computed)) return 0;
    if (pidx != proof_len) return 0;                 /* reject trailing junk */
    return memcmp(computed, root, H) == 0;
}

/* RFC 6962 §2.1.2 SUBPROOF over [lo, hi) with prefix count m (0 < m <= hi-lo). */
static void subproof(const unsigned char leaves[][H], size_t lo, size_t hi, size_t m, int b,
                     unsigned char proof[][H], size_t *plen) {
    size_t n = hi - lo;
    if (m == n) {
        if (!b) mth(leaves, lo, hi, proof[(*plen)++]);
        return;
    }
    size_t k = split(n);
    if (m <= k) {
        subproof(leaves, lo, lo + k, m, b, proof, plen);
        mth(leaves, lo + k, hi, proof[(*plen)++]);
    } else {
        subproof(leaves, lo + k, hi, m - k, 0, proof, plen);
        mth(leaves, lo, lo + k, proof[(*plen)++]);
    }
}

int merkle_consistency_proof(const unsigned char leaves[][H], size_t n, size_t m,
                             unsigned char proof_out[][H], size_t *proof_len) {
    if (m == 0 || m > n) return -1;
    *proof_len = 0;
    if (m == n) return 0;                            /* prefix == tree: empty proof */
    subproof(leaves, 0, n, m, 1, proof_out, proof_len);
    return 0;
}

static int is_pow2(size_t x) { return x && !(x & (x - 1)); }

/* RFC 6962-bis §2.1.4.2 consistency verification. */
int merkle_verify_consistency(size_t m, size_t n,
                              const unsigned char first_root[H], const unsigned char second_root[H],
                              const unsigned char proof[][H], size_t proof_len) {
    if (m > n) return 0;
    if (m == n) return proof_len == 0 && memcmp(first_root, second_root, H) == 0;
    if (m == 0) return proof_len == 0;               /* empty prefix: trivially consistent */

    size_t fn = m - 1, sn = n - 1;
    while (fn & 1) { fn >>= 1; sn >>= 1; }

    unsigned char fr[H], sr[H];
    size_t idx = 0;
    if (is_pow2(m)) {                                /* first tree is a full subtree */
        memcpy(fr, first_root, H);
        memcpy(sr, first_root, H);
    } else {
        if (proof_len == 0) return 0;
        memcpy(fr, proof[idx], H);
        memcpy(sr, proof[idx], H);
        idx++;
    }

    for (; idx < proof_len; idx++) {
        const unsigned char *c = proof[idx];
        if (sn == 0) return 0;
        if ((fn & 1) || fn == sn) {
            unsigned char t[H];
            hash_children(c, fr, t); memcpy(fr, t, H);
            hash_children(c, sr, t); memcpy(sr, t, H);
            while (fn != 0 && !(fn & 1)) { fn >>= 1; sn >>= 1; }
        } else {
            unsigned char t[H];
            hash_children(sr, c, t); memcpy(sr, t, H);
        }
        fn >>= 1; sn >>= 1;
    }
    return sn == 0 && memcmp(fr, first_root, H) == 0 && memcmp(sr, second_root, H) == 0;
}
