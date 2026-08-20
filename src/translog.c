/* Transparency log + Signed Tree Head — see include/translog.h and
 * veil/docs/KEY_TRANSPARENCY.md. Thin, auditable layer over the RFC 6962 Merkle
 * primitive (merkle.c) plus qsafe's ML-DSA signatures for the STH. */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "translog.h"
#include "merkle.h"
#include "crypto_utils.h"

#define STH_LABEL "Veil-STH-v1"
#define STH_LABEL_LEN 11
#define STH_BYTES_MAX (STH_LABEL_LEN + 8 + MERKLE_HASH_SIZE + 8)

/* Canonical signed bytes: label || u64be(size) || root || u64be(timestamp). */
static size_t sth_bytes(const translog_sth_t *sth, unsigned char buf[STH_BYTES_MAX]) {
    unsigned char *p = buf;
    memcpy(p, STH_LABEL, STH_LABEL_LEN); p += STH_LABEL_LEN;
    for (int i = 7; i >= 0; i--) *p++ = (unsigned char)(sth->size >> (8 * i));
    memcpy(p, sth->root, MERKLE_HASH_SIZE); p += MERKLE_HASH_SIZE;
    for (int i = 7; i >= 0; i--) *p++ = (unsigned char)(sth->timestamp >> (8 * i));
    return (size_t)(p - buf);
}

crypto_error_t translog_sth_sign(const unsigned char sk[QSAFE_SIG_SEC_SIZE],
                                 const translog_sth_t *sth,
                                 unsigned char *sig_out, size_t *sig_len) {
    if (!sk || !sth || !sig_out || !sig_len) return CRYPTO_ERR_INVALID_INPUT;
    unsigned char buf[STH_BYTES_MAX];
    size_t n = sth_bytes(sth, buf);
    return crypto_sig_sign_buf(buf, n, sk, sig_out, sig_len);
}

crypto_error_t translog_sth_verify(const unsigned char pk[QSAFE_SIG_PUB_SIZE],
                                   const translog_sth_t *sth,
                                   const unsigned char *sig, size_t sig_len) {
    if (!pk || !sth || !sig) return CRYPTO_ERR_INVALID_INPUT;
    unsigned char buf[STH_BYTES_MAX];
    size_t n = sth_bytes(sth, buf);
    return crypto_sig_verify_buf(buf, n, sig, sig_len, pk);
}

int translog_verify_inclusion(const translog_sth_t *sth, uint64_t index,
                              const unsigned char *leaf_data, size_t leaf_len,
                              const unsigned char proof[][MERKLE_HASH_SIZE], size_t proof_len) {
    if (!sth || index >= sth->size) return 0;
    unsigned char lh[MERKLE_HASH_SIZE];
    merkle_hash_leaf(leaf_data, leaf_len, lh);
    return merkle_verify_inclusion((size_t)index, (size_t)sth->size, lh, proof, proof_len, sth->root);
}

int translog_verify_consistency(const translog_sth_t *a, const translog_sth_t *b,
                                const unsigned char proof[][MERKLE_HASH_SIZE], size_t proof_len) {
    if (!a || !b || a->size > b->size) return 0;
    return merkle_verify_consistency((size_t)a->size, (size_t)b->size, a->root, b->root, proof, proof_len);
}

translog_verdict_t translog_gossip_check(const unsigned char log_pk[QSAFE_SIG_PUB_SIZE],
                                         const translog_sth_t *a, const unsigned char *sig_a, size_t sig_a_len,
                                         const translog_sth_t *b, const unsigned char *sig_b, size_t sig_b_len,
                                         const unsigned char proof[][MERKLE_HASH_SIZE], size_t proof_len) {
    if (translog_sth_verify(log_pk, a, sig_a, sig_a_len) != CRYPTO_SUCCESS) return TRANSLOG_BADSIG;
    if (translog_sth_verify(log_pk, b, sig_b, sig_b_len) != CRYPTO_SUCCESS) return TRANSLOG_BADSIG;

    const translog_sth_t *lo = a, *hi = b;
    if (a->size > b->size) { lo = b; hi = a; }
    if (lo->size == hi->size)
        return memcmp(lo->root, hi->root, MERKLE_HASH_SIZE) == 0 ? TRANSLOG_CONSISTENT : TRANSLOG_FORK;
    /* proof is the smaller->larger consistency proof, regardless of (a,b) order. */
    return merkle_verify_consistency((size_t)lo->size, (size_t)hi->size, lo->root, hi->root, proof, proof_len)
             ? TRANSLOG_CONSISTENT : TRANSLOG_FORK;
}

/* --- operator-side append-only log --- */

struct translog {
    unsigned char (*leaves)[MERKLE_HASH_SIZE];
    size_t n, cap;
};

translog_t *translog_new(void) { return calloc(1, sizeof(translog_t)); }

void translog_free(translog_t *log) {
    if (!log) return;
    free(log->leaves);
    free(log);
}

uint64_t translog_append(translog_t *log, const unsigned char *leaf_data, size_t len) {
    if (!log) return (uint64_t)-1;
    if (log->n == log->cap) {
        size_t nc = log->cap ? log->cap * 2 : 16;
        void *p = realloc(log->leaves, nc * MERKLE_HASH_SIZE);
        if (!p) return (uint64_t)-1;
        log->leaves = p;
        log->cap = nc;
    }
    merkle_hash_leaf(leaf_data, len, log->leaves[log->n]);
    return (uint64_t)(log->n++);
}

uint64_t translog_size(const translog_t *log) { return log ? (uint64_t)log->n : 0; }

void translog_root(const translog_t *log, unsigned char out[MERKLE_HASH_SIZE]) {
    merkle_root(log->leaves, log->n, out);
}

void translog_head(const translog_t *log, uint64_t timestamp, translog_sth_t *out) {
    out->size = (uint64_t)log->n;
    merkle_root(log->leaves, log->n, out->root);
    out->timestamp = timestamp;
}

int translog_prove_inclusion(const translog_t *log, uint64_t index,
                             unsigned char proof_out[][MERKLE_HASH_SIZE], size_t *proof_len) {
    if (!log || index >= log->n) return -1;
    return merkle_inclusion_proof(log->leaves, log->n, (size_t)index, proof_out, proof_len);
}

int translog_prove_consistency(const translog_t *log, uint64_t old_size,
                               unsigned char proof_out[][MERKLE_HASH_SIZE], size_t *proof_len) {
    if (!log || old_size == 0 || old_size > log->n) return -1;
    return merkle_consistency_proof(log->leaves, log->n, (size_t)old_size, proof_out, proof_len);
}
