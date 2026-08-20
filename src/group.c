/* Sender-key group ratchet — see include/group.h and veil/docs/GROUP_MESSAGING.md. */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include "group.h"
#include "crypto_utils.h"

static void secure_zero(void *p, size_t n) { OPENSSL_cleanse(p, n); }

static void put_u32(unsigned char *p, uint32_t v) {
    p[0]=(unsigned char)(v>>24); p[1]=(unsigned char)(v>>16); p[2]=(unsigned char)(v>>8); p[3]=(unsigned char)v;
}
static uint32_t get_u32(const unsigned char *p) {
    return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];
}

/* Chain KDF: ck -> (ck', mk) via two domain-separated HKDF expansions. */
static crypto_error_t g_kdf_ck(const unsigned char ck[GROUP_KEY_SIZE],
                               unsigned char ck_out[GROUP_KEY_SIZE], unsigned char mk_out[GROUP_KEY_SIZE]) {
    static const char MSG[] = "Veil-GRP-MSG", NXT[] = "Veil-GRP-CK";
    crypto_error_t rc = crypto_hkdf_sha256(ck, GROUP_KEY_SIZE, NULL, 0,
                                           (const unsigned char *)MSG, sizeof MSG - 1, mk_out, GROUP_KEY_SIZE);
    if (rc != CRYPTO_SUCCESS) return rc;
    /* ck_out may alias ck; compute after mk. */
    return crypto_hkdf_sha256(ck, GROUP_KEY_SIZE, NULL, 0,
                              (const unsigned char *)NXT, sizeof NXT - 1, ck_out, GROUP_KEY_SIZE);
}

crypto_error_t group_sender_init(group_sender_t *out) {
    if (!out) return CRYPTO_ERR_INVALID_INPUT;
    memset(out, 0, sizeof *out);
    if (RAND_bytes(out->ck, GROUP_KEY_SIZE) != 1) return CRYPTO_ERR_CRYPTO;
    out->index = 0;
    return crypto_sig_keypair_raw(out->sig_pk, out->sig_sk);
}

void group_sender_distribution(const group_sender_t *s, unsigned char out[GROUP_SKDM_SIZE]) {
    unsigned char *q = out;
    memcpy(q, s->ck, GROUP_KEY_SIZE); q += GROUP_KEY_SIZE;
    put_u32(q, s->index); q += 4;
    memcpy(q, s->sig_pk, QSAFE_SIG_PUB_SIZE);
}

crypto_error_t group_receiver_init(group_receiver_t *out, const unsigned char skdm[GROUP_SKDM_SIZE]) {
    if (!out || !skdm) return CRYPTO_ERR_INVALID_INPUT;
    memset(out, 0, sizeof *out);
    const unsigned char *q = skdm;
    memcpy(out->ck, q, GROUP_KEY_SIZE); q += GROUP_KEY_SIZE;
    out->index = get_u32(q); q += 4;
    memcpy(out->sig_pk, q, QSAFE_SIG_PUB_SIZE);
    return CRYPTO_SUCCESS;
}

crypto_error_t group_encrypt(group_sender_t *s, const unsigned char *pt, size_t pt_len,
                             unsigned char *out, size_t *out_len) {
    if (!s || (!pt && pt_len) || !out || !out_len) return CRYPTO_ERR_INVALID_INPUT;
    if (pt_len > INT32_MAX) return CRYPTO_ERR_INVALID_INPUT;

    unsigned char mk[GROUP_KEY_SIZE], ckn[GROUP_KEY_SIZE];
    crypto_error_t rc = g_kdf_ck(s->ck, ckn, mk);
    if (rc != CRYPTO_SUCCESS) return rc;

    unsigned char idx[4]; put_u32(idx, s->index);

    /* Encrypt into a temp buffer; sign over index || ct+tag; then assemble the frame. */
    unsigned char *ct = malloc(pt_len + AES_GCM_TAG_SIZE);
    unsigned char *signbuf = malloc(4 + pt_len + AES_GCM_TAG_SIZE);
    if (!ct || !signbuf) { free(ct); free(signbuf); secure_zero(mk, sizeof mk); secure_zero(ckn, sizeof ckn); return CRYPTO_ERR_MEMORY; }

    unsigned char nonce[AES_GCM_NONCE_SIZE]; crypto_frame_nonce(s->index, 0, nonce);
    unsigned char tag[AES_GCM_TAG_SIZE];
    int ok = crypto_gcm_seal_aad(mk, nonce, idx, 4, pt, (int)pt_len, ct, tag);
    secure_zero(mk, sizeof mk);
    if (!ok) { free(ct); free(signbuf); secure_zero(ckn, sizeof ckn); return CRYPTO_ERR_CRYPTO; }
    memcpy(ct + pt_len, tag, AES_GCM_TAG_SIZE);
    size_t ctlen = pt_len + AES_GCM_TAG_SIZE;

    memcpy(signbuf, idx, 4);
    memcpy(signbuf + 4, ct, ctlen);
    unsigned char sig[QSAFE_SIG_MAX_SIZE]; size_t siglen = 0;
    rc = crypto_sig_sign_buf(signbuf, 4 + ctlen, s->sig_sk, sig, &siglen);
    secure_zero(signbuf, 4 + ctlen); free(signbuf);
    if (rc != CRYPTO_SUCCESS) { free(ct); secure_zero(ckn, sizeof ckn); return rc; }

    /* Frame: index(4) | u16 siglen | sig | ct+tag */
    unsigned char *w = out;
    memcpy(w, idx, 4); w += 4;
    w[0] = (unsigned char)(siglen >> 8); w[1] = (unsigned char)siglen; w += 2;
    memcpy(w, sig, siglen); w += siglen;
    memcpy(w, ct, ctlen); w += ctlen;
    free(ct);
    *out_len = (size_t)(w - out);

    s->index++;
    memcpy(s->ck, ckn, GROUP_KEY_SIZE);
    secure_zero(ckn, sizeof ckn);
    return CRYPTO_SUCCESS;
}

static group_skipped_t *skipped_find(group_receiver_t *r, uint32_t index) {
    for (uint32_t i = 0; i < r->n_skipped; i++) if (r->skipped[i].index == index) return &r->skipped[i];
    return NULL;
}
static void skipped_remove(group_receiver_t *r, group_skipped_t *e) {
    size_t i = (size_t)(e - r->skipped);
    secure_zero(e, sizeof *e);
    if (i + 1 < r->n_skipped) memmove(&r->skipped[i], &r->skipped[i + 1], (r->n_skipped - i - 1) * sizeof *e);
    r->n_skipped--;
}

crypto_error_t group_decrypt(group_receiver_t *r, const unsigned char *in, size_t in_len,
                             unsigned char *pt, size_t *pt_len) {
    if (!r || !in || !pt || !pt_len) return CRYPTO_ERR_INVALID_INPUT;
    if (in_len < 4 + 2) return CRYPTO_ERR_INVALID_INPUT;
    uint32_t index = get_u32(in);
    const unsigned char *q = in + 4;
    uint16_t siglen = (uint16_t)((q[0] << 8) | q[1]); q += 2;
    if (siglen > QSAFE_SIG_MAX_SIZE || in_len < (size_t)(4 + 2 + siglen + AES_GCM_TAG_SIZE)) return CRYPTO_ERR_INVALID_INPUT;
    const unsigned char *sig = q; q += siglen;
    const unsigned char *ct = q;
    size_t ctlen = in_len - (size_t)(q - in);
    size_t body = ctlen - AES_GCM_TAG_SIZE;

    /* 1. Authenticate the sender: ML-DSA signature over index || ct+tag. */
    unsigned char *signbuf = malloc(4 + ctlen);
    if (!signbuf) return CRYPTO_ERR_MEMORY;
    memcpy(signbuf, in, 4);
    memcpy(signbuf + 4, ct, ctlen);
    crypto_error_t rc = crypto_sig_verify_buf(signbuf, 4 + ctlen, sig, siglen, r->sig_pk);
    secure_zero(signbuf, 4 + ctlen); free(signbuf);
    if (rc != CRYPTO_SUCCESS) return CRYPTO_ERR_INTEGRITY;

    /* 2. Locate the message key, working on a copy so nothing commits until the tag
     * verifies. */
    group_receiver_t *w = malloc(sizeof *w);
    if (!w) return CRYPTO_ERR_MEMORY;
    memcpy(w, r, sizeof *w);

    unsigned char mk[GROUP_KEY_SIZE], nonce[AES_GCM_NONCE_SIZE];
    int have_mk = 0, from_skip = 0; group_skipped_t *hit = NULL;

    if (index < w->index) {
        hit = skipped_find(w, index);
        if (!hit) { rc = CRYPTO_ERR_INTEGRITY; goto out; }   /* replay / already consumed */
        memcpy(mk, hit->mk, GROUP_KEY_SIZE); have_mk = 1; from_skip = 1;
    } else {
        if ((uint64_t)index - w->index > GROUP_MAX_SKIP ||
            w->n_skipped + (index - w->index) > GROUP_MAX_SKIP) { rc = CRYPTO_ERR_INVALID_INPUT; goto out; }
        unsigned char ckn[GROUP_KEY_SIZE], mks[GROUP_KEY_SIZE];
        while (w->index < index) {
            rc = g_kdf_ck(w->ck, ckn, mks);
            if (rc != CRYPTO_SUCCESS) { secure_zero(ckn, sizeof ckn); secure_zero(mks, sizeof mks); goto out; }
            w->skipped[w->n_skipped].index = w->index;
            memcpy(w->skipped[w->n_skipped].mk, mks, GROUP_KEY_SIZE);
            w->n_skipped++; w->index++;
            memcpy(w->ck, ckn, GROUP_KEY_SIZE);
        }
        rc = g_kdf_ck(w->ck, ckn, mk);
        secure_zero(mks, sizeof mks);
        if (rc != CRYPTO_SUCCESS) { secure_zero(ckn, sizeof ckn); goto out; }
        memcpy(w->ck, ckn, GROUP_KEY_SIZE);
        secure_zero(ckn, sizeof ckn);
        w->index = index + 1;
        have_mk = 1;
    }

    crypto_frame_nonce(index, 0, nonce);
    int ok = have_mk && crypto_gcm_open_aad(mk, nonce, in, 4, ct, (int)body, ct + body, pt);
    secure_zero(mk, sizeof mk);
    if (!ok) { rc = CRYPTO_ERR_INTEGRITY; goto out; }
    *pt_len = body;
    if (from_skip) skipped_remove(w, hit);
    memcpy(r, w, sizeof *w);   /* commit */
    rc = CRYPTO_SUCCESS;
out:
    secure_zero(w, sizeof *w);
    free(w);
    return rc;
}

/* --- state at rest --- */

crypto_error_t group_sender_serialize(const group_sender_t *s, const char *passphrase,
                                      unsigned char **blob, size_t *blob_len) {
    if (!s || !passphrase || !blob || !blob_len) return CRYPTO_ERR_INVALID_INPUT;
    /* Fixed-size POD; seal its raw bytes (device-local, layout stability not a concern). */
    return crypto_seal_at_rest(passphrase, (const unsigned char *)s, sizeof *s, blob, blob_len);
}

crypto_error_t group_sender_deserialize(const unsigned char *blob, size_t blob_len,
                                        const char *passphrase, group_sender_t *out) {
    if (!blob || !passphrase || !out) return CRYPTO_ERR_INVALID_INPUT;
    unsigned char *pt = NULL; size_t pt_len = 0;
    crypto_error_t rc = crypto_open_at_rest(passphrase, blob, blob_len, &pt, &pt_len);
    if (rc != CRYPTO_SUCCESS) return rc;
    if (pt_len != sizeof *out) { secure_zero(pt, pt_len); free(pt); return CRYPTO_ERR_INTEGRITY; }
    memcpy(out, pt, sizeof *out);
    secure_zero(pt, pt_len); free(pt);
    return CRYPTO_SUCCESS;
}

/* Receiver is packed compactly (only the used skipped entries) before sealing. */
crypto_error_t group_receiver_serialize(const group_receiver_t *r, const char *passphrase,
                                        unsigned char **blob, size_t *blob_len) {
    if (!r || !passphrase || !blob || !blob_len) return CRYPTO_ERR_INVALID_INPUT;
    if (r->n_skipped > GROUP_MAX_SKIP) return CRYPTO_ERR_INVALID_INPUT;
    size_t base = GROUP_KEY_SIZE + 4 + QSAFE_SIG_PUB_SIZE + 4;
    size_t plain_len = base + (size_t)r->n_skipped * (4 + GROUP_KEY_SIZE);
    unsigned char *p = malloc(plain_len);
    if (!p) return CRYPTO_ERR_MEMORY;
    unsigned char *q = p;
    memcpy(q, r->ck, GROUP_KEY_SIZE); q += GROUP_KEY_SIZE;
    put_u32(q, r->index); q += 4;
    memcpy(q, r->sig_pk, QSAFE_SIG_PUB_SIZE); q += QSAFE_SIG_PUB_SIZE;
    put_u32(q, r->n_skipped); q += 4;
    for (uint32_t i = 0; i < r->n_skipped; i++) {
        put_u32(q, r->skipped[i].index); q += 4;
        memcpy(q, r->skipped[i].mk, GROUP_KEY_SIZE); q += GROUP_KEY_SIZE;
    }
    crypto_error_t rc = crypto_seal_at_rest(passphrase, p, plain_len, blob, blob_len);
    secure_zero(p, plain_len); free(p);
    return rc;
}

crypto_error_t group_receiver_deserialize(const unsigned char *blob, size_t blob_len,
                                          const char *passphrase, group_receiver_t *out) {
    if (!blob || !passphrase || !out) return CRYPTO_ERR_INVALID_INPUT;
    unsigned char *pt = NULL; size_t pt_len = 0;
    crypto_error_t rc = crypto_open_at_rest(passphrase, blob, blob_len, &pt, &pt_len);
    if (rc != CRYPTO_SUCCESS) return rc;
    size_t base = GROUP_KEY_SIZE + 4 + QSAFE_SIG_PUB_SIZE + 4;
    crypto_error_t ret = CRYPTO_ERR_INTEGRITY;
    if (pt_len >= base) {
        memset(out, 0, sizeof *out);
        const unsigned char *q = pt;
        memcpy(out->ck, q, GROUP_KEY_SIZE); q += GROUP_KEY_SIZE;
        out->index = get_u32(q); q += 4;
        memcpy(out->sig_pk, q, QSAFE_SIG_PUB_SIZE); q += QSAFE_SIG_PUB_SIZE;
        uint32_t nsk = get_u32(q); q += 4;
        if (nsk <= GROUP_MAX_SKIP && pt_len == base + (size_t)nsk * (4 + GROUP_KEY_SIZE)) {
            for (uint32_t i = 0; i < nsk; i++) {
                out->skipped[i].index = get_u32(q); q += 4;
                memcpy(out->skipped[i].mk, q, GROUP_KEY_SIZE); q += GROUP_KEY_SIZE;
            }
            out->n_skipped = nsk;
            ret = CRYPTO_SUCCESS;
        }
    }
    secure_zero(pt, pt_len); free(pt);
    return ret;
}

void group_sender_free(group_sender_t *s) { if (s) secure_zero(s, sizeof *s); }
void group_receiver_free(group_receiver_t *r) { if (r) secure_zero(r, sizeof *r); }
