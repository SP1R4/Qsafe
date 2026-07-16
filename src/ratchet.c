/* Double Ratchet session layer — see include/ratchet.h and veil/docs/SPEC.md.
 *
 * Faithful to the public Signal Double Ratchet, with qsafe's primitives:
 *   KDF_RK / KDF_CK -> crypto_hkdf_sha256
 *   DH              -> crypto_x25519_dh / crypto_x25519_keypair
 *   AEAD            -> crypto_gcm_seal_aad / crypto_gcm_open_aad (header as AAD)
 *   state-at-rest   -> crypto_derive_key_argon2id + AES-256-GCM
 *
 * DRAFT — not trusted until the vectors reproduce and crypto-review passes. */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <oqs/oqs.h>

#include "ratchet.h"
#include "crypto_utils.h"

/* Zeroise; OPENSSL_cleanse is guaranteed not to be optimised away. */
static void secure_zero(void *p, size_t n) { OPENSSL_cleanse(p, n); }

static OQS_KEM *kem_new(void) { return OQS_KEM_new(OQS_KEM_alg_ml_kem_1024); }

typedef struct {
    unsigned char dh_pub[X25519_KEY_SIZE];
    uint32_t n;
    unsigned char mk[AES_KEY_SIZE];
} skipped_key_t;

struct ratchet_session {
    unsigned char rk[AES_KEY_SIZE];                 /* root key */
    unsigned char dhs_sec[X25519_KEY_SIZE];         /* our ratchet keypair */
    unsigned char dhs_pub[X25519_KEY_SIZE];
    unsigned char dhr[X25519_KEY_SIZE];             /* peer ratchet pubkey */
    unsigned char cks[AES_KEY_SIZE];                /* sending chain key */
    unsigned char ckr[AES_KEY_SIZE];                /* receiving chain key */
    uint32_t ns, nr, pn;                            /* counters */
    int have_dhr, have_cks, have_ckr;

    /* Continuous/periodic PQ ratchet (PQ_RATCHET*.md). Zero/unused when pq == 0. */
    int pq;
    int have_kem_r, have_ct;
    int have_kss_send, have_kss_recv;               /* per-direction KEM secret present */
    int send_full;                                  /* current sending run is 0x03 (full) */
    int advertised;                                 /* we have advertised our kem_pk at least once */
    uint32_t send_steps;                            /* our ratchet-step count (rotation cadence) */
    unsigned char kem_sk[RATCHET_MLKEM_SK];         /* our ML-KEM ratchet keypair */
    unsigned char kem_pk[RATCHET_MLKEM_PK];
    unsigned char kem_r[RATCHET_MLKEM_PK];          /* peer's advertised ML-KEM key */
    unsigned char pend_ct[RATCHET_MLKEM_CT];        /* ct we advertise on full runs */
    unsigned char kss_send[RATCHET_MLKEM_SS];       /* KEM secret mixed into our sending chain */
    unsigned char kss_recv[RATCHET_MLKEM_SS];       /* KEM secret mixed into our receiving chain */

    skipped_key_t skipped[RATCHET_MAX_SKIP];
    size_t n_skipped;
};

size_t ratchet_hdr_size(const ratchet_session_t *s) {
    return (s && s->pq) ? RATCHET_PQ_HDR_SIZE : RATCHET_HDR_SIZE;
}

/* Generate a fresh ML-KEM ratchet keypair into the session. */
static crypto_error_t kem_keygen(ratchet_session_t *s) {
    OQS_KEM *kem = kem_new();
    if (!kem) return CRYPTO_ERR_CRYPTO;
    crypto_error_t rc = CRYPTO_ERR_CRYPTO;
    if (kem->length_public_key == RATCHET_MLKEM_PK &&
        kem->length_secret_key == RATCHET_MLKEM_SK &&
        kem->length_ciphertext == RATCHET_MLKEM_CT &&
        kem->length_shared_secret == RATCHET_MLKEM_SS &&
        OQS_KEM_keypair(kem, s->kem_pk, s->kem_sk) == OQS_SUCCESS)
        rc = CRYPTO_SUCCESS;
    OQS_KEM_free(kem);
    return rc;
}

/* --- key schedule (SPEC.md §3) --- */

/* KDF_RK: (rk, dh_out [‖ kem_ss]) -> (rk', ck). HKDF over the DH output, optionally
 * with an ML-KEM shared secret appended (continuous PQ ratchet), salted by rk.
 * With kem_ss == NULL the ikm is exactly dh_out, so the classical output is
 * byte-identical — mixing extra HKDF entropy can only strengthen it. */
static crypto_error_t kdf_rk(const unsigned char rk[AES_KEY_SIZE],
                             const unsigned char dh_out[X25519_KEY_SIZE],
                             const unsigned char *kem_ss, size_t kem_ss_len,
                             unsigned char rk_out[AES_KEY_SIZE],
                             unsigned char ck_out[AES_KEY_SIZE]) {
    unsigned char ikm[X25519_KEY_SIZE + RATCHET_MLKEM_SS];
    memcpy(ikm, dh_out, X25519_KEY_SIZE);
    if (kem_ss && kem_ss_len) memcpy(ikm + X25519_KEY_SIZE, kem_ss, kem_ss_len);
    size_t ikm_len = X25519_KEY_SIZE + (kem_ss ? kem_ss_len : 0);

    unsigned char okm[2 * AES_KEY_SIZE];
    crypto_error_t rc = crypto_hkdf_sha256(ikm, ikm_len,
                                           rk, AES_KEY_SIZE,
                                           (const unsigned char *)RATCHET_LABEL_RK,
                                           strlen(RATCHET_LABEL_RK),
                                           okm, sizeof okm);
    secure_zero(ikm, sizeof ikm);
    if (rc != CRYPTO_SUCCESS) return rc;
    memcpy(rk_out, okm, AES_KEY_SIZE);
    memcpy(ck_out, okm + AES_KEY_SIZE, AES_KEY_SIZE);
    secure_zero(okm, sizeof okm);
    return CRYPTO_SUCCESS;
}

/* KDF_CK: ck -> (ck', mk). Two independent HKDF expansions of the same chain key
 * under distinct info labels. */
static crypto_error_t kdf_ck(const unsigned char ck[AES_KEY_SIZE],
                             unsigned char ck_out[AES_KEY_SIZE],
                             unsigned char mk_out[AES_KEY_SIZE]) {
    crypto_error_t rc = crypto_hkdf_sha256(ck, AES_KEY_SIZE, NULL, 0,
                                           (const unsigned char *)RATCHET_LABEL_CK_MSG,
                                           strlen(RATCHET_LABEL_CK_MSG),
                                           mk_out, AES_KEY_SIZE);
    if (rc != CRYPTO_SUCCESS) return rc;
    /* ck_out may alias ck; compute after mk so we do not clobber the input. */
    return crypto_hkdf_sha256(ck, AES_KEY_SIZE, NULL, 0,
                              (const unsigned char *)RATCHET_LABEL_CK_NEXT,
                              strlen(RATCHET_LABEL_CK_NEXT),
                              ck_out, AES_KEY_SIZE);
}

/* --- wire header (SPEC.md §3.1) --- */

static void hdr_build(unsigned char *hdr, unsigned char type,
                      const unsigned char dh_pub[X25519_KEY_SIZE],
                      uint32_t pn, uint32_t n) {
    hdr[0] = 1;                 /* ver */
    hdr[1] = type;             /* 0x02 classical, 0x03 PQ */
    memcpy(hdr + 2, dh_pub, X25519_KEY_SIZE);
    unsigned char *p = hdr + 2 + X25519_KEY_SIZE;
    p[0] = (unsigned char)(pn >> 24); p[1] = (unsigned char)(pn >> 16);
    p[2] = (unsigned char)(pn >> 8);  p[3] = (unsigned char)pn;
    p[4] = (unsigned char)(n >> 24);  p[5] = (unsigned char)(n >> 16);
    p[6] = (unsigned char)(n >> 8);   p[7] = (unsigned char)n;
}

static void hdr_parse(const unsigned char hdr[RATCHET_HDR_SIZE],
                      unsigned char dh_pub[X25519_KEY_SIZE],
                      uint32_t *pn, uint32_t *n) {
    memcpy(dh_pub, hdr + 2, X25519_KEY_SIZE);
    const unsigned char *p = hdr + 2 + X25519_KEY_SIZE;
    *pn = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
    *n  = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) | ((uint32_t)p[6] << 8) | p[7];
}

/* --- init --- */

crypto_error_t ratchet_init_initiator(const unsigned char sk[AES_KEY_SIZE],
                                      const unsigned char peer_dh_pub[X25519_KEY_SIZE],
                                      ratchet_session_t **out) {
    if (!sk || !peer_dh_pub || !out) return CRYPTO_ERR_INVALID_INPUT;
    ratchet_session_t *s = calloc(1, sizeof *s);
    if (!s) return CRYPTO_ERR_MEMORY;

    crypto_error_t rc = crypto_x25519_keypair(s->dhs_sec, s->dhs_pub);
    if (rc != CRYPTO_SUCCESS) goto fail;
    memcpy(s->dhr, peer_dh_pub, X25519_KEY_SIZE);
    s->have_dhr = 1;

    unsigned char dh_out[X25519_KEY_SIZE];
    rc = crypto_x25519_dh(s->dhs_sec, s->dhr, dh_out);
    if (rc != CRYPTO_SUCCESS) goto fail;
    rc = kdf_rk(sk, dh_out, NULL, 0, s->rk, s->cks);   /* bootstrap: no KEM secret yet */
    secure_zero(dh_out, sizeof dh_out);
    if (rc != CRYPTO_SUCCESS) goto fail;
    s->have_cks = 1;

    *out = s;
    return CRYPTO_SUCCESS;
fail:
    ratchet_session_free(s);
    return rc;
}

crypto_error_t ratchet_init_responder(const unsigned char sk[AES_KEY_SIZE],
                                       const unsigned char self_dh_pub[X25519_KEY_SIZE],
                                       const unsigned char self_dh_sec[X25519_KEY_SIZE],
                                       ratchet_session_t **out) {
    if (!sk || !self_dh_pub || !self_dh_sec || !out) return CRYPTO_ERR_INVALID_INPUT;
    ratchet_session_t *s = calloc(1, sizeof *s);
    if (!s) return CRYPTO_ERR_MEMORY;

    memcpy(s->dhs_sec, self_dh_sec, X25519_KEY_SIZE);
    memcpy(s->dhs_pub, self_dh_pub, X25519_KEY_SIZE);
    memcpy(s->rk, sk, AES_KEY_SIZE);
    /* DHr, CKs, CKr unset until the first inbound message triggers a DH ratchet. */
    *out = s;
    return CRYPTO_SUCCESS;
}

crypto_error_t ratchet_pq_init_initiator(const unsigned char sk[AES_KEY_SIZE],
                                         const unsigned char peer_dh_pub[X25519_KEY_SIZE],
                                         ratchet_session_t **out) {
    crypto_error_t rc = ratchet_init_initiator(sk, peer_dh_pub, out);
    if (rc != CRYPTO_SUCCESS) return rc;
    (*out)->pq = 1;
    /* The initiator's first message must advertise its ML-KEM key (0x03), even
     * though it can't encapsulate yet (no peer key). The initial sending chain
     * has no KEM secret — same as bootstrap in the per-step design. */
    (*out)->send_full = 1;
    (*out)->advertised = 1;
    rc = kem_keygen(*out);
    if (rc != CRYPTO_SUCCESS) { ratchet_session_free(*out); *out = NULL; }
    return rc;
}

crypto_error_t ratchet_pq_init_responder(const unsigned char sk[AES_KEY_SIZE],
                                          const unsigned char self_dh_pub[X25519_KEY_SIZE],
                                          const unsigned char self_dh_sec[X25519_KEY_SIZE],
                                          ratchet_session_t **out) {
    crypto_error_t rc = ratchet_init_responder(sk, self_dh_pub, self_dh_sec, out);
    if (rc != CRYPTO_SUCCESS) return rc;
    (*out)->pq = 1;
    rc = kem_keygen(*out);
    if (rc != CRYPTO_SUCCESS) { ratchet_session_free(*out); *out = NULL; }
    return rc;
}

/* --- skipped-key store --- */

static skipped_key_t *skipped_find(ratchet_session_t *s,
                                   const unsigned char dh_pub[X25519_KEY_SIZE], uint32_t n) {
    for (size_t i = 0; i < s->n_skipped; i++)
        if (s->skipped[i].n == n && memcmp(s->skipped[i].dh_pub, dh_pub, X25519_KEY_SIZE) == 0)
            return &s->skipped[i];
    return NULL;
}

static void skipped_remove(ratchet_session_t *s, skipped_key_t *e) {
    size_t i = (size_t)(e - s->skipped);
    secure_zero(e, sizeof *e);
    if (i + 1 < s->n_skipped)
        memmove(&s->skipped[i], &s->skipped[i + 1], (s->n_skipped - i - 1) * sizeof *e);
    s->n_skipped--;
}

/* Advance the receiving chain, stashing message keys, until Nr == until. */
static crypto_error_t skip_message_keys(ratchet_session_t *s, uint32_t until) {
    if (!s->have_ckr) return CRYPTO_SUCCESS;
    if (until < s->nr) return CRYPTO_ERR_INTEGRITY;             /* replay / rewind */
    if ((uint64_t)until - s->nr > RATCHET_MAX_SKIP ||
        s->n_skipped + (until - s->nr) > RATCHET_MAX_SKIP)
        return CRYPTO_ERR_INVALID_INPUT;                        /* DoS guard */
    while (s->nr < until) {
        skipped_key_t *e = &s->skipped[s->n_skipped];
        memcpy(e->dh_pub, s->dhr, X25519_KEY_SIZE);
        e->n = s->nr;
        crypto_error_t rc = kdf_ck(s->ckr, s->ckr, e->mk);
        if (rc != CRYPTO_SUCCESS) return rc;
        s->n_skipped++;
        s->nr++;
    }
    return CRYPTO_SUCCESS;
}

/* DH (+ periodic ML-KEM) ratchet step. `msg_full` says the received message was a
 * PQ-full (0x03) message carrying the peer's kem_pk and (if in_have_ct) a
 * ciphertext to our current key; a lite (0x04) message carries none and reuses the
 * last KEM secret. Receiving mixes kss_recv (refreshed by decapsulation on a full
 * message); sending mixes kss_send (refreshed by re-encapsulation on our own
 * rotation steps, every RATCHET_KEM_EVERY steps). See PQ_RATCHET_PERIODIC.md. */
static crypto_error_t dh_ratchet(ratchet_session_t *s, const unsigned char new_dhr[X25519_KEY_SIZE],
                                 int msg_full, const unsigned char *in_kem_pk, int in_have_ct,
                                 const unsigned char *in_kem_ct) {
    s->pn = s->ns;
    s->ns = 0;
    s->nr = 0;
    memcpy(s->dhr, new_dhr, X25519_KEY_SIZE);
    s->have_dhr = 1;

    unsigned char dh_out[X25519_KEY_SIZE];
    OQS_KEM *kem = NULL;
    crypto_error_t rc;

    /* --- receiving chain --- */
    if (s->pq && msg_full) {
        memcpy(s->kem_r, in_kem_pk, RATCHET_MLKEM_PK);   /* learn/refresh peer's key */
        s->have_kem_r = 1;
        if (in_have_ct) {
            kem = kem_new();
            if (!kem) { rc = CRYPTO_ERR_CRYPTO; goto out; }
            if (OQS_KEM_decaps(kem, s->kss_recv, in_kem_ct, s->kem_sk) != OQS_SUCCESS) { rc = CRYPTO_ERR_CRYPTO; goto out; }
            OQS_KEM_free(kem); kem = NULL;
            s->have_kss_recv = 1;
        }
    }
    rc = crypto_x25519_dh(s->dhs_sec, s->dhr, dh_out);
    if (rc != CRYPTO_SUCCESS) goto out;
    rc = kdf_rk(s->rk, dh_out,
                s->have_kss_recv ? s->kss_recv : NULL, s->have_kss_recv ? RATCHET_MLKEM_SS : 0,
                s->rk, s->ckr);
    if (rc != CRYPTO_SUCCESS) goto out;
    s->have_ckr = 1;

    /* rotate our DH keypair (every step) */
    rc = crypto_x25519_keypair(s->dhs_sec, s->dhs_pub);
    if (rc != CRYPTO_SUCCESS) goto out;

    /* --- sending chain: decide our KEM rotation by cadence --- */
    if (s->pq) {
        s->send_steps++;
        int rotate = (s->send_steps % RATCHET_KEM_EVERY == 0);
        int must_advertise = !s->advertised;
        if (rotate) {                                    /* new ML-KEM keypair to advertise */
            rc = kem_keygen(s);
            if (rc != CRYPTO_SUCCESS) goto out;
        }
        s->send_full = (rotate || must_advertise) ? 1 : 0;
        s->have_ct = 0;
        if (s->send_full) {
            s->advertised = 1;
            if (s->have_kem_r) {                         /* encapsulate a fresh secret to the peer */
                kem = kem_new();
                if (!kem) { rc = CRYPTO_ERR_CRYPTO; goto out; }
                if (OQS_KEM_encaps(kem, s->pend_ct, s->kss_send, s->kem_r) != OQS_SUCCESS) { rc = CRYPTO_ERR_CRYPTO; goto out; }
                OQS_KEM_free(kem); kem = NULL;
                s->have_kss_send = 1;
                s->have_ct = 1;
            }
        }
    }
    rc = crypto_x25519_dh(s->dhs_sec, s->dhr, dh_out);
    if (rc != CRYPTO_SUCCESS) goto out;
    rc = kdf_rk(s->rk, dh_out,
                s->have_kss_send ? s->kss_send : NULL, s->have_kss_send ? RATCHET_MLKEM_SS : 0,
                s->rk, s->cks);
    if (rc != CRYPTO_SUCCESS) goto out;
    s->have_cks = 1;
    rc = CRYPTO_SUCCESS;
out:
    if (kem) OQS_KEM_free(kem);
    secure_zero(dh_out, sizeof dh_out);
    return rc;
}

/* --- messaging --- */

crypto_error_t ratchet_encrypt(ratchet_session_t *s,
                               const unsigned char *pt, size_t pt_len,
                               unsigned char *hdr,
                               unsigned char *out, size_t *out_len) {
    if (!s || (!pt && pt_len) || !hdr || !out || !out_len) return CRYPTO_ERR_INVALID_INPUT;
    if (!s->have_cks) return CRYPTO_ERR_INVALID_INPUT;         /* cannot send yet */
    if (pt_len > INT32_MAX) return CRYPTO_ERR_INVALID_INPUT;

    unsigned char mk[AES_KEY_SIZE];
    crypto_error_t rc = kdf_ck(s->cks, s->cks, mk);
    if (rc != CRYPTO_SUCCESS) return rc;

    unsigned char type = !s->pq ? RATCHET_TYPE_CLASSICAL
                                : (s->send_full ? RATCHET_TYPE_PQ_FULL : RATCHET_TYPE_PQ_LITE);
    size_t hlen = (type == RATCHET_TYPE_PQ_FULL) ? RATCHET_PQ_HDR_SIZE : RATCHET_HDR_SIZE;
    hdr_build(hdr, type, s->dhs_pub, s->pn, s->ns);
    if (type == RATCHET_TYPE_PQ_FULL) {
        unsigned char *p = hdr + RATCHET_HDR_SIZE;
        memcpy(p, s->kem_pk, RATCHET_MLKEM_PK);          p += RATCHET_MLKEM_PK;
        *p++ = (unsigned char)(s->have_ct ? 1 : 0);
        if (s->have_ct) memcpy(p, s->pend_ct, RATCHET_MLKEM_CT);
        else            memset(p, 0, RATCHET_MLKEM_CT);
    }

    unsigned char nonce[AES_GCM_NONCE_SIZE];
    crypto_frame_nonce(s->ns, 0, nonce);

    unsigned char tag[AES_GCM_TAG_SIZE];
    int ok = crypto_gcm_seal_aad(mk, nonce, hdr, (size_t)hlen,
                                 pt, (int)pt_len, out, tag);
    secure_zero(mk, sizeof mk);
    if (!ok) return CRYPTO_ERR_CRYPTO;
    memcpy(out + pt_len, tag, AES_GCM_TAG_SIZE);
    *out_len = pt_len + AES_GCM_TAG_SIZE;
    s->ns++;
    return CRYPTO_SUCCESS;
}

/* Open ct+tag under mk with the whole header (aad_len bytes) as AAD. */
static crypto_error_t open_with_mk(const unsigned char mk[AES_KEY_SIZE], uint32_t n,
                                   const unsigned char *hdr, size_t aad_len,
                                   const unsigned char *ct, size_t ct_len,
                                   unsigned char *out, size_t *out_len) {
    if (ct_len < AES_GCM_TAG_SIZE) return CRYPTO_ERR_INVALID_INPUT;
    size_t body = ct_len - AES_GCM_TAG_SIZE;
    unsigned char nonce[AES_GCM_NONCE_SIZE];
    crypto_frame_nonce(n, 0, nonce);
    int ok = crypto_gcm_open_aad(mk, nonce, hdr, aad_len,
                                 ct, (int)body, ct + body, out);
    if (!ok) return CRYPTO_ERR_INTEGRITY;
    *out_len = body;
    return CRYPTO_SUCCESS;
}

crypto_error_t ratchet_decrypt(ratchet_session_t *s,
                               const unsigned char *hdr,
                               const unsigned char *ct, size_t ct_len,
                               unsigned char *out, size_t *out_len) {
    if (!s || !hdr || !ct || !out || !out_len) return CRYPTO_ERR_INVALID_INPUT;
    if (hdr[0] != 1) return CRYPTO_ERR_INVALID_INPUT;
    if (s->pq) { if (hdr[1] != RATCHET_TYPE_PQ_FULL && hdr[1] != RATCHET_TYPE_PQ_LITE) return CRYPTO_ERR_INVALID_INPUT; }
    else       { if (hdr[1] != RATCHET_TYPE_CLASSICAL) return CRYPTO_ERR_INVALID_INPUT; }
    size_t hlen = ratchet_hdr_size_of(hdr);

    /* Transactional decrypt: all state changes (DH/KEM ratchet step, skipped-key
     * advances/removals) happen on a working copy and are committed to *s ONLY
     * after the AEAD tag authenticates. Otherwise an injected/forged message
     * with a novel ratchet key would mutate live state before failing the tag,
     * letting a single packet desync the ratchet permanently (DoS). This also
     * makes a tampered PQ header (kem_pk/kem_ct/have_ct — all AAD) safe: a bad
     * KEM step yields a wrong key, the tag fails, and nothing commits. */
    ratchet_session_t *w = malloc(sizeof *w);
    if (!w) return CRYPTO_ERR_MEMORY;
    memcpy(w, s, sizeof *w);

    unsigned char dh[X25519_KEY_SIZE];
    unsigned char mk[AES_KEY_SIZE];
    uint32_t pn, n;
    crypto_error_t rc;
    hdr_parse(hdr, dh, &pn, &n);

    int msg_full = (hdr[1] == RATCHET_TYPE_PQ_FULL);
    const unsigned char *in_kem_pk = NULL, *in_kem_ct = NULL; int in_have_ct = 0;
    if (msg_full) {
        in_kem_pk  = hdr + RATCHET_HDR_SIZE;
        in_have_ct = hdr[RATCHET_HDR_SIZE + RATCHET_MLKEM_PK];
        in_kem_ct  = hdr + RATCHET_HDR_SIZE + RATCHET_MLKEM_PK + 1;
    }

    /* 1. A stashed skipped key for exactly this (ratchet key, index)? */
    skipped_key_t *e = skipped_find(w, dh, n);
    if (e) {
        memcpy(mk, e->mk, AES_KEY_SIZE);
        rc = open_with_mk(mk, n, hdr, hlen, ct, ct_len, out, out_len);
        if (rc == CRYPTO_SUCCESS) { skipped_remove(w, e); memcpy(s, w, sizeof *w); }
        goto done;
    }

    /* 2. New ratchet key -> skip remainder of current chain, then step ratchet. */
    if (!w->have_dhr || memcmp(dh, w->dhr, X25519_KEY_SIZE) != 0) {
        rc = skip_message_keys(w, pn);
        if (rc != CRYPTO_SUCCESS) goto done;
        rc = dh_ratchet(w, dh, msg_full, in_kem_pk, in_have_ct, in_kem_ct);
        if (rc != CRYPTO_SUCCESS) goto done;
    }

    /* 3. Skip within the current receiving chain up to n. */
    rc = skip_message_keys(w, n);
    if (rc != CRYPTO_SUCCESS) goto done;
    if (!w->have_ckr) { rc = CRYPTO_ERR_INTEGRITY; goto done; }

    /* 4. Derive this message's key and open; commit only if it authenticates. */
    rc = kdf_ck(w->ckr, w->ckr, mk);
    if (rc != CRYPTO_SUCCESS) goto done;
    rc = open_with_mk(mk, n, hdr, hlen, ct, ct_len, out, out_len);
    if (rc != CRYPTO_SUCCESS) goto done;
    w->nr++;
    memcpy(s, w, sizeof *w);   /* commit */

done:
    secure_zero(mk, sizeof mk);
    secure_zero(w, sizeof *w);
    free(w);
    return rc;
}

/* --- state at rest (SPEC.md §7) ---
 * Layout on disk: salt(16) | nonce(12) | GCM_ct(plainlen) | tag(16).
 * The plaintext is the packed struct (fixed-size prefix + skipped entries). */

#define ST_FIXED (AES_KEY_SIZE + 2*X25519_KEY_SIZE + X25519_KEY_SIZE + 2*AES_KEY_SIZE \
                  + 3*4 + 3 + 4)   /* rk, dhs_sec+pub, dhr, cks, ckr, ns/nr/pn, flags, n_skipped */
/* Appended after the skipped entries: pq(1). If pq: 6 flag bytes + send_steps(4)
 * + kem_sk|kem_pk|kem_r|pend_ct|kss_send|kss_recv (= ST_KEM). */
#define ST_KEM (RATCHET_MLKEM_SK + RATCHET_MLKEM_PK + RATCHET_MLKEM_PK + RATCHET_MLKEM_CT \
                + 2*RATCHET_MLKEM_SS)
#define ST_PQ_META (6 + 4)   /* 6 flag bytes + send_steps u32 */
#define ST_SKIP_ENTRY (X25519_KEY_SIZE + 4 + AES_KEY_SIZE)

static void put_u32(unsigned char *p, uint32_t v) {
    p[0]=(unsigned char)(v>>24); p[1]=(unsigned char)(v>>16); p[2]=(unsigned char)(v>>8); p[3]=(unsigned char)v;
}
static uint32_t get_u32(const unsigned char *p) {
    return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];
}

static size_t pack(const ratchet_session_t *s, unsigned char *buf) {
    unsigned char *p = buf;
    memcpy(p, s->rk, AES_KEY_SIZE);           p += AES_KEY_SIZE;
    memcpy(p, s->dhs_sec, X25519_KEY_SIZE);   p += X25519_KEY_SIZE;
    memcpy(p, s->dhs_pub, X25519_KEY_SIZE);   p += X25519_KEY_SIZE;
    memcpy(p, s->dhr, X25519_KEY_SIZE);       p += X25519_KEY_SIZE;
    memcpy(p, s->cks, AES_KEY_SIZE);          p += AES_KEY_SIZE;
    memcpy(p, s->ckr, AES_KEY_SIZE);          p += AES_KEY_SIZE;
    put_u32(p, s->ns); p += 4;
    put_u32(p, s->nr); p += 4;
    put_u32(p, s->pn); p += 4;
    *p++ = (unsigned char)s->have_dhr;
    *p++ = (unsigned char)s->have_cks;
    *p++ = (unsigned char)s->have_ckr;
    put_u32(p, (uint32_t)s->n_skipped); p += 4;
    for (size_t i = 0; i < s->n_skipped; i++) {
        memcpy(p, s->skipped[i].dh_pub, X25519_KEY_SIZE); p += X25519_KEY_SIZE;
        put_u32(p, s->skipped[i].n); p += 4;
        memcpy(p, s->skipped[i].mk, AES_KEY_SIZE); p += AES_KEY_SIZE;
    }
    *p++ = (unsigned char)s->pq;
    if (s->pq) {
        *p++ = (unsigned char)s->have_kem_r;
        *p++ = (unsigned char)s->have_ct;
        *p++ = (unsigned char)s->have_kss_send;
        *p++ = (unsigned char)s->have_kss_recv;
        *p++ = (unsigned char)s->send_full;
        *p++ = (unsigned char)s->advertised;
        put_u32(p, s->send_steps); p += 4;
        memcpy(p, s->kem_sk, RATCHET_MLKEM_SK);   p += RATCHET_MLKEM_SK;
        memcpy(p, s->kem_pk, RATCHET_MLKEM_PK);   p += RATCHET_MLKEM_PK;
        memcpy(p, s->kem_r, RATCHET_MLKEM_PK);    p += RATCHET_MLKEM_PK;
        memcpy(p, s->pend_ct, RATCHET_MLKEM_CT);  p += RATCHET_MLKEM_CT;
        memcpy(p, s->kss_send, RATCHET_MLKEM_SS); p += RATCHET_MLKEM_SS;
        memcpy(p, s->kss_recv, RATCHET_MLKEM_SS); p += RATCHET_MLKEM_SS;
    }
    return (size_t)(p - buf);
}

static crypto_error_t unpack(ratchet_session_t *s, const unsigned char *buf, size_t len) {
    if (len < ST_FIXED) return CRYPTO_ERR_INTEGRITY;
    const unsigned char *p = buf;
    memcpy(s->rk, p, AES_KEY_SIZE);           p += AES_KEY_SIZE;
    memcpy(s->dhs_sec, p, X25519_KEY_SIZE);   p += X25519_KEY_SIZE;
    memcpy(s->dhs_pub, p, X25519_KEY_SIZE);   p += X25519_KEY_SIZE;
    memcpy(s->dhr, p, X25519_KEY_SIZE);       p += X25519_KEY_SIZE;
    memcpy(s->cks, p, AES_KEY_SIZE);          p += AES_KEY_SIZE;
    memcpy(s->ckr, p, AES_KEY_SIZE);          p += AES_KEY_SIZE;
    s->ns = get_u32(p); p += 4;
    s->nr = get_u32(p); p += 4;
    s->pn = get_u32(p); p += 4;
    s->have_dhr = *p++; s->have_cks = *p++; s->have_ckr = *p++;
    uint32_t nsk = get_u32(p); p += 4;
    if (nsk > RATCHET_MAX_SKIP) return CRYPTO_ERR_INTEGRITY;
    size_t base = ST_FIXED + (size_t)nsk * ST_SKIP_ENTRY;
    if (len < base + 1) return CRYPTO_ERR_INTEGRITY;         /* skipped entries + pq byte */
    for (uint32_t i = 0; i < nsk; i++) {
        memcpy(s->skipped[i].dh_pub, p, X25519_KEY_SIZE); p += X25519_KEY_SIZE;
        s->skipped[i].n = get_u32(p); p += 4;
        memcpy(s->skipped[i].mk, p, AES_KEY_SIZE); p += AES_KEY_SIZE;
    }
    s->n_skipped = nsk;

    s->pq = *p++;
    if (s->pq) {
        if (len != base + 1 + ST_PQ_META + ST_KEM) return CRYPTO_ERR_INTEGRITY;
        s->have_kem_r = *p++;
        s->have_ct = *p++;
        s->have_kss_send = *p++;
        s->have_kss_recv = *p++;
        s->send_full = *p++;
        s->advertised = *p++;
        s->send_steps = get_u32(p); p += 4;
        memcpy(s->kem_sk, p, RATCHET_MLKEM_SK);   p += RATCHET_MLKEM_SK;
        memcpy(s->kem_pk, p, RATCHET_MLKEM_PK);   p += RATCHET_MLKEM_PK;
        memcpy(s->kem_r, p, RATCHET_MLKEM_PK);    p += RATCHET_MLKEM_PK;
        memcpy(s->pend_ct, p, RATCHET_MLKEM_CT);  p += RATCHET_MLKEM_CT;
        memcpy(s->kss_send, p, RATCHET_MLKEM_SS); p += RATCHET_MLKEM_SS;
        memcpy(s->kss_recv, p, RATCHET_MLKEM_SS); p += RATCHET_MLKEM_SS;
    } else {
        if (len != base + 1) return CRYPTO_ERR_INTEGRITY;
    }
    return CRYPTO_SUCCESS;
}

crypto_error_t ratchet_session_serialize(const ratchet_session_t *s,
                                         const char *passphrase,
                                         unsigned char **blob, size_t *blob_len) {
    if (!s || !passphrase || !blob || !blob_len) return CRYPTO_ERR_INVALID_INPUT;
    size_t plain_len = ST_FIXED + s->n_skipped * ST_SKIP_ENTRY + 1 + (s->pq ? ST_PQ_META + ST_KEM : 0);
    unsigned char *plain = malloc(plain_len);
    if (!plain) return CRYPTO_ERR_MEMORY;
    pack(s, plain);

    size_t total = KDF_SALT_SIZE + AES_GCM_NONCE_SIZE + plain_len + AES_GCM_TAG_SIZE;
    unsigned char *b = malloc(total);
    if (!b) { secure_zero(plain, plain_len); free(plain); return CRYPTO_ERR_MEMORY; }

    crypto_error_t rc = CRYPTO_ERR_CRYPTO;
    unsigned char key[AES_KEY_SIZE];
    if (RAND_bytes(b, KDF_SALT_SIZE) != 1 ||
        RAND_bytes(b + KDF_SALT_SIZE, AES_GCM_NONCE_SIZE) != 1) goto done;
    if (crypto_derive_key_argon2id(passphrase, b, 65536, 3, 1, key) != CRYPTO_SUCCESS) goto done;

    unsigned char *ct = b + KDF_SALT_SIZE + AES_GCM_NONCE_SIZE;
    unsigned char tag[AES_GCM_TAG_SIZE];
    if (!crypto_gcm_seal_aad(key, b + KDF_SALT_SIZE, NULL, 0,
                             plain, (int)plain_len, ct, tag)) goto done;
    memcpy(ct + plain_len, tag, AES_GCM_TAG_SIZE);
    *blob = b; *blob_len = total; b = NULL;
    rc = CRYPTO_SUCCESS;
done:
    secure_zero(key, sizeof key);
    secure_zero(plain, plain_len);
    free(plain);
    if (b) free(b);
    return rc;
}

crypto_error_t ratchet_session_deserialize(const unsigned char *blob, size_t blob_len,
                                           const char *passphrase,
                                           ratchet_session_t **out) {
    if (!blob || !passphrase || !out) return CRYPTO_ERR_INVALID_INPUT;
    size_t hdr = KDF_SALT_SIZE + AES_GCM_NONCE_SIZE;
    if (blob_len < hdr + AES_GCM_TAG_SIZE) return CRYPTO_ERR_INTEGRITY;
    size_t plain_len = blob_len - hdr - AES_GCM_TAG_SIZE;

    unsigned char key[AES_KEY_SIZE];
    if (crypto_derive_key_argon2id(passphrase, blob, 65536, 3, 1, key) != CRYPTO_SUCCESS)
        return CRYPTO_ERR_CRYPTO;

    unsigned char *plain = malloc(plain_len ? plain_len : 1);
    if (!plain) { secure_zero(key, sizeof key); return CRYPTO_ERR_MEMORY; }

    const unsigned char *ct = blob + hdr;
    int ok = crypto_gcm_open_aad(key, blob + KDF_SALT_SIZE, NULL, 0,
                                 ct, (int)plain_len, ct + plain_len, plain);
    secure_zero(key, sizeof key);
    crypto_error_t rc;
    if (!ok) { rc = CRYPTO_ERR_INTEGRITY; goto done; }

    ratchet_session_t *s = calloc(1, sizeof *s);
    if (!s) { rc = CRYPTO_ERR_MEMORY; goto done; }
    rc = unpack(s, plain, plain_len);
    if (rc != CRYPTO_SUCCESS) { ratchet_session_free(s); goto done; }
    *out = s;
done:
    secure_zero(plain, plain_len);
    free(plain);
    return rc;
}

void ratchet_session_free(ratchet_session_t *s) {
    if (!s) return;
    secure_zero(s, sizeof *s);
    free(s);
}
