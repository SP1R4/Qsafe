/* PQXDH handshake — see include/pqxdh.h and veil/docs/SPEC.md §2.
 *
 * Clean PQXDH: four X25519 legs + one independent ML-KEM-1024 leg, concatenated
 * once into HKDF-SHA256 to produce the ratchet's seed secret SK. Prekeys and the
 * opening message are ML-DSA-87 signed; verification is fail-closed. */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <oqs/oqs.h>

#include "pqxdh.h"
#include "ratchet.h"
#include "crypto_utils.h"

static void secure_zero(void *p, size_t n) { OPENSSL_cleanse(p, n); }

static OQS_KEM *kem_new(void) { return OQS_KEM_new(OQS_KEM_alg_ml_kem_1024); }

/* Sign msg with a domain-separation label prefix, into sig/sig_len. */
static crypto_error_t sign_labeled(const char *label,
                                   const unsigned char *msg, size_t msg_len,
                                   const unsigned char sk[QSAFE_SIG_SEC_SIZE],
                                   unsigned char *sig, size_t *sig_len) {
    size_t llen = strlen(label);
    unsigned char *buf = malloc(llen + msg_len);
    if (!buf) return CRYPTO_ERR_MEMORY;
    memcpy(buf, label, llen);
    memcpy(buf + llen, msg, msg_len);
    crypto_error_t rc = crypto_sig_sign_buf(buf, llen + msg_len, sk, sig, sig_len);
    free(buf);
    return rc;
}

static crypto_error_t verify_labeled(const char *label,
                                     const unsigned char *msg, size_t msg_len,
                                     const unsigned char *sig, size_t sig_len,
                                     const unsigned char pk[QSAFE_SIG_PUB_SIZE]) {
    size_t llen = strlen(label);
    unsigned char *buf = malloc(llen + msg_len);
    if (!buf) return CRYPTO_ERR_MEMORY;
    memcpy(buf, label, llen);
    memcpy(buf + llen, msg, msg_len);
    crypto_error_t rc = crypto_sig_verify_buf(buf, llen + msg_len, sig, sig_len, pk);
    free(buf);
    return rc;
}

/* Canonical bytes of the opening message that IK_sig_A signs (SPEC §2.5):
 * ik_sig_pk | ik_dh_pk | ek_pk | pq_ct | used_opk(1). */
static size_t initial_signed_bytes(const pqxdh_initial_t *m, unsigned char *buf) {
    unsigned char *p = buf;
    memcpy(p, m->ik_sig_pk, QSAFE_SIG_PUB_SIZE); p += QSAFE_SIG_PUB_SIZE;
    memcpy(p, m->ik_dh_pk, X25519_KEY_SIZE);     p += X25519_KEY_SIZE;
    memcpy(p, m->ek_pk, X25519_KEY_SIZE);        p += X25519_KEY_SIZE;
    memcpy(p, m->pq_ct, PQXDH_MLKEM_CT);         p += PQXDH_MLKEM_CT;
    uint64_t v = (uint64_t)m->opk_id;
    for (int i = 7; i >= 0; i--) *p++ = (unsigned char)(v >> (8 * i));
    *p++ = (unsigned char)(m->pq ? 1 : 0);       /* PQ-ratchet intent, signed (no downgrade) */
    return (size_t)(p - buf);
}
#define INITIAL_SIGNED_LEN (QSAFE_SIG_PUB_SIZE + 2*X25519_KEY_SIZE + PQXDH_MLKEM_CT + 8 + 1)

/* Canonical signed bytes of one OPK entry: LABEL is applied by sign/verify_labeled;
 * here we build (u32 opk_id || opk_pk). */
static size_t opk_signed_bytes(uint32_t opk_id, const unsigned char opk_pk[X25519_KEY_SIZE],
                               unsigned char buf[4 + X25519_KEY_SIZE]) {
    buf[0]=(unsigned char)(opk_id>>24);buf[1]=(unsigned char)(opk_id>>16);
    buf[2]=(unsigned char)(opk_id>>8); buf[3]=(unsigned char)opk_id;
    memcpy(buf + 4, opk_pk, X25519_KEY_SIZE);
    return 4 + X25519_KEY_SIZE;
}

/* HKDF the concatenated legs (+ PQ secret) into the 32-byte session seed. */
static crypto_error_t derive_sk(const unsigned char *legs, size_t legs_len,
                                unsigned char sk[AES_KEY_SIZE]) {
    return crypto_hkdf_sha256(legs, legs_len, NULL, 0,
                              (const unsigned char *)PQXDH_LABEL_SK, strlen(PQXDH_LABEL_SK),
                              sk, AES_KEY_SIZE);
}

crypto_error_t pqxdh_identity_generate(pqxdh_identity_t *id) {
    if (!id) return CRYPTO_ERR_INVALID_INPUT;
    memset(id, 0, sizeof *id);
    crypto_error_t rc;
    if ((rc = crypto_sig_keypair_raw(id->ik_sig_pk, id->ik_sig_sk)) != CRYPTO_SUCCESS) return rc;
    if ((rc = crypto_x25519_keypair(id->ik_dh_sk, id->ik_dh_pk)) != CRYPTO_SUCCESS) return rc;
    if ((rc = crypto_x25519_keypair(id->spk_sk, id->spk_pk)) != CRYPTO_SUCCESS) return rc;
    for (uint32_t i = 0; i < PQXDH_OPK_POOL; i++) {
        if ((rc = crypto_x25519_keypair(id->opk_sk[i], id->opk_pk[i])) != CRYPTO_SUCCESS) return rc;
        unsigned char idb[4];
        if (RAND_bytes(idb, 4) != 1) return CRYPTO_ERR_CRYPTO;
        id->opk_id[i] = ((uint32_t)idb[0]<<24)|((uint32_t)idb[1]<<16)|((uint32_t)idb[2]<<8)|idb[3];
    }
    id->n_opk = PQXDH_OPK_POOL;

    OQS_KEM *kem = kem_new();
    if (!kem) return CRYPTO_ERR_CRYPTO;
    rc = CRYPTO_ERR_CRYPTO;
    if (kem->length_public_key == PQXDH_MLKEM_PUB &&
        kem->length_secret_key == PQXDH_MLKEM_SEC &&
        OQS_KEM_keypair(kem, id->pqk_pk, id->pqk_sk) == OQS_SUCCESS)
        rc = CRYPTO_SUCCESS;
    OQS_KEM_free(kem);
    return rc;
}

void pqxdh_identity_free(pqxdh_identity_t *id) {
    if (!id) return;
    secure_zero(id, sizeof *id);
}

crypto_error_t pqxdh_identity_serialize(const pqxdh_identity_t *id, const char *passphrase,
                                        unsigned char **blob, size_t *blob_len) {
    if (!id || !passphrase || !blob || !blob_len) return CRYPTO_ERR_INVALID_INPUT;
    /* The identity is fixed-size POD (no pointers); seal its raw bytes at rest.
     * The file is device-local, so struct layout stability is not a concern. */
    return crypto_seal_at_rest(passphrase, (const unsigned char *)id, sizeof *id, blob, blob_len);
}

crypto_error_t pqxdh_identity_deserialize(const unsigned char *blob, size_t blob_len,
                                          const char *passphrase, pqxdh_identity_t *out) {
    if (!blob || !passphrase || !out) return CRYPTO_ERR_INVALID_INPUT;
    unsigned char *pt = NULL; size_t pt_len = 0;
    crypto_error_t rc = crypto_open_at_rest(passphrase, blob, blob_len, &pt, &pt_len);
    if (rc != CRYPTO_SUCCESS) return rc;
    if (pt_len != sizeof *out) { secure_zero(pt, pt_len); free(pt); return CRYPTO_ERR_INTEGRITY; }
    memcpy(out, pt, sizeof *out);
    secure_zero(pt, pt_len);
    free(pt);
    return CRYPTO_SUCCESS;
}

crypto_error_t pqxdh_publish_bundle(const pqxdh_identity_t *id, pqxdh_bundle_t *out) {
    if (!id || !out) return CRYPTO_ERR_INVALID_INPUT;
    memset(out, 0, sizeof *out);
    memcpy(out->ik_sig_pk, id->ik_sig_pk, QSAFE_SIG_PUB_SIZE);
    memcpy(out->ik_dh_pk, id->ik_dh_pk, X25519_KEY_SIZE);
    memcpy(out->spk_pk, id->spk_pk, X25519_KEY_SIZE);
    memcpy(out->pqk_pk, id->pqk_pk, PQXDH_MLKEM_PUB);
    out->have_opk = 0;   /* one-time prekeys are published separately, one per fetch */

    crypto_error_t rc = sign_labeled(PQXDH_LABEL_SPK, id->spk_pk, X25519_KEY_SIZE,
                                     id->ik_sig_sk, out->spk_sig, &out->spk_sig_len);
    if (rc != CRYPTO_SUCCESS) return rc;
    return sign_labeled(PQXDH_LABEL_PQK, id->pqk_pk, PQXDH_MLKEM_PUB,
                        id->ik_sig_sk, out->pqk_sig, &out->pqk_sig_len);
}

crypto_error_t pqxdh_opk_public(const pqxdh_identity_t *id, uint32_t index,
                                uint32_t *opk_id, unsigned char opk_pk[X25519_KEY_SIZE],
                                unsigned char *opk_sig, size_t *opk_sig_len) {
    if (!id || index >= id->n_opk || !opk_id || !opk_pk || !opk_sig || !opk_sig_len)
        return CRYPTO_ERR_INVALID_INPUT;
    *opk_id = id->opk_id[index];
    memcpy(opk_pk, id->opk_pk[index], X25519_KEY_SIZE);
    unsigned char m[4 + X25519_KEY_SIZE];
    opk_signed_bytes(*opk_id, opk_pk, m);
    return sign_labeled(PQXDH_LABEL_OPK, m, sizeof m, id->ik_sig_sk, opk_sig, opk_sig_len);
}

crypto_error_t pqxdh_initiator(const pqxdh_identity_t *self, const pqxdh_bundle_t *peer,
                               int pq, pqxdh_initial_t *msg_out, ratchet_session_t **session_out) {
    if (!self || !peer || !msg_out || !session_out) return CRYPTO_ERR_INVALID_INPUT;

    /* Verify the peer's prekey signatures before using them (fail closed). */
    crypto_error_t rc = verify_labeled(PQXDH_LABEL_SPK, peer->spk_pk, X25519_KEY_SIZE,
                                       peer->spk_sig, peer->spk_sig_len, peer->ik_sig_pk);
    if (rc != CRYPTO_SUCCESS) return rc;
    rc = verify_labeled(PQXDH_LABEL_PQK, peer->pqk_pk, PQXDH_MLKEM_PUB,
                        peer->pqk_sig, peer->pqk_sig_len, peer->ik_sig_pk);
    if (rc != CRYPTO_SUCCESS) return rc;
    if (peer->have_opk) {
        unsigned char om[4 + X25519_KEY_SIZE];
        opk_signed_bytes(peer->opk_id, peer->opk_pk, om);
        rc = verify_labeled(PQXDH_LABEL_OPK, om, sizeof om, peer->opk_sig, peer->opk_sig_len, peer->ik_sig_pk);
        if (rc != CRYPTO_SUCCESS) return rc;
    }

    unsigned char ek_sk[X25519_KEY_SIZE], ek_pk[X25519_KEY_SIZE];
    unsigned char legs[4 * X25519_KEY_SIZE + AES_KEY_SIZE];
    unsigned char pq_ct[PQXDH_MLKEM_CT], pq_ss[AES_KEY_SIZE];
    unsigned char sk[AES_KEY_SIZE];
    OQS_KEM *kem = NULL;
    size_t off = 0;

    if ((rc = crypto_x25519_keypair(ek_sk, ek_pk)) != CRYPTO_SUCCESS) goto out;

    /* DH1=DH(IK_A,SPK_B) DH2=DH(EK_A,IK_B) DH3=DH(EK_A,SPK_B) [DH4=DH(EK_A,OPK_B)] */
    if ((rc = crypto_x25519_dh(self->ik_dh_sk, peer->spk_pk, legs + off)) != CRYPTO_SUCCESS) goto out; off += X25519_KEY_SIZE;
    if ((rc = crypto_x25519_dh(ek_sk, peer->ik_dh_pk, legs + off)) != CRYPTO_SUCCESS) goto out;      off += X25519_KEY_SIZE;
    if ((rc = crypto_x25519_dh(ek_sk, peer->spk_pk, legs + off)) != CRYPTO_SUCCESS) goto out;         off += X25519_KEY_SIZE;
    if (peer->have_opk) {
        if ((rc = crypto_x25519_dh(ek_sk, peer->opk_pk, legs + off)) != CRYPTO_SUCCESS) goto out;     off += X25519_KEY_SIZE;
    }

    kem = kem_new();
    /* Guard the fixed-size buffers against a mismatched liboqs variant before
     * encaps writes length_shared_secret bytes into pq_ss / length_ciphertext
     * into pq_ct. */
    if (!kem || kem->length_ciphertext != PQXDH_MLKEM_CT ||
        kem->length_public_key != PQXDH_MLKEM_PUB ||
        kem->length_shared_secret != AES_KEY_SIZE) { rc = CRYPTO_ERR_CRYPTO; goto out; }
    if (OQS_KEM_encaps(kem, pq_ct, pq_ss, peer->pqk_pk) != OQS_SUCCESS) { rc = CRYPTO_ERR_CRYPTO; goto out; }
    memcpy(legs + off, pq_ss, AES_KEY_SIZE); off += AES_KEY_SIZE;

    if ((rc = derive_sk(legs, off, sk)) != CRYPTO_SUCCESS) goto out;
    rc = pq ? ratchet_pq_init_initiator(sk, peer->spk_pk, session_out)
            : ratchet_init_initiator(sk, peer->spk_pk, session_out);
    if (rc != CRYPTO_SUCCESS) goto out;

    /* Assemble and sign the opening message. */
    memcpy(msg_out->ik_sig_pk, self->ik_sig_pk, QSAFE_SIG_PUB_SIZE);
    memcpy(msg_out->ik_dh_pk, self->ik_dh_pk, X25519_KEY_SIZE);
    memcpy(msg_out->ek_pk, ek_pk, X25519_KEY_SIZE);
    memcpy(msg_out->pq_ct, pq_ct, PQXDH_MLKEM_CT);
    msg_out->opk_id = peer->have_opk ? (int64_t)peer->opk_id : -1;
    msg_out->pq = pq ? 1 : 0;
    {
        unsigned char signbuf[INITIAL_SIGNED_LEN];
        size_t n = initial_signed_bytes(msg_out, signbuf);
        rc = crypto_sig_sign_buf(signbuf, n, self->ik_sig_sk, msg_out->sig, &msg_out->sig_len);
        if (rc != CRYPTO_SUCCESS) { ratchet_session_free(*session_out); *session_out = NULL; }
    }

out:
    if (kem) OQS_KEM_free(kem);
    secure_zero(ek_sk, sizeof ek_sk);
    secure_zero(legs, sizeof legs);
    secure_zero(pq_ss, sizeof pq_ss);
    secure_zero(sk, sizeof sk);
    return rc;
}

crypto_error_t pqxdh_responder(const pqxdh_identity_t *self, const pqxdh_initial_t *msg,
                               ratchet_session_t **session_out) {
    if (!self || !msg || !session_out) return CRYPTO_ERR_INVALID_INPUT;

    /* Authenticate the opening message under the sender's asserted identity key. */
    unsigned char signbuf[INITIAL_SIGNED_LEN];
    size_t n = initial_signed_bytes(msg, signbuf);
    crypto_error_t rc = crypto_sig_verify_buf(signbuf, n, msg->sig, msg->sig_len, msg->ik_sig_pk);
    if (rc != CRYPTO_SUCCESS) return rc;

    unsigned char legs[4 * X25519_KEY_SIZE + AES_KEY_SIZE];
    unsigned char pq_ss[AES_KEY_SIZE], sk[AES_KEY_SIZE];
    OQS_KEM *kem = NULL;
    size_t off = 0;

    if ((rc = crypto_x25519_dh(self->spk_sk, msg->ik_dh_pk, legs + off)) != CRYPTO_SUCCESS) goto out; off += X25519_KEY_SIZE;
    if ((rc = crypto_x25519_dh(self->ik_dh_sk, msg->ek_pk, legs + off)) != CRYPTO_SUCCESS) goto out;  off += X25519_KEY_SIZE;
    if ((rc = crypto_x25519_dh(self->spk_sk, msg->ek_pk, legs + off)) != CRYPTO_SUCCESS) goto out;    off += X25519_KEY_SIZE;
    if (msg->opk_id >= 0) {
        int found = -1;
        for (uint32_t i = 0; i < self->n_opk; i++)
            if (self->opk_id[i] == (uint32_t)msg->opk_id) { found = (int)i; break; }
        if (found < 0) { rc = CRYPTO_ERR_INVALID_INPUT; goto out; }   /* unknown/spent OPK */
        if ((rc = crypto_x25519_dh(self->opk_sk[found], msg->ek_pk, legs + off)) != CRYPTO_SUCCESS) goto out;
        off += X25519_KEY_SIZE;
    }

    kem = kem_new();
    if (!kem || kem->length_ciphertext != PQXDH_MLKEM_CT ||
        kem->length_secret_key != PQXDH_MLKEM_SEC ||
        kem->length_shared_secret != AES_KEY_SIZE) { rc = CRYPTO_ERR_CRYPTO; goto out; }
    if (OQS_KEM_decaps(kem, pq_ss, msg->pq_ct, self->pqk_sk) != OQS_SUCCESS) { rc = CRYPTO_ERR_INTEGRITY; goto out; }
    memcpy(legs + off, pq_ss, AES_KEY_SIZE); off += AES_KEY_SIZE;

    if ((rc = derive_sk(legs, off, sk)) != CRYPTO_SUCCESS) goto out;
    /* PQ intent is authenticated (in the signed opening message), so a MITM can't
     * downgrade the ratchet to classical. */
    rc = msg->pq ? ratchet_pq_init_responder(sk, self->spk_pk, self->spk_sk, session_out)
                 : ratchet_init_responder(sk, self->spk_pk, self->spk_sk, session_out);

out:
    if (kem) OQS_KEM_free(kem);
    secure_zero(legs, sizeof legs);
    secure_zero(pq_ss, sizeof pq_ss);
    secure_zero(sk, sizeof sk);
    return rc;
}
