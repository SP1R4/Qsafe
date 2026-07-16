/* PQXDH handshake exercise: full establishment + negative auth checks.
 * Proves both parties derive the same SK (ratchet messages flow) and that
 * forged prekey/handshake signatures are rejected. */

#include <stdio.h>
#include <string.h>

#include "pqxdh.h"
#include "ratchet.h"
#include "crypto_utils.h"

static int fails = 0;
#define CHECK(cond, msg) do { \
    if (cond) { printf("  ok   %s\n", msg); } \
    else { printf("  FAIL %s\n", msg); fails++; } } while (0)

/* Attach one signed one-time prekey (from B's pool) to a published bundle. */
static void attach_opk(const pqxdh_identity_t *id, pqxdh_bundle_t *b, uint32_t index) {
    b->have_opk = 1;
    pqxdh_opk_public(id, index, &b->opk_id, b->opk_pk, b->opk_sig, &b->opk_sig_len);
}

/* Establish a session pair from fresh identities; return 0 on success. */
static int establish(pqxdh_identity_t *A, pqxdh_identity_t *B,
                     ratchet_session_t **as, ratchet_session_t **bs) {
    pqxdh_bundle_t bundle;
    if (pqxdh_publish_bundle(B, &bundle) != CRYPTO_SUCCESS) return -1;
    pqxdh_initial_t msg;
    if (pqxdh_initiator(A, &bundle, 0, &msg, as) != CRYPTO_SUCCESS) return -1;
    if (pqxdh_responder(B, &msg, bs) != CRYPTO_SUCCESS) return -1;
    return 0;
}

int main(void) {
    pqxdh_identity_t A, B;
    CHECK(pqxdh_identity_generate(&A) == CRYPTO_SUCCESS, "generate identity A");
    CHECK(pqxdh_identity_generate(&B) == CRYPTO_SUCCESS, "generate identity B");

    /* 1. Happy path: establish and confirm both sides share the same SK. */
    ratchet_session_t *as = NULL, *bs = NULL;
    CHECK(establish(&A, &B, &as, &bs) == 0, "handshake establishes both sessions");

    if (as && bs) {
        unsigned char hdr[RATCHET_HDR_SIZE], ct[256], pt[256]; size_t cl, pl;
        const char *m1 = "handshake works";
        ratchet_encrypt(as, (const unsigned char*)m1, strlen(m1), hdr, ct, &cl);
        CHECK(ratchet_decrypt(bs, hdr, ct, cl, pt, &pl) == CRYPTO_SUCCESS &&
              pl == strlen(m1) && memcmp(pt, m1, pl) == 0, "A->B decrypt (SK agrees)");
        const char *m2 = "and both ways";
        ratchet_encrypt(bs, (const unsigned char*)m2, strlen(m2), hdr, ct, &cl);
        CHECK(ratchet_decrypt(as, hdr, ct, cl, pt, &pl) == CRYPTO_SUCCESS &&
              pl == strlen(m2) && memcmp(pt, m2, pl) == 0, "B->A decrypt");
    }
    ratchet_session_free(as);
    ratchet_session_free(bs);

    /* 1b. OPK path: attach a one-time prekey, handshake, confirm SK agrees and
     * the opk_id is carried in the opening message. */
    {
        pqxdh_bundle_t bundle; pqxdh_publish_bundle(&B, &bundle);
        attach_opk(&B, &bundle, 0);
        pqxdh_initial_t msg; ratchet_session_t *as2 = NULL, *bs2 = NULL;
        CHECK(pqxdh_initiator(&A, &bundle, 0, &msg, &as2) == CRYPTO_SUCCESS, "initiator with OPK");
        CHECK(msg.opk_id == (int64_t)bundle.opk_id, "opk_id carried in opening message");
        CHECK(pqxdh_responder(&B, &msg, &bs2) == CRYPTO_SUCCESS, "responder consumes OPK");
        if (as2 && bs2) {
            unsigned char h[RATCHET_HDR_SIZE], c[256], p[256]; size_t cl, pl;
            const char *m = "opk path";
            ratchet_encrypt(as2, (const unsigned char*)m, strlen(m), h, c, &cl);
            CHECK(ratchet_decrypt(bs2, h, c, cl, p, &pl) == CRYPTO_SUCCESS &&
                  pl == strlen(m) && memcmp(p, m, pl) == 0, "OPK-path SK agrees");
        }
        /* Forged OPK signature -> initiator rejects. */
        pqxdh_bundle_t b2; pqxdh_publish_bundle(&B, &b2); attach_opk(&B, &b2, 1);
        b2.opk_sig[0] ^= 0x01;
        pqxdh_initial_t m2; ratchet_session_t *s = NULL;
        CHECK(pqxdh_initiator(&A, &b2, 0, &m2, &s) == CRYPTO_ERR_INTEGRITY, "forged OPK signature rejected");
        ratchet_session_free(s);
        ratchet_session_free(as2);
        ratchet_session_free(bs2);
    }

    /* 1c. PQ handshake (pq=1): both sessions come up PQ; exchange over the PQ
     * ratchet with the larger header. */
    {
        pqxdh_bundle_t bundle; pqxdh_publish_bundle(&B, &bundle); attach_opk(&B, &bundle, 2);
        pqxdh_initial_t msg; ratchet_session_t *pa = NULL, *pb = NULL;
        CHECK(pqxdh_initiator(&A, &bundle, 1, &msg, &pa) == CRYPTO_SUCCESS, "PQ initiator");
        CHECK(msg.pq == 1, "opening message carries the (signed) pq flag");
        CHECK(pqxdh_responder(&B, &msg, &pb) == CRYPTO_SUCCESS, "PQ responder");
        CHECK(pa && pb && ratchet_hdr_size(pa) == RATCHET_PQ_HDR_SIZE &&
              ratchet_hdr_size(pb) == RATCHET_PQ_HDR_SIZE, "both sessions are PQ");
        if (pa && pb) {
            unsigned char h[RATCHET_PQ_HDR_SIZE], c[256], p[256]; size_t cl, pl;
            ratchet_encrypt(pa, (const unsigned char*)"pq-hi", 5, h, c, &cl);
            CHECK(ratchet_decrypt(pb, h, c, cl, p, &pl) == CRYPTO_SUCCESS && pl == 5 && memcmp(p, "pq-hi", 5) == 0, "PQ A->B decrypt");
            ratchet_encrypt(pb, (const unsigned char*)"pq-yo", 5, h, c, &cl);
            CHECK(ratchet_decrypt(pa, h, c, cl, p, &pl) == CRYPTO_SUCCESS && pl == 5 && memcmp(p, "pq-yo", 5) == 0, "PQ B->A decrypt");
        }
        ratchet_session_free(pa); ratchet_session_free(pb);
    }

    /* 2. Forged signed-prekey signature in the bundle -> initiator rejects. */
    {
        pqxdh_bundle_t bundle; pqxdh_publish_bundle(&B, &bundle);
        bundle.spk_sig[0] ^= 0x01;
        pqxdh_initial_t msg; ratchet_session_t *s = NULL;
        CHECK(pqxdh_initiator(&A, &bundle, 0, &msg, &s) == CRYPTO_ERR_INTEGRITY, "forged SPK signature rejected");
        ratchet_session_free(s);
    }

    /* 3. Swapped identity key (bundle signed by someone else) -> rejected. */
    {
        pqxdh_bundle_t bundle; pqxdh_publish_bundle(&B, &bundle);
        memcpy(bundle.ik_sig_pk, A.ik_sig_pk, QSAFE_SIG_PUB_SIZE);  /* claim A signed B's prekeys */
        pqxdh_initial_t msg; ratchet_session_t *s = NULL;
        CHECK(pqxdh_initiator(&A, &bundle, 0, &msg, &s) == CRYPTO_ERR_INTEGRITY, "wrong identity key rejected");
        ratchet_session_free(s);
    }

    /* 4. Tampered opening message -> responder rejects. */
    {
        pqxdh_bundle_t bundle; pqxdh_publish_bundle(&B, &bundle);
        pqxdh_initial_t msg; ratchet_session_t *s = NULL;
        CHECK(pqxdh_initiator(&A, &bundle, 0, &msg, &s) == CRYPTO_SUCCESS, "clean handshake for tamper test");
        ratchet_session_free(s);
        msg.ek_pk[0] ^= 0x01;   /* flip a byte the signature covers */
        ratchet_session_t *bs2 = NULL;
        CHECK(pqxdh_responder(&B, &msg, &bs2) == CRYPTO_ERR_INTEGRITY, "tampered opening message rejected");
        ratchet_session_free(bs2);
    }

    pqxdh_identity_free(&A);
    pqxdh_identity_free(&B);
    printf("\n%s\n", fails ? "SOME TESTS FAILED" : "ALL TESTS PASSED");
    return fails ? 1 : 0;
}
