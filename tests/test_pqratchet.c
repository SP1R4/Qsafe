/* Continuous PQ ratchet (veil/docs/PQ_RATCHET.md): two parties ping-pong so every
 * message triggers a DH+ML-KEM ratchet step. If the KEM encap/decap plumbing were
 * wrong the two sides' root keys would diverge and decryption would fail — so a
 * long green run is strong evidence the ML-KEM secret is mixed in identically on
 * both sides. Also checks the header size and that a tampered PQ header (AAD) is
 * rejected. */

#include <stdio.h>
#include <string.h>

#include "ratchet.h"
#include "crypto_utils.h"

static int fails = 0;
#define CHECK(cond, msg) do { \
    if (cond) { printf("  ok   %s\n", msg); } \
    else { printf("  FAIL %s\n", msg); fails++; } } while (0)

static const unsigned char SK[32] = {
    0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,
    0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,0x0f,0x1e,0x2d,0x3c,0x4b,0x5a,0x69,0x78 };

int main(void) {
    unsigned char bsk[32], bpk[32];
    if (crypto_x25519_keypair(bsk, bpk) != CRYPTO_SUCCESS) { puts("keygen failed"); return 2; }

    ratchet_session_t *A = NULL, *B = NULL;
    CHECK(ratchet_pq_init_initiator(SK, bpk, &A) == CRYPTO_SUCCESS, "pq init initiator");
    CHECK(ratchet_pq_init_responder(SK, bpk, bsk, &B) == CRYPTO_SUCCESS, "pq init responder");
    if (!A || !B) return 2;
    CHECK(ratchet_hdr_size(A) == RATCHET_PQ_HDR_SIZE, "PQ header size advertised");

    unsigned char hdr[RATCHET_PQ_HDR_SIZE];
    unsigned char ct[512], pt[512]; size_t cl, pl;

    /* Ping-pong: alternate sender each message so every message is a ratchet step
     * (new DH key + ML-KEM re-encapsulation folded into the root). */
    ratchet_session_t *S = A, *R = B;
    int ok_all = 1;
    for (int i = 0; i < 16; i++) {
        char msg[32]; snprintf(msg, sizeof msg, "pq-message-%d", i);
        if (ratchet_encrypt(S, (const unsigned char *)msg, strlen(msg), hdr, ct, &cl) != CRYPTO_SUCCESS) { ok_all = 0; break; }
        if (ratchet_decrypt(R, hdr, ct, cl, pt, &pl) != CRYPTO_SUCCESS ||
            pl != strlen(msg) || memcmp(pt, msg, pl) != 0) { ok_all = 0; break; }
        ratchet_session_t *t = S; S = R; R = t;   /* flip direction */
    }
    CHECK(ok_all, "16 alternating messages round-trip (root keys stay in sync across KEM steps)");
    /* (That the ML-KEM material is genuinely engaged — not silently skipped — is
     * proven robustly by the soak test's full/lite distribution assertion.) */

    /* Out-of-order within a sending chain (skipped keys, no KEM step involved). */
    {
        unsigned char h1[RATCHET_PQ_HDR_SIZE], c1[512]; size_t l1;
        unsigned char h2[RATCHET_PQ_HDR_SIZE], c2[512]; size_t l2;
        /* S is whoever holds a sending chain now; send two, deliver reversed. */
        CHECK(ratchet_encrypt(S, (const unsigned char *)"first", 5, h1, c1, &l1) == CRYPTO_SUCCESS, "ooo encrypt first");
        CHECK(ratchet_encrypt(S, (const unsigned char *)"second", 6, h2, c2, &l2) == CRYPTO_SUCCESS, "ooo encrypt second");
        CHECK(ratchet_decrypt(R, h2, c2, l2, pt, &pl) == CRYPTO_SUCCESS && pl == 6 && memcmp(pt, "second", 6) == 0, "ooo decrypt second (skipped key stored)");
        CHECK(ratchet_decrypt(R, h1, c1, l1, pt, &pl) == CRYPTO_SUCCESS && pl == 5 && memcmp(pt, "first", 5) == 0, "ooo decrypt first (from skipped key)");
    }

    /* Tamper checks on a FRESH pair whose first message is guaranteed PQ-full
     * (bootstrap advertises the ML-KEM key), so the tampered bytes are real KEM
     * material in the AAD (a later message may be a 42-byte lite header). */
    {
        unsigned char tbsk[32], tbpk[32]; crypto_x25519_keypair(tbsk, tbpk);
        ratchet_session_t *TA = NULL, *TB = NULL;
        ratchet_pq_init_initiator(SK, tbpk, &TA);
        ratchet_pq_init_responder(SK, tbpk, tbsk, &TB);
        unsigned char h[RATCHET_PQ_HDR_SIZE], c[256], p[256]; size_t cl2, pl2;
        /* TA's first message (full, but no ct yet). TB then holds TA's key and its
         * own first reply is PQ-full WITH a real ciphertext — tamper that. */
        ratchet_encrypt(TA, (const unsigned char *)"a", 1, h, c, &cl2);
        ratchet_decrypt(TB, h, c, cl2, p, &pl2);
        CHECK(ratchet_encrypt(TB, (const unsigned char *)"b", 1, h, c, &cl2) == CRYPTO_SUCCESS &&
              h[1] == RATCHET_TYPE_PQ_FULL && h[RATCHET_HDR_SIZE + RATCHET_MLKEM_PK] == 1,
              "tamper: responder's first reply is PQ-full with a ciphertext");
        unsigned char save = h[RATCHET_HDR_SIZE + RATCHET_MLKEM_PK + 1 + 50];
        h[RATCHET_HDR_SIZE + RATCHET_MLKEM_PK + 1 + 50] ^= 0x01;            /* a byte inside kem_ct */
        CHECK(ratchet_decrypt(TA, h, c, cl2, p, &pl2) == CRYPTO_ERR_INTEGRITY, "tampered KEM ciphertext rejected");
        h[RATCHET_HDR_SIZE + RATCHET_MLKEM_PK + 1 + 50] = save;
        h[RATCHET_HDR_SIZE + 100] ^= 0x01;                                  /* a byte inside kem_pk */
        CHECK(ratchet_decrypt(TA, h, c, cl2, p, &pl2) != CRYPTO_SUCCESS, "tampered ML-KEM public key rejected");
        ratchet_session_free(TA); ratchet_session_free(TB);
    }

    /* State-at-rest: serialize a PQ session mid-conversation, restore, and confirm
     * it keeps ratcheting with its peer — which only works if the ML-KEM state
     * (kem_sk / kem_r / pend_ct / flags) survived serialization intact. */
    {
        unsigned char cbsk[32], cbpk[32];
        crypto_x25519_keypair(cbsk, cbpk);
        ratchet_session_t *C = NULL, *D = NULL;
        ratchet_pq_init_initiator(SK, cbpk, &C);
        ratchet_pq_init_responder(SK, cbpk, cbsk, &D);
        unsigned char h[RATCHET_PQ_HDR_SIZE], c[512], p[512]; size_t cl2, pl2;
        /* advance: C->D, D->C so C holds real KEM state (have_ct set) */
        ratchet_encrypt(C, (const unsigned char *)"x", 1, h, c, &cl2); ratchet_decrypt(D, h, c, cl2, p, &pl2);
        ratchet_encrypt(D, (const unsigned char *)"y", 1, h, c, &cl2); ratchet_decrypt(C, h, c, cl2, p, &pl2);

        unsigned char *blob; size_t blen;
        CHECK(ratchet_session_serialize(C, "pw", &blob, &blen) == CRYPTO_SUCCESS, "PQ session serialize");
        ratchet_session_t *C2 = NULL;
        CHECK(ratchet_session_deserialize(blob, blen, "pw", &C2) == CRYPTO_SUCCESS, "PQ session deserialize");
        ratchet_session_t *bad = NULL;
        CHECK(ratchet_session_deserialize(blob, blen, "wrong", &bad) == CRYPTO_ERR_INTEGRITY, "PQ wrong passphrase rejected");
        free(blob);
        CHECK(C2 && ratchet_hdr_size(C2) == RATCHET_PQ_HDR_SIZE, "restored session is PQ");

        int ok2 = 1;
        ratchet_session_t *SS = C2, *RR = D;
        for (int i = 0; i < 4 && C2; i++) {
            char m[16]; snprintf(m, sizeof m, "r%d", i);
            if (ratchet_encrypt(SS, (const unsigned char *)m, strlen(m), h, c, &cl2) != CRYPTO_SUCCESS) { ok2 = 0; break; }
            if (ratchet_decrypt(RR, h, c, cl2, p, &pl2) != CRYPTO_SUCCESS || pl2 != strlen(m) || memcmp(p, m, pl2) != 0) { ok2 = 0; break; }
            ratchet_session_t *t = SS; SS = RR; RR = t;
        }
        CHECK(ok2, "PQ session resumes across restore (KEM state intact through ratchet steps)");
        ratchet_session_free(C); ratchet_session_free(C2); ratchet_session_free(D);
    }

    ratchet_session_free(A);
    ratchet_session_free(B);
    printf("\n%s\n", fails ? "SOME TESTS FAILED" : "ALL TESTS PASSED");
    return fails ? 1 : 0;
}
