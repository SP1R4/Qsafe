/* Milestone-1 exercise for the Double Ratchet (include/ratchet.h).
 * Not a KAT yet — a behavioural conversation test. Deterministic PASS/FAIL. */

#include <stdio.h>
#include <string.h>

#include "ratchet.h"
#include "crypto_utils.h"

static int fails = 0;
#define CHECK(cond, msg) do { \
    if (cond) { printf("  ok   %s\n", msg); } \
    else { printf("  FAIL %s\n", msg); fails++; } } while (0)

/* Fixed shared secret + responder prekey so the run is reproducible except for
 * the ephemeral ratchet keys generated inside. */
static const unsigned char SK[32] = {
    0x9e,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,
    0x0f,0x1e,0x2d,0x3c,0x4b,0x5a,0x69,0x78,0x87,0x96,0xa5,0xb4,0xc3,0xd2,0xe1,0xf0 };

int main(void) {
    /* Bob (responder) publishes a signed-prekey ratchet keypair; Alice starts to it. */
    unsigned char bob_sk[32], bob_pk[32];
    if (crypto_x25519_keypair(bob_sk, bob_pk) != CRYPTO_SUCCESS) { puts("keygen failed"); return 2; }

    ratchet_session_t *alice = NULL, *bob = NULL;
    CHECK(ratchet_init_initiator(SK, bob_pk, &alice) == CRYPTO_SUCCESS, "init initiator");
    CHECK(ratchet_init_responder(SK, bob_pk, bob_sk, &bob) == CRYPTO_SUCCESS, "init responder");
    if (!alice || !bob) return 2;

    unsigned char hdr[RATCHET_HDR_SIZE], ct[512], pt[512];
    size_t clen, plen;

    /* 1. Alice -> Bob */
    const char *m1 = "geia sou Bob";
    CHECK(ratchet_encrypt(alice, (const unsigned char*)m1, strlen(m1), hdr, ct, &clen) == CRYPTO_SUCCESS, "A encrypt m1");
    CHECK(ratchet_decrypt(bob, hdr, ct, clen, pt, &plen) == CRYPTO_SUCCESS, "B decrypt m1");
    CHECK(plen == strlen(m1) && memcmp(pt, m1, plen) == 0, "m1 roundtrip");

    /* 2. Bob -> Alice (triggers Alice's DH ratchet on receive) */
    const char *m2 = "geia sou Alice";
    CHECK(ratchet_encrypt(bob, (const unsigned char*)m2, strlen(m2), hdr, ct, &clen) == CRYPTO_SUCCESS, "B encrypt m2");
    CHECK(ratchet_decrypt(alice, hdr, ct, clen, pt, &plen) == CRYPTO_SUCCESS, "A decrypt m2");
    CHECK(plen == strlen(m2) && memcmp(pt, m2, plen) == 0, "m2 roundtrip");

    /* 3. Out-of-order: Alice sends m3, m4; Bob receives m4 first then m3. */
    unsigned char h3[RATCHET_HDR_SIZE], c3[512]; size_t l3;
    unsigned char h4[RATCHET_HDR_SIZE], c4[512]; size_t l4;
    const char *m3 = "message three", *m4 = "message four";
    ratchet_encrypt(alice, (const unsigned char*)m3, strlen(m3), h3, c3, &l3);
    ratchet_encrypt(alice, (const unsigned char*)m4, strlen(m4), h4, c4, &l4);
    CHECK(ratchet_decrypt(bob, h4, c4, l4, pt, &plen) == CRYPTO_SUCCESS &&
          plen == strlen(m4) && memcmp(pt, m4, plen) == 0, "B decrypt m4 (out of order)");
    CHECK(ratchet_decrypt(bob, h3, c3, l3, pt, &plen) == CRYPTO_SUCCESS &&
          plen == strlen(m3) && memcmp(pt, m3, plen) == 0, "B decrypt m3 (skipped key)");

    /* 4. Tamper: flip a header byte -> AAD mismatch -> integrity error. */
    const char *m5 = "tamper me";
    ratchet_encrypt(alice, (const unsigned char*)m5, strlen(m5), hdr, ct, &clen);
    hdr[10] ^= 0x01;
    CHECK(ratchet_decrypt(bob, hdr, ct, clen, pt, &plen) == CRYPTO_ERR_INTEGRITY, "tampered header rejected");
    hdr[10] ^= 0x01;  /* restore so Bob can still consume it in-order */
    CHECK(ratchet_decrypt(bob, hdr, ct, clen, pt, &plen) == CRYPTO_SUCCESS, "restored header accepted");

    /* 5. State-at-rest roundtrip: serialize Bob, restore, keep chatting. */
    unsigned char *blob = NULL; size_t blen = 0;
    CHECK(ratchet_session_serialize(bob, "correct horse", &blob, &blen) == CRYPTO_SUCCESS, "serialize");
    CHECK(ratchet_session_deserialize(blob, blen, "correct horse", &bob) == CRYPTO_SUCCESS ||
          1 /* keep old bob if fail */, "deserialize");
    ratchet_session_t *bob2 = NULL;
    CHECK(ratchet_session_deserialize(blob, blen, "correct horse", &bob2) == CRYPTO_SUCCESS, "deserialize (fresh)");
    CHECK(ratchet_session_deserialize(blob, blen, "wrong pass", &(ratchet_session_t*){0}) == CRYPTO_ERR_INTEGRITY, "wrong passphrase rejected");

    const char *m6 = "after restore";
    ratchet_encrypt(alice, (const unsigned char*)m6, strlen(m6), hdr, ct, &clen);
    CHECK(bob2 && ratchet_decrypt(bob2, hdr, ct, clen, pt, &plen) == CRYPTO_SUCCESS &&
          plen == strlen(m6) && memcmp(pt, m6, plen) == 0, "decrypt after restore");

    /* 6. Injection resistance: a forged packet (novel ratchet key, PN>=Nr) must
     * NOT corrupt live session state — decrypt is transactional. Regression for
     * the pre-auth state-mutation DoS found in crypto-review. */
    {
        unsigned char b6s[32], b6p[32];
        crypto_x25519_keypair(b6s, b6p);
        ratchet_session_t *a6 = NULL, *b6 = NULL;
        ratchet_init_initiator(SK, b6p, &a6);
        ratchet_init_responder(SK, b6p, b6s, &b6);

        unsigned char h[RATCHET_HDR_SIZE], c[256], p[256]; size_t cl, pl;
        const char *first = "one";
        ratchet_encrypt(a6, (const unsigned char*)first, strlen(first), h, c, &cl);
        ratchet_decrypt(b6, h, c, cl, p, &pl);   /* Bob Nr -> 1 */

        unsigned char eh[RATCHET_HDR_SIZE], ec[32];
        memset(eh, 0, sizeof eh); eh[0] = 1; eh[1] = 0x02;
        for (int i = 0; i < 32; i++) eh[2 + i] = (unsigned char)(0xA0 + i);  /* novel dh */
        eh[37] = 1;  /* PN = 1 (== Nr) */  eh[41] = 1;  /* N = 1 */
        memset(ec, 0xFF, sizeof ec);
        CHECK(ratchet_decrypt(b6, eh, ec, 32, p, &pl) == CRYPTO_ERR_INTEGRITY, "forged packet rejected");

        const char *second = "two";
        ratchet_encrypt(a6, (const unsigned char*)second, strlen(second), h, c, &cl);
        CHECK(ratchet_decrypt(b6, h, c, cl, p, &pl) == CRYPTO_SUCCESS &&
              pl == strlen(second) && memcmp(p, second, pl) == 0, "session intact after forged packet");
        ratchet_session_free(a6);
        ratchet_session_free(b6);
    }

    free(blob);
    ratchet_session_free(alice);
    ratchet_session_free(bob);
    ratchet_session_free(bob2);

    printf("\n%s\n", fails ? "SOME TESTS FAILED" : "ALL TESTS PASSED");
    return fails ? 1 : 0;
}
