/* Header-encryption ratchet exercise (veil/docs/HEADER_ENCRYPTION.md).
 * Behavioural: same conversation patterns as the classical ratchet, plus checks
 * that the on-wire header is opaque and unlinkable. Deterministic PASS/FAIL. */

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
    0xf0,0xe1,0xd2,0xc3,0xb4,0xa5,0x96,0x87,0x78,0x69,0x5a,0x4b,0x3c,0x2d,0x1e,0x0f };

#define HH RATCHET_HE_HDR_SIZE

int main(void) {
    unsigned char bob_sk[32], bob_pk[32];
    if (crypto_x25519_keypair(bob_sk, bob_pk) != CRYPTO_SUCCESS) { puts("keygen failed"); return 2; }

    ratchet_session_t *alice = NULL, *bob = NULL;
    CHECK(ratchet_he_init_initiator(SK, bob_pk, &alice) == CRYPTO_SUCCESS, "HE init initiator");
    CHECK(ratchet_he_init_responder(SK, bob_pk, bob_sk, &bob) == CRYPTO_SUCCESS, "HE init responder");
    if (!alice || !bob) return 2;

    CHECK(ratchet_hdr_size(alice) == RATCHET_HE_HDR_SIZE, "HE header size advertised");

    unsigned char hdr[HH], ct[512], pt[512];
    size_t clen, plen;

    /* 1. Alice -> Bob, Bob -> Alice (drives Alice's first DH ratchet on receive). */
    const char *m1 = "encrypted headers now";
    CHECK(ratchet_encrypt(alice, (const unsigned char*)m1, strlen(m1), hdr, ct, &clen) == CRYPTO_SUCCESS, "A encrypt m1");
    CHECK(ratchet_decrypt(bob, hdr, ct, clen, pt, &plen) == CRYPTO_SUCCESS &&
          plen == strlen(m1) && memcmp(pt, m1, plen) == 0, "B decrypt m1");
    const char *m2 = "and back";
    CHECK(ratchet_encrypt(bob, (const unsigned char*)m2, strlen(m2), hdr, ct, &clen) == CRYPTO_SUCCESS, "B encrypt m2");
    CHECK(ratchet_decrypt(alice, hdr, ct, clen, pt, &plen) == CRYPTO_SUCCESS &&
          plen == strlen(m2) && memcmp(pt, m2, plen) == 0, "A decrypt m2 (ratchet step)");

    /* 2. Long ping-pong across many DH-ratchet steps. */
    int pingpong_ok = 1;
    for (int i = 0; i < 40; i++) {
        char buf[32]; int len = snprintf(buf, sizeof buf, "pp-%d", i);
        ratchet_session_t *tx = (i & 1) ? bob : alice;
        ratchet_session_t *rx = (i & 1) ? alice : bob;
        unsigned char h[HH], c[128], p[128]; size_t cl, pl;
        if (ratchet_encrypt(tx, (const unsigned char*)buf, (size_t)len, h, c, &cl) != CRYPTO_SUCCESS ||
            ratchet_decrypt(rx, h, c, cl, p, &pl) != CRYPTO_SUCCESS ||
            pl != (size_t)len || memcmp(p, buf, pl) != 0) { pingpong_ok = 0; break; }
    }
    CHECK(pingpong_ok, "40-message ping-pong across ratchet steps");

    /* 3. Out-of-order within one sending chain (skipped header keys). */
    unsigned char ha[HH], ca[512]; size_t la;
    unsigned char hb[HH], cb[512]; size_t lb;
    unsigned char hc[HH], cc[512]; size_t lc;
    const char *a = "ooo-a", *b = "ooo-b", *c = "ooo-c";
    ratchet_encrypt(alice, (const unsigned char*)a, strlen(a), ha, ca, &la);
    ratchet_encrypt(alice, (const unsigned char*)b, strlen(b), hb, cb, &lb);
    ratchet_encrypt(alice, (const unsigned char*)c, strlen(c), hc, cc, &lc);
    CHECK(ratchet_decrypt(bob, hc, cc, lc, pt, &plen) == CRYPTO_SUCCESS &&
          memcmp(pt, c, plen) == 0, "B decrypt 3rd first (skips headers)");
    CHECK(ratchet_decrypt(bob, ha, ca, la, pt, &plen) == CRYPTO_SUCCESS &&
          memcmp(pt, a, plen) == 0, "B decrypt 1st from stored skipped header key");
    CHECK(ratchet_decrypt(bob, hb, cb, lb, pt, &plen) == CRYPTO_SUCCESS &&
          memcmp(pt, b, plen) == 0, "B decrypt 2nd from stored skipped header key");

    /* 4. Unlinkability: three messages in ONE sending chain have fully distinct
     * on-wire headers (a passive relay can't cluster them), and no 32-byte run of
     * either header equals the other's — i.e. no shared cleartext ratchet key. */
    unsigned char h1[HH], h2[HH], h3[HH], cx[128]; size_t lx;
    const char *u = "u";
    ratchet_encrypt(alice, (const unsigned char*)u, 1, h1, cx, &lx);
    ratchet_encrypt(alice, (const unsigned char*)u, 1, h2, cx, &lx);
    ratchet_encrypt(alice, (const unsigned char*)u, 1, h3, cx, &lx);
    CHECK(memcmp(h1, h2, HH) != 0 && memcmp(h2, h3, HH) != 0 && memcmp(h1, h3, HH) != 0,
          "same-chain headers are all distinct (unlinkable)");
    int shares_run = 0;
    for (size_t off = 0; off + 32 <= HH; off++)
        if (memcmp(h1 + off, h2 + off, 32) == 0) shares_run = 1;
    CHECK(!shares_run, "no shared 32-byte block between same-chain headers (dh_pub hidden)");
    /* Deliver them so the sessions stay in sync for later checks. */
    ratchet_decrypt(bob, h1, cx, lx, pt, &plen);  /* lx is same len for all (1+tag) */

    /* 5. Tamper the encrypted header -> reject; tamper the body -> reject; and a
     * good message still opens afterwards (transactional: no state corruption). */
    unsigned char ht[HH], ctht[128]; size_t lt;
    const char *t = "tamper-me";
    ratchet_encrypt(alice, (const unsigned char*)t, strlen(t), ht, ctht, &lt);
    unsigned char save = ht[20]; ht[20] ^= 0x01;
    CHECK(ratchet_decrypt(bob, ht, ctht, lt, pt, &plen) == CRYPTO_ERR_INTEGRITY, "tampered header rejected");
    ht[20] = save;
    unsigned char cs = ctht[0]; ctht[0] ^= 0x01;
    CHECK(ratchet_decrypt(bob, ht, ctht, lt, pt, &plen) == CRYPTO_ERR_INTEGRITY, "tampered body rejected");
    ctht[0] = cs;
    CHECK(ratchet_decrypt(bob, ht, ctht, lt, pt, &plen) == CRYPTO_SUCCESS &&
          plen == strlen(t) && memcmp(pt, t, plen) == 0, "clean message opens after tamper attempts");

    /* 6. HE session refuses to serialize (persistence deferred to veil wiring). */
    unsigned char *blob = NULL; size_t blen = 0;
    CHECK(ratchet_session_serialize(alice, "pw", &blob, &blen) == CRYPTO_ERR_INVALID_INPUT,
          "HE session serialize refused (not yet supported)");
    free(blob);

    ratchet_session_free(alice);
    ratchet_session_free(bob);
    printf("\n%s\n", fails ? "SOME TESTS FAILED" : "ALL TESTS PASSED");
    return fails ? 1 : 0;
}
