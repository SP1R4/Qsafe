/* Sender-key group ratchet tests (veil/docs/GROUP_MESSAGING.md): multi-member
 * round-trip, out-of-order/skipped delivery, sender-key rotation, and the security
 * property that a member who knows the shared chain key still cannot forge another
 * member's messages (the per-message ML-DSA signature stops it). */

#include <stdio.h>
#include <string.h>

#include "group.h"
#include "crypto_utils.h"

static int fails = 0;
#define CHECK(cond, msg) do { \
    if (cond) { printf("  ok   %s\n", msg); } \
    else { printf("  FAIL %s\n", msg); fails++; } } while (0)

#define FRAME_MAX (GROUP_OVERHEAD + 256)

int main(void) {
    /* Three members; each publishes a sender key, others install receiving chains. */
    group_sender_t A, B;
    CHECK(group_sender_init(&A) == CRYPTO_SUCCESS, "member A sender key");
    CHECK(group_sender_init(&B) == CRYPTO_SUCCESS, "member B sender key");

    unsigned char skdmA[GROUP_SKDM_SIZE], skdmB[GROUP_SKDM_SIZE];
    group_sender_distribution(&A, skdmA);
    group_sender_distribution(&B, skdmB);

    group_receiver_t B_fromA, C_fromA;     /* B and C receive A */
    group_receiver_t A_fromB;              /* A receives B */
    CHECK(group_receiver_init(&B_fromA, skdmA) == CRYPTO_SUCCESS, "B installs A's sender key");
    CHECK(group_receiver_init(&C_fromA, skdmA) == CRYPTO_SUCCESS, "C installs A's sender key");
    group_receiver_init(&A_fromB, skdmB);

    unsigned char f[FRAME_MAX], pt[256]; size_t fl, pl;

    /* 1. A -> group; both B and C decrypt the same frame. */
    const char *m1 = "hello group";
    CHECK(group_encrypt(&A, (const unsigned char *)m1, strlen(m1), f, &fl) == CRYPTO_SUCCESS, "A encrypts");
    CHECK(group_decrypt(&B_fromA, f, fl, pt, &pl) == CRYPTO_SUCCESS && pl == strlen(m1) && memcmp(pt, m1, pl) == 0, "B decrypts A");
    CHECK(group_decrypt(&C_fromA, f, fl, pt, &pl) == CRYPTO_SUCCESS && pl == strlen(m1) && memcmp(pt, m1, pl) == 0, "C decrypts A");

    /* 2. B -> group; A decrypts (independent chain). */
    const char *m2 = "hi from B";
    group_encrypt(&B, (const unsigned char *)m2, strlen(m2), f, &fl);
    CHECK(group_decrypt(&A_fromB, f, fl, pt, &pl) == CRYPTO_SUCCESS && memcmp(pt, m2, pl) == 0, "A decrypts B");

    /* 3. Out-of-order within A's chain: A sends x,y,z; C receives z, then x, then y. */
    unsigned char fx[FRAME_MAX], fy[FRAME_MAX], fz[FRAME_MAX]; size_t lx, ly, lz;
    group_encrypt(&A, (const unsigned char *)"x", 1, fx, &lx);
    group_encrypt(&A, (const unsigned char *)"y", 1, fy, &ly);
    group_encrypt(&A, (const unsigned char *)"z", 1, fz, &lz);
    CHECK(group_decrypt(&C_fromA, fz, lz, pt, &pl) == CRYPTO_SUCCESS && pt[0] == 'z', "C decrypts z first (skips)");
    CHECK(group_decrypt(&C_fromA, fx, lx, pt, &pl) == CRYPTO_SUCCESS && pt[0] == 'x', "C decrypts x from skipped key");
    CHECK(group_decrypt(&C_fromA, fy, ly, pt, &pl) == CRYPTO_SUCCESS && pt[0] == 'y', "C decrypts y from skipped key");
    CHECK(group_decrypt(&C_fromA, fx, lx, pt, &pl) == CRYPTO_ERR_INTEGRITY, "replay of a consumed message rejected");

    /* 4. Forgery: member C knows A's chain key (it decrypts A's messages), but cannot
     * sign as A. C builds a message on A's chain with its OWN signature key; B rejects. */
    group_sender_t forge;
    group_sender_init(&forge);                 /* fresh (C's) signature keypair */
    memcpy(forge.ck, skdmA, GROUP_KEY_SIZE);   /* A's initial chain key, as any member has it */
    forge.index = 0;
    unsigned char ff[FRAME_MAX]; size_t ffl;
    group_encrypt(&forge, (const unsigned char *)"i am A", 6, ff, &ffl);
    group_receiver_t victim; group_receiver_init(&victim, skdmA);
    CHECK(group_decrypt(&victim, ff, ffl, pt, &pl) == CRYPTO_ERR_INTEGRITY,
          "forged message from a chain-key holder rejected (signature)");

    /* 5. Tamper: flip a signature byte, a ciphertext byte, and the index — all rejected;
     * a clean frame still opens afterwards (transactional, no state corruption). */
    unsigned char ft[FRAME_MAX]; size_t ftl;
    group_receiver_t D_fromA; group_receiver_init(&D_fromA, skdmA);
    /* bring D up to A's current index by replaying the earlier frames in order */
    group_decrypt(&D_fromA, f, fl, pt, &pl);   /* index 0 (m1) */
    group_encrypt(&A, (const unsigned char *)"tamper", 6, ft, &ftl);
    unsigned char save = ft[10]; ft[10] ^= 1;  /* inside the signature */
    CHECK(group_decrypt(&D_fromA, ft, ftl, pt, &pl) == CRYPTO_ERR_INTEGRITY, "tampered signature rejected");
    ft[10] = save;
    unsigned char cs = ft[ftl - 1]; ft[ftl - 1] ^= 1;   /* inside ct/tag */
    CHECK(group_decrypt(&D_fromA, ft, ftl, pt, &pl) == CRYPTO_ERR_INTEGRITY, "tampered ciphertext rejected");
    ft[ftl - 1] = cs;
    unsigned char is = ft[0]; ft[0] ^= 1;               /* index (signature covers it) */
    CHECK(group_decrypt(&D_fromA, ft, ftl, pt, &pl) == CRYPTO_ERR_INTEGRITY, "tampered index rejected");
    ft[0] = is;
    CHECK(group_decrypt(&D_fromA, ft, ftl, pt, &pl) == CRYPTO_SUCCESS && memcmp(pt, "tamper", 6) == 0,
          "clean frame opens after tamper attempts (transactional)");

    /* 6. Sender-key rotation (e.g. after a member leaves): A makes a fresh key and
     * redistributes; a new receiving chain decrypts new messages, old chain does not. */
    group_sender_t A2; group_sender_init(&A2);
    unsigned char skdmA2[GROUP_SKDM_SIZE]; group_sender_distribution(&A2, skdmA2);
    group_receiver_t B_fromA2; group_receiver_init(&B_fromA2, skdmA2);
    unsigned char fr[FRAME_MAX]; size_t frl;
    group_encrypt(&A2, (const unsigned char *)"rotated", 7, fr, &frl);
    CHECK(group_decrypt(&B_fromA2, fr, frl, pt, &pl) == CRYPTO_SUCCESS && memcmp(pt, "rotated", 7) == 0, "rotated sender key works");
    CHECK(group_decrypt(&B_fromA, fr, frl, pt, &pl) == CRYPTO_ERR_INTEGRITY, "old chain rejects rotated-key message");

    /* 7. State at rest: serialize/restore sender and receiver mid-stream and keep going. */
    {
        unsigned char *sb = NULL; size_t sbl = 0;
        CHECK(group_sender_serialize(&A2, "pw", &sb, &sbl) == CRYPTO_SUCCESS, "sender serialize");
        group_sender_t A2r;
        CHECK(group_sender_deserialize(sb, sbl, "pw", &A2r) == CRYPTO_SUCCESS, "sender deserialize");
        group_sender_t bad_s;
        CHECK(group_sender_deserialize(sb, sbl, "wrong", &bad_s) == CRYPTO_ERR_INTEGRITY, "sender wrong passphrase rejected");

        unsigned char *rb = NULL; size_t rbl = 0;
        CHECK(group_receiver_serialize(&B_fromA2, "pw", &rb, &rbl) == CRYPTO_SUCCESS, "receiver serialize");
        group_receiver_t B_fromA2r;
        CHECK(group_receiver_deserialize(rb, rbl, "pw", &B_fromA2r) == CRYPTO_SUCCESS, "receiver deserialize");

        /* Restored sender continues its chain; restored receiver decrypts it. */
        unsigned char fc[FRAME_MAX]; size_t fcl;
        group_encrypt(&A2r, (const unsigned char *)"after-restore", 13, fc, &fcl);
        CHECK(group_decrypt(&B_fromA2r, fc, fcl, pt, &pl) == CRYPTO_SUCCESS && memcmp(pt, "after-restore", 13) == 0,
              "restored sender+receiver resume the chain");

        unsigned char tb = rb[rbl / 2]; rb[rbl / 2] ^= 1;
        group_receiver_t bad_r;
        CHECK(group_receiver_deserialize(rb, rbl, "pw", &bad_r) == CRYPTO_ERR_INTEGRITY, "tampered receiver blob rejected");
        rb[rbl / 2] = tb;

        free(sb); free(rb);
        group_sender_free(&A2r);
    }

    group_sender_free(&A); group_sender_free(&B); group_sender_free(&forge); group_sender_free(&A2);
    printf("\n%s\n", fails ? "SOME TESTS FAILED" : "ALL TESTS PASSED");
    return fails ? 1 : 0;
}
