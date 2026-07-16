/* Soak/stress test for the ratchet — classical AND PQ — under a punishing
 * schedule: many rounds, each a burst of messages delivered OUT OF ORDER (heavy
 * skipped-key exercise), alternating direction (a ratchet step every round). Any
 * key-schedule desync, skipped-key bug, or PQ KEM-step error shows up as a failed
 * decrypt or a content mismatch. Deterministic PRNG so a failure is reproducible. */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "ratchet.h"
#include "crypto_utils.h"

static uint64_t g_st;
static uint32_t rr(void) { g_st ^= g_st << 13; g_st ^= g_st >> 7; g_st ^= g_st << 17; return (uint32_t)g_st; }

#define ROUNDS   200
#define MAXBURST 8
#define MAXMSG   64

/* One buffered frame: header + ciphertext + the plaintext it should decrypt to. */
typedef struct {
    unsigned char hdr[RATCHET_PQ_HDR_SIZE];
    unsigned char ct[128];
    size_t ctlen;
    char expect[32];
} frame_t;

static int soak(int pq, const char *label) {
    g_st = 0x1234567890abcdefULL ^ (uint64_t)pq;   /* reproducible, distinct per mode */
    unsigned char bsk[32], bpk[32];
    if (crypto_x25519_keypair(bsk, bpk) != CRYPTO_SUCCESS) return 0;

    /* Fixed shared secret, as if from a completed handshake. */
    unsigned char SK[32]; for (int i = 0; i < 32; i++) SK[i] = (unsigned char)(i * 7 + pq);
    ratchet_session_t *A = NULL, *B = NULL;
    if (pq) {
        if (ratchet_pq_init_initiator(SK, bpk, &A) != CRYPTO_SUCCESS) return 0;
        if (ratchet_pq_init_responder(SK, bpk, bsk, &B) != CRYPTO_SUCCESS) return 0;
    } else {
        if (ratchet_init_initiator(SK, bpk, &A) != CRYPTO_SUCCESS) return 0;
        if (ratchet_init_responder(SK, bpk, bsk, &B) != CRYPTO_SUCCESS) return 0;
    }

    frame_t fr[MAXMSG];
    unsigned char pt[128]; size_t pl;
    long total = 0, full = 0;           /* full = PQ-full (0x03) messages carrying KEM material */
    ratchet_session_t *S = A, *R = B;   /* A sends first (initiator has a sending chain) */

    for (int round = 0; round < ROUNDS; round++) {
        int burst = 1 + (int)(rr() % MAXBURST);
        /* sender encrypts a burst (same sending chain) */
        for (int i = 0; i < burst; i++) {
            snprintf(fr[i].expect, sizeof fr[i].expect, "r%d-m%d", round, i);
            size_t olen;
            if (ratchet_encrypt(S, (const unsigned char *)fr[i].expect, strlen(fr[i].expect),
                                fr[i].hdr, fr[i].ct, &olen) != CRYPTO_SUCCESS) {
                printf("  FAIL %s: encrypt round %d msg %d\n", label, round, i); return 0;
            }
            fr[i].ctlen = olen;
            if (fr[i].hdr[1] == RATCHET_TYPE_PQ_FULL) full++;
        }
        /* Fisher-Yates shuffle the burst -> out-of-order delivery. */
        int ord[MAXBURST]; for (int i = 0; i < burst; i++) ord[i] = i;
        for (int i = burst - 1; i > 0; i--) { int j = (int)(rr() % (uint32_t)(i + 1)); int t = ord[i]; ord[i] = ord[j]; ord[j] = t; }
        /* receiver decrypts in shuffled order; verify content. */
        for (int k = 0; k < burst; k++) {
            frame_t *f = &fr[ord[k]];
            if (ratchet_decrypt(R, f->hdr, f->ct, f->ctlen, pt, &pl) != CRYPTO_SUCCESS) {
                printf("  FAIL %s: decrypt round %d (msg '%s', shuffle pos %d)\n", label, round, f->expect, k); return 0;
            }
            if (pl != strlen(f->expect) || memcmp(pt, f->expect, pl) != 0) {
                printf("  FAIL %s: content mismatch round %d ('%s')\n", label, round, f->expect); return 0;
            }
            total++;
        }
        ratchet_session_t *t = S; S = R; R = t;   /* flip direction -> ratchet step next round */
    }

    ratchet_session_free(A);
    ratchet_session_free(B);
    if (pq) {
        /* Bandwidth win: KEM material rides only ~1/K of messages (plus bootstrap),
         * so the large majority must be lite. */
        long lite = total - full;
        if (lite <= total / 2) {
            printf("  FAIL %s: expected mostly lite messages, got %ld full / %ld total\n", label, full, total);
            return 0;
        }
        printf("  ok   %s: %ld messages (%ld full / %ld lite, ~1/%d KEM cadence), out-of-order, %d steps\n",
               label, total, full, lite, RATCHET_KEM_EVERY, ROUNDS);
    } else {
        printf("  ok   %s: %ld messages, out-of-order bursts, %d ratchet steps\n", label, total, ROUNDS);
    }
    return 1;
}

int main(void) {
    int ok = 1;
    ok &= soak(0, "classical ratchet soak");
    ok &= soak(1, "PQ ratchet soak");
    printf("\n%s\n", ok ? "ALL TESTS PASSED" : "SOME TESTS FAILED");
    return ok ? 0 : 1;
}
