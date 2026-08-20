/* Transparency-log / STH tests: signed-tree-head round-trip, client inclusion &
 * consistency verification against an operator log, and split-view (equivocation)
 * detection — the property that actually deprives an untrusted log of the ability to
 * equivocate undetectably. */

#include <stdio.h>
#include <string.h>

#include "translog.h"
#include "merkle.h"
#include "crypto_utils.h"

static int fails = 0;
#define CHECK(cond, msg) do { \
    if (cond) { printf("  ok   %s\n", msg); } \
    else { printf("  FAIL %s\n", msg); fails++; } } while (0)

static void bind(translog_t *log, const char *s) {
    translog_append(log, (const unsigned char *)s, strlen(s));
}

int main(void) {
    unsigned char pk[QSAFE_SIG_PUB_SIZE], sk[QSAFE_SIG_SEC_SIZE];
    unsigned char pk2[QSAFE_SIG_PUB_SIZE], sk2[QSAFE_SIG_SEC_SIZE];
    if (crypto_sig_keypair_raw(pk, sk) != CRYPTO_SUCCESS ||
        crypto_sig_keypair_raw(pk2, sk2) != CRYPTO_SUCCESS) { puts("keygen failed"); return 2; }

    /* Operator builds a log of five bindings and signs its head. */
    translog_t *log = translog_new();
    const char *names[] = { "alice:KA", "bob:KB", "carol:KC", "dave:KD", "erin:KE",
                            "frank:KF", "gina:KG", "hugo:KH" };
    for (int i = 0; i < 5; i++) bind(log, names[i]);

    translog_sth_t sth; translog_head(log, 1000, &sth);
    unsigned char sig[QSAFE_SIG_MAX_SIZE]; size_t siglen;
    CHECK(translog_sth_sign(sk, &sth, sig, &siglen) == CRYPTO_SUCCESS, "STH signed");
    CHECK(translog_sth_verify(pk, &sth, sig, siglen) == CRYPTO_SUCCESS, "STH verifies under log key");
    CHECK(translog_sth_verify(pk2, &sth, sig, siglen) != CRYPTO_SUCCESS, "STH rejected under a different key");

    /* Tampered STH fields must break the signature. */
    { translog_sth_t t = sth; t.size = 6;
      CHECK(translog_sth_verify(pk, &t, sig, siglen) != CRYPTO_SUCCESS, "tampered STH size rejected"); }
    { translog_sth_t t = sth; t.root[0] ^= 1;
      CHECK(translog_sth_verify(pk, &t, sig, siglen) != CRYPTO_SUCCESS, "tampered STH root rejected"); }
    { translog_sth_t t = sth; t.timestamp = 999;
      CHECK(translog_sth_verify(pk, &t, sig, siglen) != CRYPTO_SUCCESS, "tampered STH timestamp rejected"); }

    /* Client verifies each binding's inclusion under the signed STH. */
    int all_incl = 1;
    unsigned char proof[MERKLE_MAX_PROOF][MERKLE_HASH_SIZE]; size_t plen;
    for (int i = 0; i < 5; i++) {
        translog_prove_inclusion(log, (uint64_t)i, proof, &plen);
        if (!translog_verify_inclusion(&sth, (uint64_t)i, (const unsigned char *)names[i], strlen(names[i]), proof, plen))
            all_incl = 0;
    }
    CHECK(all_incl, "every binding proves inclusion under the STH");

    /* A binding that isn't in the log (wrong data at that index) is rejected. */
    translog_prove_inclusion(log, 2, proof, &plen);
    CHECK(!translog_verify_inclusion(&sth, 2, (const unsigned char *)"mallory:KM", 10, proof, plen),
          "forged binding rejected");

    /* Operator appends three more; client checks append-only consistency old -> new. */
    for (int i = 5; i < 8; i++) bind(log, names[i]);
    translog_sth_t sth2; translog_head(log, 2000, &sth2);
    unsigned char sig2[QSAFE_SIG_MAX_SIZE]; size_t sig2len;
    translog_sth_sign(sk, &sth2, sig2, &sig2len);
    unsigned char cproof[MERKLE_MAX_PROOF][MERKLE_HASH_SIZE]; size_t clen;
    translog_prove_consistency(log, sth.size, cproof, &clen);
    CHECK(translog_verify_consistency(&sth, &sth2, cproof, clen) == 1, "new STH is an append-only extension");
    CHECK(translog_gossip_check(pk, &sth, sig, siglen, &sth2, sig2, sig2len, cproof, clen) == TRANSLOG_CONSISTENT,
          "gossip: honest extension is consistent");

    /* Split view: a second, forked log of the same size but different first binding.
     * Both STHs are validly signed, but they cannot both be honest — detected as a fork. */
    translog_t *forkA = translog_new(); translog_t *forkB = translog_new();
    for (int i = 0; i < 5; i++) bind(forkA, names[i]);
    bind(forkB, "alice:EVIL");                       /* attacker swaps alice's key... */
    for (int i = 1; i < 5; i++) bind(forkB, names[i]);
    translog_sth_t sa, sb; translog_head(forkA, 3000, &sa); translog_head(forkB, 3000, &sb);
    unsigned char siga[QSAFE_SIG_MAX_SIZE], sigb[QSAFE_SIG_MAX_SIZE]; size_t sal, sbl;
    translog_sth_sign(sk, &sa, siga, &sal); translog_sth_sign(sk, &sb, sigb, &sbl);
    CHECK(translog_gossip_check(pk, &sa, siga, sal, &sb, sigb, sbl, NULL, 0) == TRANSLOG_FORK,
          "gossip: same-size divergent views = FORK (equivocation caught)");

    /* Split view across sizes: forkB grows to 8 on its rewritten history; the
     * consistency proof it offers cannot reconcile with forkA's size-5 root. */
    for (int i = 5; i < 8; i++) bind(forkB, names[i]);
    translog_sth_t sb8; translog_head(forkB, 4000, &sb8);
    unsigned char sigb8[QSAFE_SIG_MAX_SIZE]; size_t sb8l; translog_sth_sign(sk, &sb8, sigb8, &sb8l);
    translog_prove_consistency(forkB, 5, cproof, &clen);   /* proof consistent with forkB's own prefix */
    CHECK(translog_gossip_check(pk, &sa, siga, sal, &sb8, sigb8, sb8l, cproof, clen) == TRANSLOG_FORK,
          "gossip: extension on a rewritten history = FORK");

    /* Bad signature is distinguished from a fork. */
    unsigned char badsig[QSAFE_SIG_MAX_SIZE]; memcpy(badsig, sig, siglen); badsig[0] ^= 1;
    CHECK(translog_gossip_check(pk, &sth, badsig, siglen, &sth2, sig2, sig2len, cproof, clen) == TRANSLOG_BADSIG,
          "gossip: bad STH signature reported as BADSIG");

    translog_free(log); translog_free(forkA); translog_free(forkB);
    printf("\n%s\n", fails ? "SOME TESTS FAILED" : "ALL TESTS PASSED");
    return fails ? 1 : 0;
}
