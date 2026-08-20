/* PQ-TreeKEM tests (veil/docs/TREEKEM.md): every member converges to one root secret
 * after a commit, a second committer heals again, and post-compromise security — a
 * committer's update is never sealed to its own (possibly compromised) path, so its old
 * keys cannot open the new group secret. */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "treekem.h"
#include "crypto_utils.h"

static int fails = 0;
#define CHECK(cond, msg) do { \
    if (cond) { printf("  ok   %s\n", msg); } \
    else { printf("  FAIL %s\n", msg); fails++; } } while (0)

static int anc(uint32_t a, uint32_t leaf) { while (leaf > a) leaf >>= 1; return leaf == a; }

/* Everyone converges to the committer's root secret. */
static int converge(treekem_t **t, uint32_t n, uint32_t committer, treekem_commit_t *c) {
    if (treekem_commit(t[committer], c) != CRYPTO_SUCCESS) return 0;
    const unsigned char *r = treekem_root_secret(t[committer]);
    if (!r) return 0;
    for (uint32_t m = 0; m < n; m++) {
        if (m == committer) continue;
        if (treekem_process(t[m], c) != CRYPTO_SUCCESS) return 0;
        const unsigned char *rm = treekem_root_secret(t[m]);
        if (!rm || memcmp(rm, r, TREEKEM_SECRET) != 0) return 0;
    }
    return 1;
}

static void run(uint32_t N, const char *tag) {
    unsigned char (*pubs)[TREEKEM_MLKEM_PK] = malloc(N * TREEKEM_MLKEM_PK);
    unsigned char (*privs)[TREEKEM_MLKEM_SK] = malloc(N * TREEKEM_MLKEM_SK);
    treekem_t **t = malloc(N * sizeof *t);
    treekem_commit_t *c = malloc(sizeof *c);
    for (uint32_t m = 0; m < N; m++) treekem_keygen(pubs[m], privs[m]);
    for (uint32_t m = 0; m < N; m++) treekem_init(&t[m], N, m, pubs, privs[m]);

    char msg[64];
    snprintf(msg, sizeof msg, "%s: member 0 commit -> all converge", tag);
    CHECK(converge(t, N, 0, c), msg);

    snprintf(msg, sizeof msg, "%s: member %u commit -> all re-converge", tag, N - 1);
    CHECK(converge(t, N, N - 1, c), msg);

    /* PCS: member 1 heals. Its update must not be sealed to any node on its own path. */
    unsigned char root_before[TREEKEM_SECRET];
    memcpy(root_before, treekem_root_secret(t[1]), TREEKEM_SECRET);
    CHECK(treekem_commit(t[1], c) == CRYPTO_SUCCESS, "PCS: committer produces an update");
    uint32_t leaf1 = N + 1;
    int self_sealed = 0;
    for (uint32_t s = 0; s < c->n_steps; s++)
        for (uint32_t i = 0; i < c->step[s].n_enc; i++)
            if (anc(c->step[s].enc[i].recipient, leaf1)) self_sealed = 1;
    CHECK(!self_sealed, "PCS: no path secret is sealed to the committer's own compromised path");

    const unsigned char *r1 = treekem_root_secret(t[1]);
    CHECK(memcmp(r1, root_before, TREEKEM_SECRET) != 0, "PCS: healed root differs from the compromised one");
    int others_ok = 1;
    for (uint32_t m = 0; m < N; m++) {
        if (m == 1) continue;
        if (treekem_process(t[m], c) != CRYPTO_SUCCESS ||
            memcmp(treekem_root_secret(t[m]), r1, TREEKEM_SECRET) != 0) others_ok = 0;
    }
    CHECK(others_ok, "PCS: every other member still reaches the healed root");

    for (uint32_t m = 0; m < N; m++) treekem_free(t[m]);
    free(pubs); free(privs); free(t); free(c);
}

/* Dynamic membership: remove a member (forward secrecy) and add a new one (Welcome). */
static void run_dynamic(void) {
    const uint32_t N = 4;
    unsigned char (*pubs)[TREEKEM_MLKEM_PK] = malloc(N * TREEKEM_MLKEM_PK);
    unsigned char (*privs)[TREEKEM_MLKEM_SK] = malloc(N * TREEKEM_MLKEM_SK);
    treekem_t *t[4]; treekem_commit_t *c = malloc(sizeof *c);
    for (uint32_t m = 0; m < N; m++) treekem_keygen(pubs[m], privs[m]);
    for (uint32_t m = 0; m < N; m++) treekem_init(&t[m], N, m, pubs, privs[m]);
    CHECK(converge(t, N, 0, c), "dynamic: initial group converges");
    unsigned char R0[TREEKEM_SECRET]; memcpy(R0, treekem_root_secret(t[0]), TREEKEM_SECRET);

    /* Remove member 3 (leaf N+3 = 7): blank it, member 0 commits. */
    uint32_t leaf3 = N + 3;
    treekem_blank_leaf(t[0], leaf3);
    CHECK(treekem_commit(t[0], c) == CRYPTO_SUCCESS, "remove: committer re-keys around the removed leaf");
    int seals_removed = 0;
    for (uint32_t s = 0; s < c->n_steps; s++)
        for (uint32_t i = 0; i < c->step[s].n_enc; i++)
            if (anc(c->step[s].enc[i].recipient, leaf3)) seals_removed = 1;
    CHECK(!seals_removed, "remove: nothing is sealed to the removed member's path (forward secrecy)");
    int rm_ok = 1;
    for (uint32_t m = 1; m <= 2; m++)
        if (treekem_process(t[m], c) != CRYPTO_SUCCESS ||
            memcmp(treekem_root_secret(t[m]), treekem_root_secret(t[0]), TREEKEM_SECRET) != 0) rm_ok = 0;
    CHECK(rm_ok, "remove: remaining members reach the new root");
    CHECK(treekem_process(t[3], c) != CRYPTO_SUCCESS, "remove: the removed member cannot derive the new root");
    CHECK(memcmp(treekem_root_secret(t[0]), R0, TREEKEM_SECRET) != 0, "remove: group secret changed");
    treekem_free(t[3]);

    /* Add a fresh joiner back into the freed slot 7 (a Welcome-style join). */
    int slot = treekem_free_leaf(t[0]);
    CHECK(slot == (int)leaf3, "add: the freed slot is available");
    unsigned char jpub[TREEKEM_MLKEM_PK], jpriv[TREEKEM_MLKEM_SK];
    treekem_keygen(jpub, jpriv);
    CHECK(treekem_add_leaf(t[0], (uint32_t)slot, jpub) == CRYPTO_SUCCESS, "add: joiner leaf installed");
    CHECK(treekem_commit(t[0], c) == CRYPTO_SUCCESS, "add: committer commits");
    treekem_public_t *welcome = malloc(sizeof *welcome);
    treekem_export(t[0], welcome);
    treekem_t *tj = NULL;
    CHECK(treekem_import(&tj, welcome, (uint32_t)slot, jpriv) == CRYPTO_SUCCESS, "add: joiner builds its view from the Welcome");
    const unsigned char *radd = treekem_root_secret(t[0]);
    int add_ok = (treekem_process(tj, c) == CRYPTO_SUCCESS) &&
                 treekem_root_secret(tj) && memcmp(treekem_root_secret(tj), radd, TREEKEM_SECRET) == 0;
    for (uint32_t m = 1; m <= 2; m++)
        if (treekem_process(t[m], c) != CRYPTO_SUCCESS ||
            memcmp(treekem_root_secret(t[m]), radd, TREEKEM_SECRET) != 0) add_ok = 0;
    CHECK(add_ok, "add: joiner and existing members converge to the same root");

    treekem_free(t[0]); treekem_free(t[1]); treekem_free(t[2]); treekem_free(tj);
    free(pubs); free(privs); free(c); free(welcome);
}

/* Serialization for transport + epoch secret export. */
static void run_serial(void) {
    const uint32_t N = 4;
    unsigned char (*pubs)[TREEKEM_MLKEM_PK] = malloc(N * TREEKEM_MLKEM_PK);
    unsigned char (*privs)[TREEKEM_MLKEM_SK] = malloc(N * TREEKEM_MLKEM_SK);
    treekem_t *t[4]; treekem_commit_t *c = malloc(sizeof *c), *c2 = malloc(sizeof *c2);
    for (uint32_t m = 0; m < N; m++) treekem_keygen(pubs[m], privs[m]);
    for (uint32_t m = 0; m < N; m++) treekem_init(&t[m], N, m, pubs, privs[m]);

    treekem_commit(t[0], c);
    /* A commit survives a serialize/deserialize round-trip and still processes. */
    unsigned char *cb = NULL; size_t cl = 0;
    CHECK(treekem_commit_serialize(c, &cb, &cl) == CRYPTO_SUCCESS, "commit serialize");
    CHECK(treekem_commit_deserialize(cb, cl, c2) == CRYPTO_SUCCESS, "commit deserialize");
    CHECK(treekem_process(t[1], c2) == CRYPTO_SUCCESS &&
          memcmp(treekem_root_secret(t[1]), treekem_root_secret(t[0]), TREEKEM_SECRET) == 0,
          "deserialized commit converges to the committer's root");
    /* Bounds-checked parser: truncated or malformed wire commits are rejected. */
    treekem_commit_t *cbad = malloc(sizeof *cbad);
    CHECK(treekem_commit_deserialize(cb, cl - 1, cbad) != CRYPTO_SUCCESS, "truncated wire commit rejected");
    CHECK(treekem_commit_deserialize(cb, 4, cbad) != CRYPTO_SUCCESS, "short wire commit rejected");
    { unsigned char *cc = malloc(cl); memcpy(cc, cb, cl); cc[7] = 0xff;   /* absurd n_steps */
      CHECK(treekem_commit_deserialize(cc, cl, cbad) != CRYPTO_SUCCESS, "oversized n_steps rejected"); free(cc); }
    free(cbad); free(cb);

    /* Epoch export: converged members derive the same labelled secret. */
    treekem_process(t[2], c); treekem_process(t[3], c);
    unsigned char k0[32], k1[32];
    CHECK(treekem_export_secret(t[0], "veil-mls-app", k0, 32) == CRYPTO_SUCCESS &&
          treekem_export_secret(t[1], "veil-mls-app", k1, 32) == CRYPTO_SUCCESS &&
          memcmp(k0, k1, 32) == 0, "epoch export_secret agrees across members");

    /* Public tree (Welcome) round-trips. */
    treekem_public_t *pt = malloc(sizeof *pt), *pt2 = malloc(sizeof *pt2);
    treekem_export(t[0], pt);
    unsigned char *pb = NULL; size_t pl = 0;
    CHECK(treekem_public_serialize(pt, &pb, &pl) == CRYPTO_SUCCESS &&
          treekem_public_deserialize(pb, pl, pt2) == CRYPTO_SUCCESS &&
          pt2->n_leaves == pt->n_leaves, "public tree serialize/deserialize round-trips");
    free(pb);

    for (uint32_t m = 0; m < N; m++) treekem_free(t[m]);
    free(pubs); free(privs); free(c); free(c2); free(pt); free(pt2);
}

int main(void) {
    run(2, "N=2");
    run(4, "N=4");
    run(8, "N=8");
    run_dynamic();
    run_serial();

    /* A commit cannot be processed by its own author, and a random member's root is
     * unset before any commit. */
    unsigned char (*pubs)[TREEKEM_MLKEM_PK] = malloc(4 * TREEKEM_MLKEM_PK);
    unsigned char (*privs)[TREEKEM_MLKEM_SK] = malloc(4 * TREEKEM_MLKEM_SK);
    treekem_t *t0, *t1; treekem_commit_t *c = malloc(sizeof *c);
    for (int m = 0; m < 4; m++) treekem_keygen(pubs[m], privs[m]);
    treekem_init(&t0, 4, 0, pubs, privs[0]);
    treekem_init(&t1, 4, 1, pubs, privs[1]);
    CHECK(treekem_root_secret(t1) == NULL, "no root secret before any commit");
    treekem_commit(t0, c);
    CHECK(treekem_process(t0, c) == CRYPTO_ERR_INVALID_INPUT, "cannot process your own commit");
    /* A tampered sealed secret is rejected (integrity). */
    c->step[0].enc[0].sealed[0] ^= 1;
    CHECK(treekem_process(t1, c) == CRYPTO_ERR_INTEGRITY || treekem_root_secret(t1) == NULL,
          "tampered update rejected");
    treekem_free(t0); treekem_free(t1); free(pubs); free(privs); free(c);

    printf("\n%s\n", fails ? "SOME TESTS FAILED" : "ALL TESTS PASSED");
    return fails ? 1 : 0;
}
