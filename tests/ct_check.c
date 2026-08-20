/* ctgrind-style constant-time check (Linux/valgrind only).
 *
 * Marks secret inputs as *uninitialized* with valgrind client requests and
 * runs the key-handling paths. Memcheck reports any branch or memory index
 * that depends on uninitialized (= secret) data, which is exactly a
 * data-dependent-timing leak. Run under:
 *
 *   valgrind --error-exitcode=1 --track-origins=yes tests/ct_check
 *
 * Covered: scrypt passphrase derivation (both the default cost and vault's
 * cost, §5), HKDF hybrid-KEK expansion, ML-KEM-1024 decapsulation with a
 * poisoned secret key, and AES-256-GCM frame seal/open with a poisoned key
 * (§4 — the same crypto_gcm_seal_aad/open_aad every QSAFE007 payload frame
 * *and* every vault slot use, see docs/HIDDEN_VOLUMES.md). The AEAD open
 * path's ciphertext/tag/plaintext are deliberately NOT poisoned: whether the
 * tag matches is meant to be observable (that's the accept/reject decision
 * itself), so poisoning it would be a guaranteed false positive — only the
 * *key* stands in for "secret" here, exactly as the KEM section below only
 * poisons the secret key, not the ciphertext.
 *
 * The vault v2 anchor derivation's reduction into the placeable offset range
 * was changed from a data-dependent `x mod m` to a constant-time Lemire
 * multiply-shift `(x * m) >> 64` (src/vault.c, docs/HIDDEN_VOLUMES_V2.md §2),
 * so it no longer divides on the secret-derived `x`.
 *
 * Out of scope for this harness, found by manual review instead of memcheck:
 * vault_write's frame-filling loop (src/vault.c) does either an fread() (for
 * real content bytes) or a RAND_bytes() call (for padding) to fill each
 * frame, and those two have different throughput. Total wall-clock time of
 * `vault write` can therefore correlate with how much of the declared
 * --capacity is real content versus padding — a coarse timing side channel
 * memcheck can't see (content_len isn't cryptographic secret material, so
 * poisoning it here would be meaningless) but which matters for vault's own
 * deniability threat model. See docs/HIDDEN_VOLUMES.md §6. Not fixed: closing
 * it means deliberately wasting CPU time to equalize the two paths'
 * throughput, which is a real cost for a documented-but-narrow local-timing
 * threat (an adversary who can time your own machine's CLI invocation is
 * already most of the way to the "attacker on your machine" out-of-scope
 * line in THREAT_MODEL.md). */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>
#include <openssl/crypto.h>
#include "crypto_utils.h"

#ifdef __has_include
#  if __has_include(<valgrind/memcheck.h>)
#    include <valgrind/memcheck.h>
#    define HAVE_MEMCHECK 1
#  endif
#endif

#ifndef HAVE_MEMCHECK
#  define VALGRIND_MAKE_MEM_UNDEFINED(a, n) ((void)0)
#  define VALGRIND_MAKE_MEM_DEFINED(a, n) ((void)0)
#endif

int main(void) {
#ifndef HAVE_MEMCHECK
    fprintf(stderr, "ct_check: valgrind headers unavailable; nothing poisoned "
                    "(build on Linux with valgrind installed)\n");
#endif

    /* 1) scrypt: the passphrase is the secret. */
    {
        char pass[32] = "correct horse battery staple...";
        unsigned char salt[KDF_SALT_SIZE];
        unsigned char key[AES_KEY_SIZE];
        memset(salt, 0x24, sizeof(salt));
        VALGRIND_MAKE_MEM_UNDEFINED(pass, strlen(pass)); /* not the NUL */
        if (crypto_derive_key_from_passphrase(pass, salt, 1ULL << 14, 8, 1, key) != CRYPTO_SUCCESS) {
            fprintf(stderr, "ct_check: scrypt failed\n");
            return 2;
        }
        VALGRIND_MAKE_MEM_DEFINED(key, sizeof(key));
        fprintf(stderr, "ct_check: scrypt path exercised\n");
    }

    /* 1b) Argon2id: the passphrase is the secret. Argon2id is designed to be
     * data-independent in its memory access (unlike Argon2d), so it should not
     * branch/index on the poisoned passphrase. */
    {
        char pass[32] = "correct horse battery staple...";
        unsigned char salt[KDF_SALT_SIZE];
        unsigned char key[AES_KEY_SIZE];
        memset(salt, 0x24, sizeof(salt));
        VALGRIND_MAKE_MEM_UNDEFINED(pass, strlen(pass));
        if (crypto_derive_key_argon2id(pass, salt, 16, 3, 1, key) != CRYPTO_SUCCESS) {
            fprintf(stderr, "ct_check: argon2id failed\n");
            return 2;
        }
        VALGRIND_MAKE_MEM_DEFINED(key, sizeof(key));
        fprintf(stderr, "ct_check: Argon2id path exercised\n");
    }

    /* 2) HKDF: the input keying material (DH ‖ KEM shared secret) is secret. */
    {
        unsigned char ikm[64];
        unsigned char out[AES_KEY_SIZE];
        memset(ikm, 0x42, sizeof(ikm));
        VALGRIND_MAKE_MEM_UNDEFINED(ikm, sizeof(ikm));
        if (crypto_derive_aes_key(ikm, sizeof(ikm), out) != CRYPTO_SUCCESS) {
            fprintf(stderr, "ct_check: HKDF failed\n");
            return 2;
        }
        VALGRIND_MAKE_MEM_DEFINED(out, sizeof(out));
        fprintf(stderr, "ct_check: HKDF path exercised\n");
    }

    /* 2b) General HKDF with an explicit salt (crypto_hkdf_sha256) — the
     * primitive vault v2 derives slot keys with. Both the ikm (a scrypt output
     * in real use) and the salt (the per-slot nonce salt) are secret-adjacent;
     * poison both. */
    {
        unsigned char ikm[AES_KEY_SIZE];
        unsigned char salt[16];
        unsigned char out[AES_KEY_SIZE];
        memset(ikm, 0x53, sizeof(ikm));
        memset(salt, 0x64, sizeof(salt));
        VALGRIND_MAKE_MEM_UNDEFINED(ikm, sizeof(ikm));
        VALGRIND_MAKE_MEM_UNDEFINED(salt, sizeof(salt));
        if (crypto_hkdf_sha256(ikm, sizeof(ikm), salt, sizeof(salt),
                               (const unsigned char *)"qsafe-vault-slot-v2", 19,
                               out, sizeof(out)) != CRYPTO_SUCCESS) {
            fprintf(stderr, "ct_check: crypto_hkdf_sha256 failed\n");
            return 2;
        }
        VALGRIND_MAKE_MEM_DEFINED(out, sizeof(out));
        VALGRIND_MAKE_MEM_DEFINED(ikm, sizeof(ikm));
        VALGRIND_MAKE_MEM_DEFINED(salt, sizeof(salt));
        fprintf(stderr, "ct_check: general HKDF (explicit salt) path exercised\n");
    }

    /* 3) ML-KEM-1024 decapsulation: the KEM secret key is secret. Decaps with
     * implicit rejection must not branch on it. */
    {
        OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
        if (!kem) {
            fprintf(stderr, "ct_check: ML-KEM unavailable\n");
            return 2;
        }
        unsigned char *pk = malloc(kem->length_public_key);
        unsigned char *sk = malloc(kem->length_secret_key);
        unsigned char *ct = malloc(kem->length_ciphertext);
        unsigned char *ss = malloc(kem->length_shared_secret);
        unsigned char *ss2 = malloc(kem->length_shared_secret);
        if (!pk || !sk || !ct || !ss || !ss2 ||
            OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS ||
            OQS_KEM_encaps(kem, ct, ss, pk) != OQS_SUCCESS) {
            fprintf(stderr, "ct_check: KEM setup failed\n");
            return 2;
        }
        VALGRIND_MAKE_MEM_UNDEFINED(sk, kem->length_secret_key);
        if (OQS_KEM_decaps(kem, ss2, ct, sk) != OQS_SUCCESS) {
            /* The return status may legitimately depend on nothing secret. */
            fprintf(stderr, "ct_check: decaps returned failure\n");
        }
        VALGRIND_MAKE_MEM_DEFINED(ss2, kem->length_shared_secret);
        VALGRIND_MAKE_MEM_DEFINED(sk, kem->length_secret_key);
        OPENSSL_cleanse(sk, kem->length_secret_key);
        free(pk); free(sk); free(ct); free(ss); free(ss2);
        OQS_KEM_free(kem);
        fprintf(stderr, "ct_check: ML-KEM decaps path exercised\n");
    }

    /* 4) AES-256-GCM frame seal/open: the key is secret. Only the key is
     * poisoned — ciphertext/tag/plaintext stay "defined" throughout, since
     * those are meant to be public (they're what actually gets written to
     * disk) and poisoning them would flag the intentional, public
     * accept/reject decision as a false positive. */
    {
        unsigned char key[AES_KEY_SIZE];
        unsigned char nonce[AES_GCM_NONCE_SIZE];
        unsigned char pt[64], ct[64], tag[AES_GCM_TAG_SIZE], pt_out[64];
        memset(key, 0x37, sizeof(key));
        memset(nonce, 0, sizeof(nonce));
        memset(pt, 0x11, sizeof(pt));

        VALGRIND_MAKE_MEM_UNDEFINED(key, sizeof(key));
        if (!crypto_gcm_seal_aad(key, nonce, NULL, 0, pt, sizeof(pt), ct, tag)) {
            fprintf(stderr, "ct_check: gcm seal failed\n");
            return 2;
        }
        VALGRIND_MAKE_MEM_DEFINED(ct, sizeof(ct));
        VALGRIND_MAKE_MEM_DEFINED(tag, sizeof(tag));

        /* Re-poison for the open call — a fresh secret, not the seal call's
         * leftover-defined copy. */
        VALGRIND_MAKE_MEM_UNDEFINED(key, sizeof(key));
        if (!crypto_gcm_open_aad(key, nonce, NULL, 0, ct, sizeof(ct), tag, pt_out)) {
            fprintf(stderr, "ct_check: gcm open failed (unexpected on a freshly sealed, untampered tag)\n");
            return 2;
        }
        VALGRIND_MAKE_MEM_DEFINED(pt_out, sizeof(pt_out));
        VALGRIND_MAKE_MEM_DEFINED(key, sizeof(key));
        fprintf(stderr, "ct_check: AES-256-GCM frame seal/open path exercised (key poisoned)\n");
    }

    /* 5) scrypt at vault's cost tier (N=2^14): same function as §1, exercised
     * separately since it's the cost tier tests/fixtures/vault/ and the
     * fuzz_vault.c seed corpus actually use, and vault's threat model (a bare
     * passphrase with no separate high-entropy secret key behind it) makes
     * this KDF call the whole ballgame for that format — see
     * docs/HIDDEN_VOLUMES.md §3. */
    {
        char pass[32] = "vault fixture passphrase.......";
        unsigned char salt[KDF_SALT_SIZE];
        unsigned char key[AES_KEY_SIZE];
        memset(salt, 0x55, sizeof(salt));
        VALGRIND_MAKE_MEM_UNDEFINED(pass, strlen(pass));
        if (crypto_derive_key_from_passphrase(pass, salt, 1ULL << 14, 8, 1, key) != CRYPTO_SUCCESS) {
            fprintf(stderr, "ct_check: vault-cost scrypt failed\n");
            return 2;
        }
        VALGRIND_MAKE_MEM_DEFINED(key, sizeof(key));
        fprintf(stderr, "ct_check: vault-cost (N=2^14) scrypt path exercised\n");
    }

    fprintf(stderr, "ct_check: done (report is valgrind's exit code)\n");
    return 0;
}
