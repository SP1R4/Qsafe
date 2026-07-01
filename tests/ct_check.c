/* ctgrind-style constant-time check (Linux/valgrind only).
 *
 * Marks secret inputs as *uninitialized* with valgrind client requests and
 * runs the key-handling paths. Memcheck reports any branch or memory index
 * that depends on uninitialized (= secret) data, which is exactly a
 * data-dependent-timing leak. Run under:
 *
 *   valgrind --error-exitcode=1 --track-origins=yes tests/ct_check
 *
 * Covered: scrypt passphrase derivation, HKDF hybrid-KEK expansion, and
 * ML-KEM-1024 decapsulation with a poisoned secret key. The AEAD open path is
 * deliberately NOT poisoned end-to-end: its final accept/reject branch on the
 * tag is public by design and would be a guaranteed false positive. */

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

    fprintf(stderr, "ct_check: done (report is valgrind's exit code)\n");
    return 0;
}
