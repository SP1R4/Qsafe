/* libqsafe — thin, stable wrappers over the Qsafe engine (crypto_utils.c).
 * Each call manages its own OQS_KEM handle and crypto_config so callers don't
 * have to know the internals. */

#define _DEFAULT_SOURCE

#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <oqs/oqs.h>
#include "crypto_utils.h"
#include "libqsafe.h"

#define QSAFE_LIB_VERSION "7.0.0"

const char *qsafe_version(void) { return QSAFE_LIB_VERSION; }

const char *qsafe_strerror(qsafe_status status) {
    switch (status) {
        case QSAFE_OK:         return "ok";
        case QSAFE_ERR_IO:     return "I/O error";
        case QSAFE_ERR_MEMORY: return "out of memory";
        case QSAFE_ERR_CRYPTO: return "cryptographic operation failed";
        case QSAFE_ERR_INPUT:  return "invalid input";
        case QSAFE_ERR_AUTH:   return "authentication failed";
        default:               return "unknown error";
    }
}

static qsafe_status map_err(crypto_error_t e) {
    switch (e) {
        case CRYPTO_SUCCESS:           return QSAFE_OK;
        case CRYPTO_ERR_FILE_IO:       return QSAFE_ERR_IO;
        case CRYPTO_ERR_MEMORY:        return QSAFE_ERR_MEMORY;
        case CRYPTO_ERR_CRYPTO:        return QSAFE_ERR_CRYPTO;
        case CRYPTO_ERR_INVALID_INPUT: return QSAFE_ERR_INPUT;
        case CRYPTO_ERR_INTEGRITY:     return QSAFE_ERR_AUTH;
        default:                       return QSAFE_ERR_CRYPTO;
    }
}

static void base_config(crypto_config_t *c, const char *passphrase) {
    memset(c, 0, sizeof(*c));
    c->force_overwrite = 1;   /* library callers own the paths they pass */
    c->passphrase = passphrase;
}

qsafe_status qsafe_keygen(const char *secret_path, const char *public_path,
                          const char *passphrase) {
    if (!secret_path || !public_path || !passphrase || !*passphrase) return QSAFE_ERR_INPUT;
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
    if (!kem) return QSAFE_ERR_CRYPTO;

    crypto_config_t cfg;
    base_config(&cfg, passphrase);
    unsigned char *pub = NULL, *sec = NULL;
    size_t pl = 0, sl = 0;
    qsafe_status rc = QSAFE_ERR_CRYPTO;

    if (crypto_generate_identity(kem, &pub, &pl, &sec, &sl) != CRYPTO_SUCCESS) goto done;
    if (crypto_save_secret_key(secret_path, sec, sl, &cfg) != CRYPTO_SUCCESS) { rc = QSAFE_ERR_IO; goto done; }
    if (crypto_save_public_key(public_path, pub, pl, &cfg) != CRYPTO_SUCCESS) { rc = QSAFE_ERR_IO; goto done; }
    rc = QSAFE_OK;

done:
    if (sec) { OPENSSL_cleanse(sec, sl); free(sec); }
    free(pub);
    OQS_KEM_free(kem);
    return rc;
}

qsafe_status qsafe_encrypt(const char *in_path, const char *out_path,
                           const char *const *recipient_public_paths, size_t n_recipients) {
    if (!in_path || !out_path || !recipient_public_paths || n_recipients == 0) return QSAFE_ERR_INPUT;
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
    if (!kem) return QSAFE_ERR_CRYPTO;

    crypto_config_t cfg;
    base_config(&cfg, NULL);
    size_t explen = X25519_KEY_SIZE + kem->length_public_key;
    unsigned char **bufs = calloc(n_recipients, sizeof(*bufs));
    const unsigned char **ptrs = calloc(n_recipients, sizeof(*ptrs));
    qsafe_status rc = QSAFE_ERR_MEMORY;
    if (!bufs || !ptrs) goto done;

    for (size_t i = 0; i < n_recipients; i++) {
        bufs[i] = crypto_load_public_key(recipient_public_paths[i], explen, &cfg);
        if (!bufs[i]) { rc = QSAFE_ERR_IO; goto done; }
        ptrs[i] = bufs[i];
    }
    rc = map_err(crypto_encrypt_file(in_path, out_path, kem, ptrs, n_recipients, &cfg));

done:
    if (bufs) for (size_t i = 0; i < n_recipients; i++) free(bufs[i]);
    free(bufs);
    free((void *)ptrs);
    OQS_KEM_free(kem);
    return rc;
}

static qsafe_status decrypt_common(const char *in_path, const char *out_path,
                                   const char *secret_path, const char *passphrase, int check_only) {
    if (!in_path || !secret_path || !passphrase) return QSAFE_ERR_INPUT;
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
    if (!kem) return QSAFE_ERR_CRYPTO;

    crypto_config_t cfg;
    base_config(&cfg, passphrase);
    cfg.check_only = check_only;
    size_t slen = 0;
    unsigned char *sec = crypto_load_secret_key(secret_path, &slen, &cfg);
    qsafe_status rc;
    if (!sec || slen != X25519_KEY_SIZE + kem->length_secret_key) {
        rc = QSAFE_ERR_IO;
    } else {
        rc = map_err(crypto_decrypt_file(in_path, out_path ? out_path : "-", kem, sec, &cfg));
    }
    if (sec) { OPENSSL_cleanse(sec, slen); free(sec); }
    OQS_KEM_free(kem);
    return rc;
}

qsafe_status qsafe_decrypt(const char *in_path, const char *out_path,
                           const char *secret_path, const char *passphrase) {
    if (!out_path) return QSAFE_ERR_INPUT;
    return decrypt_common(in_path, out_path, secret_path, passphrase, 0);
}

qsafe_status qsafe_verify(const char *in_path, const char *secret_path, const char *passphrase) {
    return decrypt_common(in_path, NULL, secret_path, passphrase, 1);
}

qsafe_status qsafe_sign_keygen(const char *secret_path, const char *public_path,
                               const char *passphrase) {
    if (!secret_path || !public_path || !passphrase || !*passphrase) return QSAFE_ERR_INPUT;
    crypto_config_t cfg;
    base_config(&cfg, passphrase);
    return map_err(crypto_sig_keygen(secret_path, public_path, &cfg));
}

qsafe_status qsafe_sign(const char *in_path, const char *sig_path,
                        const char *sign_secret_path, const char *passphrase) {
    if (!in_path || !sig_path || !sign_secret_path || !passphrase) return QSAFE_ERR_INPUT;
    crypto_config_t cfg;
    base_config(&cfg, passphrase);
    return map_err(crypto_sign_file(in_path, sig_path, sign_secret_path, &cfg));
}

qsafe_status qsafe_verify_signature(const char *in_path, const char *sig_path,
                                    const char *sign_public_path) {
    if (!in_path || !sig_path || !sign_public_path) return QSAFE_ERR_INPUT;
    crypto_config_t cfg;
    base_config(&cfg, NULL);
    return map_err(crypto_verify_signature(in_path, sig_path, sign_public_path, &cfg));
}
