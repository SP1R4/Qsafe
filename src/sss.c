/* Shamir secret sharing over GF(256) — see include/sss.h for the share format.
 *
 * Arithmetic is over GF(2^8) with the AES reduction polynomial x^8+x^4+x^3+x+1
 * (0x11b), via log/exp tables. Table lookups are not constant-time; splitting
 * and joining are interactive, offline recovery operations, not per-message
 * hot paths, so key-independent timing is not a design goal here. */

/* Expose POSIX symbols (mode_t, PATH_MAX, chmod via platform.h) under -std=c11,
 * which otherwise restricts glibc to strict ISO C. Must precede all includes. */
#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include "platform.h"
#include "sss.h"

/* --- GF(256) --- */

static unsigned char gf_exp[512];
static unsigned char gf_log[256];
static int gf_ready = 0;

static void gf_init(void) {
    if (gf_ready) return;
    unsigned int x = 1;
    for (int i = 0; i < 255; i++) {
        gf_exp[i] = (unsigned char)x;
        gf_log[x] = (unsigned char)i;
        /* Multiply by 0x03 (= x+1), a primitive element of GF(2^8)/0x11b.
         * (0x02 is NOT primitive for this modulus — its order is only 51.) */
        x ^= x << 1;
        if (x & 0x100) x ^= 0x11b;
    }
    for (int i = 255; i < 512; i++) gf_exp[i] = gf_exp[i - 255];
    gf_ready = 1;
}

static unsigned char gf_mul(unsigned char a, unsigned char b) {
    if (a == 0 || b == 0) return 0;
    return gf_exp[gf_log[a] + gf_log[b]];
}

static unsigned char gf_div(unsigned char a, unsigned char b) {
    /* b must be nonzero (share indices are distinct and nonzero). */
    if (a == 0) return 0;
    return gf_exp[gf_log[a] + 255 - gf_log[b]];
}

const char *sss_strerror(sss_status s) {
    switch (s) {
        case SSS_OK:           return "ok";
        case SSS_ERR_INPUT:    return "invalid parameters or malformed share";
        case SSS_ERR_IO:       return "I/O error";
        case SSS_ERR_MEMORY:   return "out of memory";
        case SSS_ERR_CRYPTO:   return "random generation failed";
        case SSS_ERR_MISMATCH: return "shares do not belong together or are corrupt";
        default:               return "unknown error";
    }
}

static void store_u32le(unsigned char *p, uint32_t v) {
    for (int i = 0; i < 4; i++) p[i] = (unsigned char)((v >> (8 * i)) & 0xff);
}
static uint32_t load_u32le(const unsigned char *p) {
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) v |= (uint32_t)p[i] << (8 * i);
    return v;
}

static int sha256(const unsigned char *data, size_t len, unsigned char out[32]) {
    unsigned int dl = 0;
    return EVP_Digest(data, len, out, &dl, EVP_sha256(), NULL) == 1 && dl == 32;
}

sss_status sss_split_to_files(const unsigned char *secret, size_t secret_len,
                              unsigned int t, unsigned int n, const char *prefix) {
    if (!secret || secret_len == 0 || secret_len > 0xFFFFFFFFu || !prefix ||
        t < SSS_MIN_THRESHOLD || t > SSS_MAX_THRESHOLD || n < t || n > SSS_MAX_SHARES) {
        return SSS_ERR_INPUT;
    }
    gf_init();

    sss_status ret = SSS_ERR_MEMORY;
    unsigned char header[SSS_HEADER_SIZE];
    unsigned char set_id[SSS_SET_ID_SIZE];
    unsigned char digest[32];
    unsigned char coeffs[SSS_MAX_THRESHOLD - 1];
    unsigned char **shares = calloc(n, sizeof(*shares));
    FILE *f = NULL;
    if (!shares) return SSS_ERR_MEMORY;
    for (unsigned int i = 0; i < n; i++) {
        shares[i] = malloc(secret_len);
        if (!shares[i]) goto done;
    }

    if (RAND_bytes(set_id, sizeof(set_id)) != 1) { ret = SSS_ERR_CRYPTO; goto done; }
    if (!sha256(secret, secret_len, digest)) { ret = SSS_ERR_CRYPTO; goto done; }

    /* Per byte position: a fresh random degree-(t-1) polynomial with constant
     * term secret[j]; share i evaluates it at x = i+1 (Horner). */
    for (size_t j = 0; j < secret_len; j++) {
        if (RAND_bytes(coeffs, (int)(t - 1)) != 1) { ret = SSS_ERR_CRYPTO; goto done; }
        for (unsigned int i = 0; i < n; i++) {
            unsigned char x = (unsigned char)(i + 1);
            unsigned char y = coeffs[t - 2];
            for (int d = (int)t - 3; d >= 0; d--) {
                y = (unsigned char)(gf_mul(y, x) ^ coeffs[d]);
            }
            y = (unsigned char)(gf_mul(y, x) ^ secret[j]);
            shares[i][j] = y;
        }
    }

    memcpy(header, SSS_MAGIC, SSS_MAGIC_SIZE);
    memcpy(header + SSS_MAGIC_SIZE, set_id, SSS_SET_ID_SIZE);
    header[24] = 0; /* index, per share below */
    header[25] = (unsigned char)t;
    store_u32le(header + 26, (uint32_t)secret_len);
    memcpy(header + 30, digest, 32);

    for (unsigned int i = 0; i < n; i++) {
        char path[1024];
        if ((size_t)snprintf(path, sizeof(path), "%s.share%u", prefix, i + 1) >= sizeof(path)) {
            ret = SSS_ERR_INPUT;
            goto done;
        }
        header[24] = (unsigned char)(i + 1);
        f = fopen(path, "wb");
        if (!f) { perror("Error writing share"); ret = SSS_ERR_IO; goto done; }
        if (fwrite(header, 1, sizeof(header), f) != sizeof(header) ||
            fwrite(shares[i], 1, secret_len, f) != secret_len) {
            perror("Error writing share");
            fclose(f); f = NULL;
            ret = SSS_ERR_IO;
            goto done;
        }
        fclose(f); f = NULL;
        /* A share is unwrapped key material: owner-only, like a secret key. */
        qsafe_chmod_private(path);
    }
    ret = SSS_OK;

done:
    if (f) fclose(f);
    for (unsigned int i = 0; i < n; i++) {
        if (shares[i]) { OPENSSL_cleanse(shares[i], secret_len); free(shares[i]); }
    }
    free(shares);
    OPENSSL_cleanse(coeffs, sizeof(coeffs));
    return ret;
}

/* Reads one share file; *data is malloc'd (secret-sized). */
static sss_status read_share(const char *path, unsigned char set_id[SSS_SET_ID_SIZE],
                             unsigned char *index, unsigned char *threshold,
                             uint32_t *data_len, unsigned char digest[32],
                             unsigned char **data) {
    unsigned char header[SSS_HEADER_SIZE];
    *data = NULL;
    FILE *f = fopen(path, "rb");
    if (!f) { perror("Error opening share"); return SSS_ERR_IO; }

    sss_status ret = SSS_ERR_INPUT;
    if (fread(header, 1, sizeof(header), f) != sizeof(header) ||
        memcmp(header, SSS_MAGIC, SSS_MAGIC_SIZE) != 0) {
        fprintf(stderr, "Error: '%s' is not a Qsafe key share\n", path);
        goto done;
    }
    memcpy(set_id, header + SSS_MAGIC_SIZE, SSS_SET_ID_SIZE);
    *index = header[24];
    *threshold = header[25];
    *data_len = load_u32le(header + 26);
    memcpy(digest, header + 30, 32);
    if (*index == 0 || *threshold < SSS_MIN_THRESHOLD || *threshold > SSS_MAX_THRESHOLD ||
        *data_len == 0 || *data_len > (1u << 24)) {
        fprintf(stderr, "Error: '%s' declares invalid share parameters\n", path);
        goto done;
    }
    *data = malloc(*data_len);
    if (!*data) { ret = SSS_ERR_MEMORY; goto done; }
    if (fread(*data, 1, *data_len, f) != *data_len || fgetc(f) != EOF) {
        fprintf(stderr, "Error: '%s' is truncated or oversized\n", path);
        free(*data);
        *data = NULL;
        goto done;
    }
    ret = SSS_OK;

done:
    fclose(f);
    return ret;
}

sss_status sss_join_files(const char *const *paths, size_t n_paths,
                          unsigned char **out, size_t *out_len) {
    if (!paths || n_paths < SSS_MIN_THRESHOLD || n_paths > SSS_MAX_THRESHOLD || !out || !out_len) {
        return SSS_ERR_INPUT;
    }
    gf_init();

    sss_status ret;
    unsigned char set_id0[SSS_SET_ID_SIZE], digest0[32];
    unsigned char idx[SSS_MAX_THRESHOLD];
    unsigned char t = 0;
    uint32_t dlen = 0;
    unsigned char *data[SSS_MAX_THRESHOLD] = { 0 };
    unsigned char *secret = NULL;
    *out = NULL;
    *out_len = 0;

    for (size_t i = 0; i < n_paths; i++) {
        unsigned char set_id[SSS_SET_ID_SIZE], digest[32], ti;
        uint32_t dl;
        ret = read_share(paths[i], set_id, &idx[i], &ti, &dl, digest, &data[i]);
        if (ret != SSS_OK) goto done;
        if (i == 0) {
            memcpy(set_id0, set_id, sizeof(set_id0));
            memcpy(digest0, digest, sizeof(digest0));
            t = ti;
            dlen = dl;
        } else if (memcmp(set_id, set_id0, sizeof(set_id0)) != 0 || ti != t || dl != dlen ||
                   memcmp(digest, digest0, sizeof(digest0)) != 0) {
            fprintf(stderr, "Error: '%s' belongs to a different share set\n", paths[i]);
            ret = SSS_ERR_MISMATCH;
            goto done;
        }
        for (size_t k = 0; k < i; k++) {
            if (idx[k] == idx[i]) {
                fprintf(stderr, "Error: share index %u supplied twice\n", idx[i]);
                ret = SSS_ERR_MISMATCH;
                goto done;
            }
        }
    }
    if (n_paths < t) {
        fprintf(stderr, "Error: this share set needs %u shares (got %zu)\n", t, n_paths);
        ret = SSS_ERR_INPUT;
        goto done;
    }

    secret = malloc(dlen);
    if (!secret) { ret = SSS_ERR_MEMORY; goto done; }

    /* Lagrange interpolation at x = 0, using the first t shares:
     * secret[j] = sum_i y_i * prod_{k != i} x_k / (x_k ^ x_i). The basis
     * coefficients depend only on the indices, so compute them once. */
    unsigned char basis[SSS_MAX_THRESHOLD];
    for (unsigned int i = 0; i < t; i++) {
        unsigned char num = 1, den = 1;
        for (unsigned int k = 0; k < t; k++) {
            if (k == i) continue;
            num = gf_mul(num, idx[k]);
            den = gf_mul(den, (unsigned char)(idx[k] ^ idx[i]));
        }
        basis[i] = gf_div(num, den);
    }
    for (uint32_t j = 0; j < dlen; j++) {
        unsigned char v = 0;
        for (unsigned int i = 0; i < t; i++) {
            v ^= gf_mul(data[i][j], basis[i]);
        }
        secret[j] = v;
    }

    /* Fail closed: the reconstruction must match the digest recorded at split
     * time (catches corrupt shares and wrong combinations). */
    unsigned char check[32];
    if (!sha256(secret, dlen, check)) { ret = SSS_ERR_CRYPTO; goto done; }
    if (CRYPTO_memcmp(check, digest0, sizeof(check)) != 0) {
        fprintf(stderr, "Error: reconstructed key does not verify (corrupt share?)\n");
        ret = SSS_ERR_MISMATCH;
        goto done;
    }

    *out = secret;
    *out_len = dlen;
    secret = NULL;
    ret = SSS_OK;

done:
    for (size_t i = 0; i < n_paths; i++) {
        if (data[i]) { OPENSSL_cleanse(data[i], dlen ? dlen : 1); free(data[i]); }
    }
    if (secret) { OPENSSL_cleanse(secret, dlen); free(secret); }
    return ret;
}
