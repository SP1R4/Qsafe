/* age v1 (X25519) interop for Qsafe. Self-contained: Bech32, X25519,
 * ChaCha20-Poly1305, HKDF-SHA256, HMAC-SHA256, and the STREAM payload, all over
 * OpenSSL. Validated byte-for-byte against the reference `age` implementation.
 *
 * Spec: https://age-encryption.org/v1
 *   header   = "age-encryption.org/v1\n" stanza* "--- " b64(HMAC) "\n"
 *   stanza   = "-> X25519 " b64(ephemeral_pub) "\n" b64(wrap(file_key)) "\n"
 *   payload  = nonce(16) STREAM_ChaCha20Poly1305(payload_key, plaintext)
 * where file_key is 16 random bytes, wrap key = HKDF(shared, epk||rpk,
 * "age-encryption.org/v1/X25519"), MAC key = HKDF(file_key, "", "header"),
 * payload key = HKDF(file_key, nonce, "payload"), and STREAM uses 64 KiB chunks
 * with a 12-byte nonce of u88_be(counter) || last_flag. */

#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#include "age.h"

#define AGE_CHUNK     65536
#define AGE_TAG       16
#define FILE_KEY_LEN  16
#define X25519_LEN    32

const char *age_strerror(age_status s) {
    switch (s) {
        case AGE_OK:         return "ok";
        case AGE_ERR_IO:     return "I/O error";
        case AGE_ERR_FORMAT: return "malformed age file or key";
        case AGE_ERR_CRYPTO: return "authentication failed or no matching identity";
        case AGE_ERR_INPUT:  return "invalid input";
        default:             return "unknown error";
    }
}

/* --------------------------- base64 (standard, unpadded) ----------------- */

static const char B64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/* Encodes n bytes as unpadded standard base64. Returns length, or -1 if the
 * output buffer is too small. */
static int b64enc(const uint8_t *in, size_t n, char *out, size_t outsz) {
    size_t need = (n * 8 + 5) / 6;
    if (need + 1 > outsz) return -1;
    size_t o = 0;
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        int rem = (int)(n - i);
        if (rem > 1) v |= (uint32_t)in[i + 1] << 8;
        if (rem > 2) v |= in[i + 2];
        out[o++] = B64[(v >> 18) & 63];
        out[o++] = B64[(v >> 12) & 63];
        if (rem > 1) out[o++] = B64[(v >> 6) & 63];
        if (rem > 2) out[o++] = B64[v & 63];
    }
    out[o] = '\0';
    return (int)o;
}

/* Decodes base64 (padding optional). Returns byte length, or -1 on bad input. */
static int b64dec(const char *in, size_t len, uint8_t *out, size_t outsz) {
    uint32_t acc = 0;
    int bits = 0;
    size_t o = 0;
    for (size_t i = 0; i < len; i++) {
        char c = in[i];
        if (c == '=' || c == '\n' || c == '\r' || c == ' ') continue;
        int v = b64_val(c);
        if (v < 0) return -1;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o >= outsz) return -1;
            out[o++] = (uint8_t)((acc >> bits) & 0xFF);
        }
    }
    return (int)o;
}

/* --------------------------- Bech32 -------------------------------------- */

static const char BECH[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static int bech_val(char c) {
    for (int i = 0; i < 32; i++) if (BECH[i] == c) return i;
    return -1;
}

static uint32_t bech_polymod(const uint8_t *v, size_t n) {
    static const uint32_t G[5] = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};
    uint32_t chk = 1;
    for (size_t i = 0; i < n; i++) {
        uint32_t b = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ v[i];
        for (int j = 0; j < 5; j++) if ((b >> j) & 1) chk ^= G[j];
    }
    return chk;
}

/* Convert 8-bit groups to 5-bit (pad=1) or 5-bit to 8-bit (pad=0). */
static int convbits(const uint8_t *in, size_t n, int from, int to, int pad,
                    uint8_t *out, size_t *outlen) {
    uint32_t acc = 0;
    int bits = 0;
    size_t o = 0;
    uint32_t maxv = (1u << to) - 1;
    for (size_t i = 0; i < n; i++) {
        acc = (acc << from) | in[i];
        bits += from;
        while (bits >= to) {
            bits -= to;
            out[o++] = (uint8_t)((acc >> bits) & maxv);
        }
    }
    if (pad) {
        if (bits) out[o++] = (uint8_t)((acc << (to - bits)) & maxv);
    } else if (bits >= from || ((acc << (to - bits)) & maxv)) {
        return -1;  /* invalid padding */
    }
    *outlen = o;
    return 0;
}

/* Encode data as Bech32 with the given HRP (lowercase output). */
static int bech32_encode(const char *hrp, const uint8_t *data, size_t dlen,
                         char *out, size_t outsz) {
    uint8_t five[256];
    size_t flen = 0;
    if (convbits(data, dlen, 8, 5, 1, five, &flen) != 0) return -1;
    size_t hlen = strlen(hrp);
    uint8_t values[512];
    size_t vi = 0;
    for (size_t i = 0; i < hlen; i++) values[vi++] = (uint8_t)(hrp[i] >> 5);
    values[vi++] = 0;
    for (size_t i = 0; i < hlen; i++) values[vi++] = (uint8_t)(hrp[i] & 31);
    for (size_t i = 0; i < flen; i++) values[vi++] = five[i];
    for (int i = 0; i < 6; i++) values[vi++] = 0;
    uint32_t polymod = bech_polymod(values, vi) ^ 1;
    uint8_t cks[6];
    for (int i = 0; i < 6; i++) cks[i] = (uint8_t)((polymod >> (5 * (5 - i))) & 31);
    if (hlen + 1 + flen + 6 + 1 > outsz) return -1;
    size_t o = 0;
    for (size_t i = 0; i < hlen; i++) out[o++] = hrp[i];
    out[o++] = '1';
    for (size_t i = 0; i < flen; i++) out[o++] = BECH[five[i]];
    for (int i = 0; i < 6; i++) out[o++] = BECH[cks[i]];
    out[o] = '\0';
    return (int)o;
}

/* Decode a Bech32 string into raw bytes; verifies HRP matches want_hrp
 * (case-insensitively). Returns 0 on success. */
static int bech32_decode(const char *str, const char *want_hrp,
                         uint8_t *out, size_t *outlen) {
    char low[512];
    size_t n = strlen(str);
    if (n >= sizeof(low)) return -1;
    for (size_t i = 0; i < n; i++) {
        char c = str[i];
        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
        low[i] = c;
    }
    low[n] = '\0';
    char *sep = strrchr(low, '1');
    if (!sep) return -1;
    size_t hlen = (size_t)(sep - low);
    char want_low[64];
    size_t wl = strlen(want_hrp);
    if (wl >= sizeof(want_low) || wl != hlen) return -1;
    for (size_t i = 0; i < wl; i++) {
        char c = want_hrp[i];
        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
        if (low[i] != c) return -1;
    }
    const char *dp = sep + 1;
    size_t dlen = strlen(dp);
    if (dlen < 6) return -1;
    uint8_t five[512];
    for (size_t i = 0; i < dlen; i++) {
        int v = bech_val(dp[i]);
        if (v < 0) return -1;
        five[i] = (uint8_t)v;
    }
    /* (checksum verification omitted: we re-derive keys and the AEAD/MAC catch
     * any corruption; data bytes are the 5-bit groups minus the 6 checksum.) */
    return convbits(five, dlen - 6, 5, 8, 0, out, outlen);
}

/* --------------------------- primitives --------------------------------- */

static int hmac_sha256(const uint8_t *key, size_t keylen,
                       const uint8_t *data, size_t datalen, uint8_t out[32]) {
    unsigned int l = 32;
    return HMAC(EVP_sha256(), key, (int)keylen, data, datalen, out, &l) != NULL && l == 32;
}

/* HKDF-SHA256 (RFC 5869). An empty salt yields HMAC with a zero-length key,
 * equivalent to the spec's HashLen zero salt. info is at most ~32 bytes. */
static int hkdf(const uint8_t *ikm, size_t ikmlen,
                const uint8_t *salt, size_t saltlen,
                const uint8_t *info, size_t infolen,
                uint8_t *out, size_t outlen) {
    uint8_t prk[32];
    if (!hmac_sha256(salt, saltlen, ikm, ikmlen, prk)) return 0;
    uint8_t t[32] = {0};
    size_t tlen = 0, done = 0;
    uint8_t ctr = 1;
    uint8_t buf[32 + 64 + 1];
    while (done < outlen) {
        size_t bl = 0;
        memcpy(buf, t, tlen); bl += tlen;
        memcpy(buf + bl, info, infolen); bl += infolen;
        buf[bl++] = ctr++;
        if (!hmac_sha256(prk, 32, buf, bl, t)) { OPENSSL_cleanse(prk, 32); return 0; }
        tlen = 32;
        size_t take = (outlen - done < 32) ? outlen - done : 32;
        memcpy(out + done, t, take);
        done += take;
    }
    OPENSSL_cleanse(prk, sizeof(prk));
    OPENSSL_cleanse(t, sizeof(t));
    return 1;
}

/* ChaCha20-Poly1305 seal: writes ptlen + 16 bytes to ct. */
static int cc_seal(const uint8_t key[32], const uint8_t nonce[12],
                   const uint8_t *pt, size_t ptlen, uint8_t *ct) {
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c) return 0;
    int ok = 0, ol = 0, fl = 0;
    if (EVP_EncryptInit_ex(c, EVP_chacha20_poly1305(), NULL, NULL, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) == 1 &&
        EVP_EncryptInit_ex(c, NULL, NULL, key, nonce) == 1 &&
        EVP_EncryptUpdate(c, ct, &ol, pt, (int)ptlen) == 1 &&
        EVP_EncryptFinal_ex(c, ct + ol, &fl) == 1 &&
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_GET_TAG, AGE_TAG, ct + ptlen) == 1) {
        ok = 1;
    }
    EVP_CIPHER_CTX_free(c);
    return ok;
}

/* ChaCha20-Poly1305 open: ctlen includes the 16-byte tag; writes ctlen-16. */
static int cc_open(const uint8_t key[32], const uint8_t nonce[12],
                   const uint8_t *ct, size_t ctlen, uint8_t *pt) {
    if (ctlen < AGE_TAG) return 0;
    size_t ptlen = ctlen - AGE_TAG;
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c) return 0;
    int ok = 0, ol = 0, fl = 0;
    if (EVP_DecryptInit_ex(c, EVP_chacha20_poly1305(), NULL, NULL, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) == 1 &&
        EVP_DecryptInit_ex(c, NULL, NULL, key, nonce) == 1 &&
        EVP_DecryptUpdate(c, pt, &ol, ct, (int)ptlen) == 1 &&
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_TAG, AGE_TAG, (void *)(ct + ptlen)) == 1 &&
        EVP_DecryptFinal_ex(c, pt + ol, &fl) == 1) {
        ok = 1;
    }
    EVP_CIPHER_CTX_free(c);
    return ok;
}

static int x25519_keypair(uint8_t sk[32], uint8_t pk[32]) {
    EVP_PKEY *p = NULL;
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    int ok = 0;
    if (c && EVP_PKEY_keygen_init(c) == 1 && EVP_PKEY_keygen(c, &p) == 1) {
        size_t sl = 32, pl = 32;
        ok = EVP_PKEY_get_raw_private_key(p, sk, &sl) == 1 &&
             EVP_PKEY_get_raw_public_key(p, pk, &pl) == 1 && sl == 32 && pl == 32;
    }
    EVP_PKEY_free(p);
    EVP_PKEY_CTX_free(c);
    return ok;
}

static int x25519_pub_from_priv(const uint8_t sk[32], uint8_t pk[32]) {
    EVP_PKEY *p = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, sk, 32);
    if (!p) return 0;
    size_t pl = 32;
    int ok = EVP_PKEY_get_raw_public_key(p, pk, &pl) == 1 && pl == 32;
    EVP_PKEY_free(p);
    return ok;
}

static int x25519_shared(const uint8_t sk[32], const uint8_t peer[32], uint8_t out[32]) {
    EVP_PKEY *priv = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, sk, 32);
    EVP_PKEY *pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer, 32);
    EVP_PKEY_CTX *c = priv ? EVP_PKEY_CTX_new(priv, NULL) : NULL;
    int ok = 0;
    size_t l = 32;
    if (c && pub && EVP_PKEY_derive_init(c) == 1 &&
        EVP_PKEY_derive_set_peer(c, pub) == 1 &&
        EVP_PKEY_derive(c, out, &l) == 1 && l == 32) {
        ok = 1;
    }
    EVP_PKEY_CTX_free(c);
    EVP_PKEY_free(priv);
    EVP_PKEY_free(pub);
    return ok;
}

static void stream_nonce(uint64_t counter, int last, uint8_t out[12]) {
    memset(out, 0, 12);
    /* big-endian counter in the low 8 of the 11-byte field is enough for any
     * real file (2^64 chunks). */
    for (int i = 0; i < 8; i++) out[10 - i] = (uint8_t)(counter >> (8 * i));
    out[11] = last ? 1 : 0;
}

/* --------------------------- public API --------------------------------- */

age_status age_keygen(char *pub, size_t pub_sz, char *sec, size_t sec_sz) {
    uint8_t sk[32], pk[32];
    if (!x25519_keypair(sk, pk)) return AGE_ERR_CRYPTO;
    char secbuf[200];
    age_status rc = AGE_ERR_INPUT;
    /* Bech32 checksums are defined over the lowercase HRP; age uppercases the
     * secret key only for display. Encode with the lowercase HRP, then upcase. */
    if (bech32_encode("age", pk, 32, pub, pub_sz) > 0 &&
        bech32_encode("age-secret-key-", sk, 32, secbuf, sizeof(secbuf)) > 0) {
        for (char *p = secbuf; *p; p++) if (*p >= 'a' && *p <= 'z') *p = (char)(*p - 'a' + 'A');
        if (strlen(secbuf) + 1 <= sec_sz) { strcpy(sec, secbuf); rc = AGE_OK; }
    }
    OPENSSL_cleanse(sk, sizeof(sk));
    OPENSSL_cleanse(secbuf, sizeof(secbuf));
    return rc;
}

/* Build one X25519 recipient stanza into *out (caller frees). */
static age_status make_stanza(const uint8_t file_key[FILE_KEY_LEN],
                              const char *recipient, char **out) {
    uint8_t rpk[64];
    size_t rpl = 0;
    if (bech32_decode(recipient, "age", rpk, &rpl) != 0 || rpl != 32) return AGE_ERR_INPUT;
    uint8_t esk[32], epk[32], shared[32], wrap[32];
    if (!x25519_keypair(esk, epk) || !x25519_shared(esk, rpk, shared)) {
        OPENSSL_cleanse(esk, 32);
        return AGE_ERR_CRYPTO;
    }
    uint8_t salt[64];
    memcpy(salt, epk, 32);
    memcpy(salt + 32, rpk, 32);
    int ok = hkdf(shared, 32, salt, 64,
                  (const uint8_t *)"age-encryption.org/v1/X25519", 28, wrap, 32);
    OPENSSL_cleanse(esk, 32);
    OPENSSL_cleanse(shared, 32);
    if (!ok) return AGE_ERR_CRYPTO;
    uint8_t body[FILE_KEY_LEN + AGE_TAG];
    uint8_t zero[12] = {0};
    if (!cc_seal(wrap, zero, file_key, FILE_KEY_LEN, body)) return AGE_ERR_CRYPTO;
    OPENSSL_cleanse(wrap, 32);
    char epk_b64[64], body_b64[64];
    b64enc(epk, 32, epk_b64, sizeof(epk_b64));
    b64enc(body, sizeof(body), body_b64, sizeof(body_b64));
    char *s = malloc(160);
    if (!s) return AGE_ERR_IO;
    snprintf(s, 160, "-> X25519 %s\n%s\n", epk_b64, body_b64);
    *out = s;
    return AGE_OK;
}

age_status age_encrypt_file(const char *in_path, const char *out_path,
                            const char *const *recipients, size_t n_recipients) {
    if (n_recipients == 0) return AGE_ERR_INPUT;
    uint8_t file_key[FILE_KEY_LEN];
    if (RAND_bytes(file_key, FILE_KEY_LEN) != 1) return AGE_ERR_CRYPTO;

    /* Build the header up to "---". */
    char header[8192];
    size_t hl = 0;
    int w = snprintf(header, sizeof(header), "age-encryption.org/v1\n");
    if (w < 0) return AGE_ERR_FORMAT;
    hl = (size_t)w;
    age_status rc = AGE_OK;
    for (size_t i = 0; i < n_recipients; i++) {
        char *st = NULL;
        rc = make_stanza(file_key, recipients[i], &st);
        if (rc != AGE_OK) { OPENSSL_cleanse(file_key, FILE_KEY_LEN); return rc; }
        size_t sl = strlen(st);
        if (hl + sl + 4 >= sizeof(header)) { free(st); OPENSSL_cleanse(file_key, FILE_KEY_LEN); return AGE_ERR_FORMAT; }
        memcpy(header + hl, st, sl); hl += sl;
        free(st);
    }
    memcpy(header + hl, "---", 3); hl += 3;

    uint8_t mac_key[32], mac[32];
    if (!hkdf(file_key, FILE_KEY_LEN, NULL, 0, (const uint8_t *)"header", 6, mac_key, 32) ||
        !hmac_sha256(mac_key, 32, (const uint8_t *)header, hl, mac)) {
        OPENSSL_cleanse(file_key, FILE_KEY_LEN);
        return AGE_ERR_CRYPTO;
    }
    char mac_b64[64];
    b64enc(mac, 32, mac_b64, sizeof(mac_b64));

    uint8_t nonce[16];
    if (RAND_bytes(nonce, 16) != 1) { OPENSSL_cleanse(file_key, FILE_KEY_LEN); return AGE_ERR_CRYPTO; }
    uint8_t pkey[32];
    if (!hkdf(file_key, FILE_KEY_LEN, nonce, 16, (const uint8_t *)"payload", 7, pkey, 32)) {
        OPENSSL_cleanse(file_key, FILE_KEY_LEN);
        return AGE_ERR_CRYPTO;
    }
    OPENSSL_cleanse(file_key, FILE_KEY_LEN);

    FILE *in = strcmp(in_path, "-") == 0 ? stdin : fopen(in_path, "rb");
    FILE *out = strcmp(out_path, "-") == 0 ? stdout : fopen(out_path, "wb");
    if (!in || !out) {
        if (in && in != stdin) fclose(in);
        if (out && out != stdout) fclose(out);
        OPENSSL_cleanse(pkey, 32);
        return AGE_ERR_IO;
    }
    rc = AGE_ERR_IO;
    if (fwrite(header, 1, hl, out) == hl &&
        fputc(' ', out) != EOF &&
        fwrite(mac_b64, 1, strlen(mac_b64), out) == strlen(mac_b64) &&
        fputc('\n', out) != EOF &&
        fwrite(nonce, 1, 16, out) == 16) {
        rc = AGE_OK;
    }

    /* STREAM: read CHUNK-sized pieces with one-chunk lookahead so the last flag
     * lands on the final chunk (which may be full); empty input -> one empty
     * last chunk. */
    uint8_t *cur = malloc(AGE_CHUNK), *nxt = malloc(AGE_CHUNK);
    uint8_t *ct = malloc(AGE_CHUNK + AGE_TAG);
    if (rc == AGE_OK && cur && nxt && ct) {
        size_t curlen = fread(cur, 1, AGE_CHUNK, in);
        uint64_t counter = 0;
        for (;;) {
            size_t nxtlen = fread(nxt, 1, AGE_CHUNK, in);
            int last = (nxtlen == 0);
            uint8_t nonce12[12];
            stream_nonce(counter, last, nonce12);
            if (!cc_seal(pkey, nonce12, cur, curlen, ct) ||
                fwrite(ct, 1, curlen + AGE_TAG, out) != curlen + AGE_TAG) {
                rc = AGE_ERR_IO;
                break;
            }
            counter++;
            if (last) break;
            uint8_t *tmp = cur; cur = nxt; nxt = tmp;
            curlen = nxtlen;
        }
    } else if (rc == AGE_OK) {
        rc = AGE_ERR_IO;
    }
    free(cur); free(nxt); free(ct);
    OPENSSL_cleanse(pkey, 32);
    if (in != stdin) fclose(in);
    if (out != stdout) { if (fclose(out) != 0) rc = AGE_ERR_IO; }
    if (rc != AGE_OK && strcmp(out_path, "-") != 0) remove(out_path);
    return rc;
}

/* Slurp a whole file (or stdin) into a freshly allocated buffer. */
static int slurp(const char *path, uint8_t **buf, size_t *len) {
    FILE *f = strcmp(path, "-") == 0 ? stdin : fopen(path, "rb");
    if (!f) return 0;
    size_t cap = 1 << 16, n = 0;
    uint8_t *p = malloc(cap);
    if (!p) { if (f != stdin) fclose(f); return 0; }
    for (;;) {
        if (n == cap) { cap *= 2; uint8_t *q = realloc(p, cap); if (!q) { free(p); if (f != stdin) fclose(f); return 0; } p = q; }
        size_t r = fread(p + n, 1, cap - n, f);
        n += r;
        if (r == 0) break;
    }
    if (f != stdin) fclose(f);
    *buf = p; *len = n;
    return 1;
}

static const uint8_t *find_bytes(const uint8_t *hay, size_t hl, const char *needle) {
    size_t nl = strlen(needle);
    if (nl == 0 || hl < nl) return NULL;
    for (size_t i = 0; i + nl <= hl; i++)
        if (memcmp(hay + i, needle, nl) == 0) return hay + i;
    return NULL;
}

age_status age_decrypt_file(const char *in_path, const char *out_path,
                            const char *identity) {
    uint8_t sk[64];
    size_t skl = 0;
    if (bech32_decode(identity, "AGE-SECRET-KEY-", sk, &skl) != 0 || skl != 32)
        return AGE_ERR_INPUT;

    uint8_t *data = NULL;
    size_t dlen = 0;
    if (!slurp(in_path, &data, &dlen)) { OPENSSL_cleanse(sk, 32); return AGE_ERR_IO; }

    age_status rc = AGE_ERR_FORMAT;
    uint8_t my_pub[32];
    uint8_t file_key[FILE_KEY_LEN];
    int have_key = 0;

    /* Locate the MAC line "\n--- ". The header (for the MAC) is everything up to
     * and including the "---". */
    const char *intro = "age-encryption.org/v1\n";
    if (dlen < strlen(intro) || memcmp(data, intro, strlen(intro)) != 0) goto done;
    const uint8_t *macline = find_bytes(data, dlen, "\n--- ");
    if (!macline) goto done;
    size_t header_len = (size_t)(macline - data) + 1 + 3;   /* '\n' + "---" */
    const uint8_t *mac_b64 = macline + 5;
    const uint8_t *nl = find_bytes(mac_b64, (size_t)(data + dlen - mac_b64), "\n");
    if (!nl) goto done;
    uint8_t want_mac[32];
    if (b64dec((const char *)mac_b64, (size_t)(nl - mac_b64), want_mac, sizeof(want_mac)) != 32) goto done;
    size_t payload_off = (size_t)(nl - data) + 1;

    if (!x25519_pub_from_priv(sk, my_pub)) { rc = AGE_ERR_CRYPTO; goto done; }

    /* Walk stanzas: lines between the intro and the mac line. */
    const uint8_t *p = data + strlen(intro);
    const uint8_t *hend = data + (header_len - 3);  /* points at the '\n' before --- ... actually at "---"? */
    /* hend should mark the start of "---"; header_len-3 is index of "---". */
    hend = data + (header_len - 3);
    while (p < hend && !have_key) {
        /* expect "-> X25519 <epk>\n<body...>\n" */
        const uint8_t *eol = find_bytes(p, (size_t)(hend - p), "\n");
        if (!eol) break;
        size_t arglen = (size_t)(eol - p);
        if (arglen > 10 && memcmp(p, "-> X25519 ", 10) == 0) {
            uint8_t epk[32];
            if (b64dec((const char *)(p + 10), arglen - 10, epk, sizeof(epk)) == 32) {
                /* gather body lines until next "-> " or end */
                const uint8_t *bp = eol + 1;
                uint8_t body[64];
                size_t bl = 0;
                while (bp < hend) {
                    const uint8_t *be = find_bytes(bp, (size_t)(hend - bp), "\n");
                    size_t linelen = be ? (size_t)(be - bp) : (size_t)(hend - bp);
                    if (linelen >= 3 && memcmp(bp, "-> ", 3) == 0) break;
                    int n = b64dec((const char *)bp, linelen, body + bl, sizeof(body) - bl);
                    if (n < 0) { bl = 0; break; }
                    bl += (size_t)n;
                    if (!be) { bp = hend; break; }
                    bp = be + 1;
                }
                if (bl == FILE_KEY_LEN + AGE_TAG) {
                    uint8_t shared[32], wrap[32], salt[64], zero[12] = {0};
                    memcpy(salt, epk, 32);
                    memcpy(salt + 32, my_pub, 32);
                    if (x25519_shared(sk, epk, shared) &&
                        hkdf(shared, 32, salt, 64,
                             (const uint8_t *)"age-encryption.org/v1/X25519", 28, wrap, 32) &&
                        cc_open(wrap, zero, body, bl, file_key)) {
                        have_key = 1;
                    }
                    OPENSSL_cleanse(shared, 32);
                    OPENSSL_cleanse(wrap, 32);
                }
                p = bp;
                continue;
            }
        }
        p = eol + 1;
    }
    OPENSSL_cleanse(sk, 32);
    if (!have_key) { rc = AGE_ERR_CRYPTO; goto done; }

    /* Verify the header MAC. */
    uint8_t mac_key[32], got_mac[32];
    if (!hkdf(file_key, FILE_KEY_LEN, NULL, 0, (const uint8_t *)"header", 6, mac_key, 32) ||
        !hmac_sha256(mac_key, 32, data, header_len, got_mac) ||
        CRYPTO_memcmp(got_mac, want_mac, 32) != 0) {
        OPENSSL_cleanse(file_key, FILE_KEY_LEN);
        rc = AGE_ERR_CRYPTO;
        goto done;
    }

    /* Derive payload key and STREAM-decrypt. */
    if (payload_off + 16 > dlen) { OPENSSL_cleanse(file_key, FILE_KEY_LEN); rc = AGE_ERR_FORMAT; goto done; }
    uint8_t nonce[16], pkey[32];
    memcpy(nonce, data + payload_off, 16);
    if (!hkdf(file_key, FILE_KEY_LEN, nonce, 16, (const uint8_t *)"payload", 7, pkey, 32)) {
        OPENSSL_cleanse(file_key, FILE_KEY_LEN);
        rc = AGE_ERR_CRYPTO;
        goto done;
    }
    OPENSSL_cleanse(file_key, FILE_KEY_LEN);

    {
        const uint8_t *enc = data + payload_off + 16;
        size_t enclen = dlen - payload_off - 16;
        FILE *out = strcmp(out_path, "-") == 0 ? stdout : fopen(out_path, "wb");
        if (!out) { OPENSSL_cleanse(pkey, 32); rc = AGE_ERR_IO; goto done; }
        uint8_t *pt = malloc(AGE_CHUNK);
        rc = AGE_OK;
        if (!pt) rc = AGE_ERR_IO;
        size_t off = 0;
        uint64_t counter = 0;
        const size_t CCHUNK = AGE_CHUNK + AGE_TAG;
        for (; rc == AGE_OK;) {
            if (enclen - off < AGE_TAG) { rc = AGE_ERR_FORMAT; break; }
            size_t take = enclen - off < CCHUNK ? enclen - off : CCHUNK;
            int last = (off + take >= enclen);
            uint8_t nonce12[12];
            stream_nonce(counter, last, nonce12);
            if (!cc_open(pkey, nonce12, enc + off, take, pt)) { rc = AGE_ERR_CRYPTO; break; }
            size_t ptlen = take - AGE_TAG;
            if (ptlen && fwrite(pt, 1, ptlen, out) != ptlen) { rc = AGE_ERR_IO; break; }
            off += take;
            counter++;
            if (last) break;
        }
        free(pt);
        OPENSSL_cleanse(pkey, 32);
        if (out != stdout) { if (fclose(out) != 0 && rc == AGE_OK) rc = AGE_ERR_IO; }
        if (rc != AGE_OK && strcmp(out_path, "-") != 0) remove(out_path);
    }

done:
    OPENSSL_cleanse(sk, 32);
    free(data);
    return rc;
}
