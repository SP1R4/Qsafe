/* age-plugin-qsafe — post-quantum hybrid recipients for the age ecosystem.
 *
 * Implements the age plugin protocol (C2SP age-plugin, states recipient-v1 and
 * identity-v1) so any age client can encrypt to Qsafe's hybrid
 * X25519 + ML-KEM-1024 identities:
 *
 *   age-plugin-qsafe --keygen -o key.txt     # prints an age1qsafe1... recipient
 *   age -r age1qsafe1... -o file.age file
 *   age -d -i key.txt file.age
 *
 * Encoding:
 *   recipient  = Bech32("age1qsafe", public_blob)            # 1600 bytes
 *   identity   = Bech32("age-plugin-qsafe-", secret ‖ public) # 4800 bytes
 *   stanza     = "qsafe" with body e_pk(32) ‖ kem_ct(1568) ‖ nonce(12) ‖
 *                wrapped_file_key(16) ‖ tag(16), the standard Qsafe hybrid
 *                wrap (crypto_hybrid_wrap) of age's 16-byte file key under the
 *                HKDF label "qsafe-age-plugin-v1".
 *
 * The identity carries both halves of the keypair so recipient derivation
 * never depends on a KEM secret-key layout. Identities are unencrypted, like
 * native age identities: protect the file. */

#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>
#include <openssl/crypto.h>
#include "platform.h"
#include "crypto_utils.h"

#define PLUGIN_NAME "qsafe"
#define RECIPIENT_HRP "age1qsafe"
#define IDENTITY_HRP "age-plugin-qsafe-"
#define STANZA_TAG "qsafe"
#define AGE_HKDF_LABEL "qsafe-age-plugin-v1"
#define AGE_FILE_KEY_SIZE 16

#define PUB_BLOB_SIZE 1600     /* x25519_pub(32) + mlkem1024_pub(1568) */
#define SEC_BLOB_SIZE 3200     /* x25519_sec(32) + mlkem1024_sec(3168) */
#define ID_PAYLOAD_SIZE (SEC_BLOB_SIZE + PUB_BLOB_SIZE)
#define REC_BODY_SIZE (32 + 1568 + 12 + AGE_FILE_KEY_SIZE + 16) /* 1644 */

#define MAX_RECIPIENTS 64
#define MAX_IDENTITIES 16
#define MAX_FILE_KEYS 64
#define MAX_STANZAS 256
#define LINE_MAX_LEN 16384

/* ------------------------------- bech32 ---------------------------------- */
/* BIP-173 Bech32 without the 90-character length cap (age lifted it for
 * plugin recipients/identities). */

static const char B32_CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static uint32_t b32_polymod(const unsigned char *values, size_t len) {
    static const uint32_t GEN[5] = { 0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3 };
    uint32_t chk = 1;
    for (size_t i = 0; i < len; i++) {
        uint32_t top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ values[i];
        for (int j = 0; j < 5; j++) {
            if ((top >> j) & 1) chk ^= GEN[j];
        }
    }
    return chk;
}

/* hrp-expand ‖ data, shared by checksum create/verify. Caller frees. */
static unsigned char *b32_expand(const char *hrp, const unsigned char *data5, size_t dlen, size_t *outlen) {
    size_t hl = strlen(hrp);
    unsigned char *v = malloc(hl * 2 + 1 + dlen + 6);
    if (!v) return NULL;
    for (size_t i = 0; i < hl; i++) v[i] = (unsigned char)(hrp[i] >> 5);
    v[hl] = 0;
    for (size_t i = 0; i < hl; i++) v[hl + 1 + i] = (unsigned char)(hrp[i] & 0x1f);
    memcpy(v + hl * 2 + 1, data5, dlen);
    *outlen = hl * 2 + 1 + dlen;
    return v;
}

/* Converts between bit group sizes (frombits -> tobits); returns out length or
 * -1. pad=1 when encoding (8->5), pad=0 when decoding (5->8). */
static int convert_bits(const unsigned char *in, size_t inlen, int frombits, int tobits,
                        int pad, unsigned char *out, size_t outcap) {
    uint32_t acc = 0;
    int bits = 0;
    size_t n = 0;
    uint32_t maxv = (1u << tobits) - 1;
    for (size_t i = 0; i < inlen; i++) {
        acc = (acc << frombits) | in[i];
        bits += frombits;
        while (bits >= tobits) {
            bits -= tobits;
            if (n >= outcap) return -1;
            out[n++] = (unsigned char)((acc >> bits) & maxv);
        }
    }
    if (pad) {
        if (bits > 0) {
            if (n >= outcap) return -1;
            out[n++] = (unsigned char)((acc << (tobits - bits)) & maxv);
        }
    } else if (bits >= frombits || ((acc << (tobits - bits)) & maxv)) {
        return -1; /* non-canonical padding */
    }
    return (int)n;
}

/* Encodes data (8-bit bytes) as lowercase bech32 into out. Returns 1 on ok. */
static int bech32_encode(const char *hrp, const unsigned char *data, size_t dlen,
                         char *out, size_t outcap) {
    size_t d5cap = dlen * 8 / 5 + 2;
    unsigned char *d5 = malloc(d5cap);
    if (!d5) return 0;
    int d5len = convert_bits(data, dlen, 8, 5, 1, d5, d5cap);
    int ok = 0;
    if (d5len >= 0) {
        size_t explen = 0;
        unsigned char *exp = b32_expand(hrp, d5, (size_t)d5len, &explen);
        if (exp) {
            memset(exp + explen, 0, 6);
            uint32_t mod = b32_polymod(exp, explen + 6) ^ 1;
            size_t hl = strlen(hrp);
            if (hl + 1 + (size_t)d5len + 6 + 1 <= outcap) {
                memcpy(out, hrp, hl);
                out[hl] = '1';
                for (int i = 0; i < d5len; i++) out[hl + 1 + i] = B32_CHARSET[d5[i]];
                for (int i = 0; i < 6; i++) {
                    out[hl + 1 + d5len + i] = B32_CHARSET[(mod >> (5 * (5 - i))) & 0x1f];
                }
                out[hl + 1 + d5len + 6] = '\0';
                ok = 1;
            }
            free(exp);
        }
    }
    free(d5);
    return ok;
}

/* Decodes a bech32 string (either case, not mixed). On success returns 1 with
 * the HRP in hrp_out and 8-bit data in data/dlen. */
static int bech32_decode(const char *s, char *hrp_out, size_t hrpcap,
                         unsigned char *data, size_t datacap, size_t *dlen) {
    size_t slen = strlen(s);
    if (slen < 8) return 0;
    int has_lower = 0, has_upper = 0;
    for (size_t i = 0; i < slen; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 33 || c > 126) return 0;
        if (c >= 'a' && c <= 'z') has_lower = 1;
        if (c >= 'A' && c <= 'Z') has_upper = 1;
    }
    if (has_lower && has_upper) return 0;

    char *low = malloc(slen + 1);
    if (!low) return 0;
    for (size_t i = 0; i <= slen; i++) {
        char c = s[i];
        low[i] = (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
    }

    int ok = 0;
    const char *sep = strrchr(low, '1');
    if (sep && sep != low && (size_t)(sep - low) + 7 <= slen) {
        size_t hl = (size_t)(sep - low);
        size_t d5len = slen - hl - 1;
        unsigned char *d5 = malloc(d5len);
        if (d5 && hl < hrpcap) {
            int valid = 1;
            for (size_t i = 0; i < d5len; i++) {
                const char *p = strchr(B32_CHARSET, sep[1 + i]);
                if (!p) { valid = 0; break; }
                d5[i] = (unsigned char)(p - B32_CHARSET);
            }
            if (valid) {
                memcpy(hrp_out, low, hl);
                hrp_out[hl] = '\0';
                size_t explen = 0;
                unsigned char *exp = b32_expand(hrp_out, d5, d5len, &explen);
                if (exp) {
                    if (b32_polymod(exp, explen) == 1) {
                        int n = convert_bits(d5, d5len - 6, 5, 8, 0, data, datacap);
                        if (n >= 0) {
                            *dlen = (size_t)n;
                            ok = 1;
                        }
                    }
                    free(exp);
                }
            }
        }
        free(d5);
    }
    free(low);
    return ok;
}

/* ------------------------------ base64 ----------------------------------- */
/* Standard alphabet, unpadded (the age stanza body encoding). */

static const char B64_CHARSET[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static size_t b64_encode(const unsigned char *in, size_t inlen, char *out) {
    size_t n = 0;
    size_t i = 0;
    while (i + 3 <= inlen) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | in[i + 2];
        out[n++] = B64_CHARSET[(v >> 18) & 63];
        out[n++] = B64_CHARSET[(v >> 12) & 63];
        out[n++] = B64_CHARSET[(v >> 6) & 63];
        out[n++] = B64_CHARSET[v & 63];
        i += 3;
    }
    if (inlen - i == 1) {
        uint32_t v = (uint32_t)in[i] << 16;
        out[n++] = B64_CHARSET[(v >> 18) & 63];
        out[n++] = B64_CHARSET[(v >> 12) & 63];
    } else if (inlen - i == 2) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8);
        out[n++] = B64_CHARSET[(v >> 18) & 63];
        out[n++] = B64_CHARSET[(v >> 12) & 63];
        out[n++] = B64_CHARSET[(v >> 6) & 63];
    }
    out[n] = '\0';
    return n;
}

static int b64_val(char c) {
    const char *p = strchr(B64_CHARSET, c);
    return (p && c) ? (int)(p - B64_CHARSET) : -1;
}

/* Returns decoded length or -1 (rejects padding and non-canonical tails). */
static int b64_decode(const char *in, size_t inlen, unsigned char *out, size_t outcap) {
    if (inlen % 4 == 1) return -1;
    size_t n = 0;
    uint32_t acc = 0;
    int bits = 0;
    for (size_t i = 0; i < inlen; i++) {
        int v = b64_val(in[i]);
        if (v < 0) return -1;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (n >= outcap) return -1;
            out[n++] = (unsigned char)((acc >> bits) & 0xff);
        }
    }
    if ((acc & ((1u << bits) - 1)) != 0) return -1; /* stray bits must be zero */
    return (int)n;
}

/* --------------------------- stanza wire I/O ------------------------------ */

typedef struct {
    char verb[64];
    char args[8][LINE_MAX_LEN];
    int nargs;
    unsigned char body[8192];
    size_t body_len;
} stanza_t;

/* Reads one "-> verb args" command plus its base64 body. Returns 1 on
 * success, 0 on EOF/parse error. */
static int read_stanza(stanza_t *st) {
    static char line[LINE_MAX_LEN];
    if (!fgets(line, sizeof(line), stdin)) return 0;
    size_t l = strlen(line);
    while (l > 0 && (line[l - 1] == '\n' || line[l - 1] == '\r')) line[--l] = '\0';
    if (strncmp(line, "-> ", 3) != 0) return 0;

    st->nargs = 0;
    st->body_len = 0;
    char *tok = line + 3;
    char *sp = strchr(tok, ' ');
    size_t vlen = sp ? (size_t)(sp - tok) : strlen(tok);
    if (vlen >= sizeof(st->verb)) return 0;
    memcpy(st->verb, tok, vlen);
    st->verb[vlen] = '\0';
    while (sp && st->nargs < 8) {
        tok = sp + 1;
        sp = strchr(tok, ' ');
        size_t alen = sp ? (size_t)(sp - tok) : strlen(tok);
        if (alen >= LINE_MAX_LEN) return 0;
        memcpy(st->args[st->nargs], tok, alen);
        st->args[st->nargs][alen] = '\0';
        st->nargs++;
    }

    /* Body: base64 lines wrapped at 64 columns; a short line terminates. */
    char b64[12288];
    size_t b64len = 0;
    for (;;) {
        if (!fgets(line, sizeof(line), stdin)) return 0;
        l = strlen(line);
        while (l > 0 && (line[l - 1] == '\n' || line[l - 1] == '\r')) line[--l] = '\0';
        if (b64len + l >= sizeof(b64)) return 0;
        memcpy(b64 + b64len, line, l);
        b64len += l;
        if (l < 64) break;
    }
    int n = b64_decode(b64, b64len, st->body, sizeof(st->body));
    if (n < 0) return 0;
    st->body_len = (size_t)n;
    return 1;
}

/* Writes "-> verbline" plus the base64 body (64-column wrapped, short final
 * line) and flushes. */
static void write_stanza(const char *verbline, const unsigned char *body, size_t body_len) {
    static char b64[12288];
    size_t n = b64_encode(body, body_len, b64);
    printf("-> %s\n", verbline);
    size_t off = 0;
    while (n - off >= 64) {
        fwrite(b64 + off, 1, 64, stdout);
        fputc('\n', stdout);
        off += 64;
    }
    /* Final short (possibly empty) line terminates the body. */
    fwrite(b64 + off, 1, n - off, stdout);
    fputc('\n', stdout);
    fflush(stdout);
}

/* Sends a phase-2 command and consumes the client's ok/fail response.
 * Returns 1 if the client answered "ok". */
static int send_and_ack(const char *verbline, const unsigned char *body, size_t body_len) {
    write_stanza(verbline, body, body_len);
    stanza_t resp;
    if (!read_stanza(&resp)) return 0;
    return strcmp(resp.verb, "ok") == 0;
}

static void send_error(const char *kind, const char *msg) {
    char verb[128];
    snprintf(verb, sizeof(verb), "error %s", kind);
    send_and_ack(verb, (const unsigned char *)msg, strlen(msg));
}

/* ------------------------------ keygen ----------------------------------- */

static int cmd_keygen(const char *out_path) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
    if (!kem) {
        fprintf(stderr, "Error: ML-KEM-1024 unavailable\n");
        return 1;
    }
    unsigned char *pub = NULL, *sec = NULL;
    size_t pl = 0, sl = 0;
    int rc = 1;
    char *recip = malloc(8192), *ident = malloc(16384);
    unsigned char payload[ID_PAYLOAD_SIZE];

    if (!recip || !ident) goto done;
    if (crypto_generate_identity(kem, &pub, &pl, &sec, &sl) != CRYPTO_SUCCESS ||
        pl != PUB_BLOB_SIZE || sl != SEC_BLOB_SIZE) {
        fprintf(stderr, "Error: keypair generation failed\n");
        goto done;
    }
    memcpy(payload, sec, SEC_BLOB_SIZE);
    memcpy(payload + SEC_BLOB_SIZE, pub, PUB_BLOB_SIZE);

    if (!bech32_encode(RECIPIENT_HRP, pub, PUB_BLOB_SIZE, recip, 8192) ||
        !bech32_encode(IDENTITY_HRP, payload, ID_PAYLOAD_SIZE, ident, 16384)) {
        fprintf(stderr, "Error: bech32 encoding failed\n");
        goto done;
    }
    /* Identities are conventionally displayed uppercase. */
    for (char *c = ident; *c; c++) {
        if (*c >= 'a' && *c <= 'z') *c = (char)(*c - 'a' + 'A');
    }

    FILE *f = out_path ? fopen(out_path, "w") : stdout;
    if (!f) {
        fprintf(stderr, "Error: cannot write '%s'\n", out_path);
        goto done;
    }
    fprintf(f, "# public key: %s\n%s\n", recip, ident);
    if (out_path) {
        fclose(f);
        qsafe_chmod_private(out_path);
        fprintf(stderr, "Public key: %s\n", recip);
    }
    rc = 0;

done:
    OPENSSL_cleanse(payload, sizeof(payload));
    if (ident) { OPENSSL_cleanse(ident, 16384); free(ident); }
    free(recip);
    if (sec) { OPENSSL_cleanse(sec, sl); free(sec); }
    free(pub);
    OQS_KEM_free(kem);
    return rc;
}

/* Converts identities on stdin (or a file) to their recipients, like
 * age-keygen -y. */
static int cmd_pubkey(const char *in_path) {
    FILE *f = in_path ? fopen(in_path, "r") : stdin;
    if (!f) {
        fprintf(stderr, "Error: cannot open '%s'\n", in_path);
        return 1;
    }
    char line[LINE_MAX_LEN];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        size_t l = strlen(line);
        while (l > 0 && (line[l - 1] == '\n' || line[l - 1] == '\r')) line[--l] = '\0';
        if (line[0] == '#' || line[0] == '\0') continue;
        char hrp[64];
        unsigned char payload[ID_PAYLOAD_SIZE + 16];
        size_t plen = 0;
        char recip[8192];
        if (bech32_decode(line, hrp, sizeof(hrp), payload, sizeof(payload), &plen) &&
            strcmp(hrp, IDENTITY_HRP) == 0 && plen == ID_PAYLOAD_SIZE &&
            bech32_encode(RECIPIENT_HRP, payload + SEC_BLOB_SIZE, PUB_BLOB_SIZE, recip, sizeof(recip))) {
            printf("%s\n", recip);
            found = 1;
        }
        OPENSSL_cleanse(payload, sizeof(payload));
    }
    if (in_path) fclose(f);
    if (!found) fprintf(stderr, "Error: no %s identity found\n", PLUGIN_NAME);
    return found ? 0 : 1;
}

/* --------------------------- recipient-v1 -------------------------------- */

static int run_recipient_v1(void) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
    if (!kem) return 1;

    static unsigned char recipients[MAX_RECIPIENTS][PUB_BLOB_SIZE];
    static unsigned char file_keys[MAX_FILE_KEYS][AGE_FILE_KEY_SIZE];
    size_t n_recipients = 0, n_file_keys = 0;
    int bad_recipient = -1, bad_identity = -1;
    stanza_t st;

    /* Phase 1: collect recipients, identities-as-recipients, and file keys. */
    for (;;) {
        if (!read_stanza(&st)) { OQS_KEM_free(kem); return 1; }
        if (strcmp(st.verb, "done") == 0) break;
        if (strcmp(st.verb, "add-recipient") == 0 && st.nargs >= 1) {
            char hrp[64];
            size_t plen = 0;
            if (n_recipients < MAX_RECIPIENTS &&
                bech32_decode(st.args[0], hrp, sizeof(hrp),
                              recipients[n_recipients], PUB_BLOB_SIZE, &plen) &&
                strcmp(hrp, RECIPIENT_HRP) == 0 && plen == PUB_BLOB_SIZE) {
                n_recipients++;
            } else if (bad_recipient < 0) {
                bad_recipient = (int)n_recipients;
            }
        } else if (strcmp(st.verb, "add-identity") == 0 && st.nargs >= 1) {
            /* Encrypting to an identity: use its embedded public half. */
            char hrp[64];
            unsigned char payload[ID_PAYLOAD_SIZE + 16];
            size_t plen = 0;
            if (n_recipients < MAX_RECIPIENTS &&
                bech32_decode(st.args[0], hrp, sizeof(hrp), payload, sizeof(payload), &plen) &&
                strcmp(hrp, IDENTITY_HRP) == 0 && plen == ID_PAYLOAD_SIZE) {
                memcpy(recipients[n_recipients], payload + SEC_BLOB_SIZE, PUB_BLOB_SIZE);
                n_recipients++;
            } else if (bad_identity < 0) {
                bad_identity = 0;
            }
            OPENSSL_cleanse(payload, sizeof(payload));
        } else if (strcmp(st.verb, "wrap-file-key") == 0) {
            if (st.body_len == AGE_FILE_KEY_SIZE && n_file_keys < MAX_FILE_KEYS) {
                memcpy(file_keys[n_file_keys++], st.body, AGE_FILE_KEY_SIZE);
            }
        }
        /* Unknown commands (grease, extension-labels) are ignored. */
    }

    /* Phase 2: wrap every file key to every recipient. */
    if (bad_recipient >= 0) {
        char verb[64];
        snprintf(verb, sizeof(verb), "error recipient %d", bad_recipient);
        send_and_ack(verb, (const unsigned char *)"malformed qsafe recipient", 25);
    } else if (bad_identity >= 0) {
        send_error("identity", "malformed qsafe identity");
    } else {
        for (size_t fk = 0; fk < n_file_keys; fk++) {
            for (size_t r = 0; r < n_recipients; r++) {
                unsigned char rec[REC_BODY_SIZE];
                if (crypto_hybrid_wrap(kem, recipients[r], AGE_HKDF_LABEL,
                                       file_keys[fk], AGE_FILE_KEY_SIZE, rec) != CRYPTO_SUCCESS) {
                    send_error("internal", "hybrid wrap failed");
                    OQS_KEM_free(kem);
                    return 1;
                }
                char verb[64];
                snprintf(verb, sizeof(verb), "recipient-stanza %zu %s", fk, STANZA_TAG);
                if (!send_and_ack(verb, rec, sizeof(rec))) {
                    OQS_KEM_free(kem);
                    return 1;
                }
            }
        }
    }

    write_stanza("done", NULL, 0);
    for (size_t i = 0; i < n_file_keys; i++) OPENSSL_cleanse(file_keys[i], AGE_FILE_KEY_SIZE);
    OQS_KEM_free(kem);
    return 0;
}

/* ---------------------------- identity-v1 -------------------------------- */

typedef struct {
    size_t file_index;
    unsigned char body[REC_BODY_SIZE];
} wrapped_t;

static int run_identity_v1(void) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
    if (!kem) return 1;

    static unsigned char identities[MAX_IDENTITIES][SEC_BLOB_SIZE];
    static wrapped_t wrapped[MAX_STANZAS];
    size_t n_identities = 0, n_wrapped = 0;
    size_t max_file = 0;
    int bad_identity = -1;
    stanza_t st;

    for (;;) {
        if (!read_stanza(&st)) { OQS_KEM_free(kem); return 1; }
        if (strcmp(st.verb, "done") == 0) break;
        if (strcmp(st.verb, "add-identity") == 0 && st.nargs >= 1) {
            char hrp[64];
            unsigned char payload[ID_PAYLOAD_SIZE + 16];
            size_t plen = 0;
            if (n_identities < MAX_IDENTITIES &&
                bech32_decode(st.args[0], hrp, sizeof(hrp), payload, sizeof(payload), &plen) &&
                strcmp(hrp, IDENTITY_HRP) == 0 && plen == ID_PAYLOAD_SIZE) {
                memcpy(identities[n_identities], payload, SEC_BLOB_SIZE);
                n_identities++;
            } else if (bad_identity < 0) {
                bad_identity = (int)n_identities;
            }
            OPENSSL_cleanse(payload, sizeof(payload));
        } else if (strcmp(st.verb, "recipient-stanza") == 0 && st.nargs >= 2) {
            /* args: <file index> <tag> [stanza args...] */
            if (strcmp(st.args[1], STANZA_TAG) == 0 &&
                st.body_len == REC_BODY_SIZE && n_wrapped < MAX_STANZAS) {
                wrapped[n_wrapped].file_index = (size_t)strtoul(st.args[0], NULL, 10);
                memcpy(wrapped[n_wrapped].body, st.body, REC_BODY_SIZE);
                if (wrapped[n_wrapped].file_index + 1 > max_file) {
                    max_file = wrapped[n_wrapped].file_index + 1;
                }
                n_wrapped++;
            }
        }
    }

    if (bad_identity >= 0) {
        char verb[64];
        snprintf(verb, sizeof(verb), "error identity %d", bad_identity);
        send_and_ack(verb, (const unsigned char *)"malformed qsafe identity", 24);
        write_stanza("done", NULL, 0);
        OQS_KEM_free(kem);
        return 0;
    }

    for (size_t f = 0; f < max_file; f++) {
        unsigned char fk[AGE_FILE_KEY_SIZE];
        int got = 0;
        for (size_t w = 0; w < n_wrapped && !got; w++) {
            if (wrapped[w].file_index != f) continue;
            for (size_t i = 0; i < n_identities && !got; i++) {
                if (crypto_hybrid_unwrap(kem, identities[i], AGE_HKDF_LABEL,
                                         wrapped[w].body, AGE_FILE_KEY_SIZE, fk)) {
                    got = 1;
                }
            }
        }
        if (got) {
            char verb[64];
            snprintf(verb, sizeof(verb), "file-key %zu", f);
            send_and_ack(verb, fk, AGE_FILE_KEY_SIZE);
            OPENSSL_cleanse(fk, sizeof(fk));
        }
    }

    write_stanza("done", NULL, 0);
    for (size_t i = 0; i < n_identities; i++) OPENSSL_cleanse(identities[i], SEC_BLOB_SIZE);
    OQS_KEM_free(kem);
    return 0;
}

/* --------------------------------- main ----------------------------------- */

int main(int argc, char *argv[]) {
    qsafe_set_binary_stdio();

    const char *state = NULL;
    const char *out_path = NULL;
    int keygen = 0, pubkey = 0;
    const char *pubkey_in = NULL;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strncmp(a, "--age-plugin=", 13) == 0) {
            state = a + 13;
        } else if (strcmp(a, "--keygen") == 0) {
            keygen = 1;
        } else if (strcmp(a, "-y") == 0) {
            pubkey = 1;
            if (i + 1 < argc) pubkey_in = argv[++i];
        } else if (strcmp(a, "-o") == 0 || strcmp(a, "--output") == 0) {
            if (++i >= argc) { fprintf(stderr, "Error: %s requires a path\n", a); return 1; }
            out_path = argv[i];
        } else if (strcmp(a, "--help") == 0 || strcmp(a, "-h") == 0) {
            printf("age-plugin-qsafe — post-quantum hybrid (X25519 + ML-KEM-1024) age recipients\n\n");
            printf("  age-plugin-qsafe --keygen [-o file]   generate an identity\n");
            printf("  age-plugin-qsafe -y [identity-file]   print the recipient for an identity\n\n");
            printf("Used automatically by age(1) for age1qsafe1... recipients and\n");
            printf("AGE-PLUGIN-QSAFE-1... identities.\n");
            return 0;
        }
    }

    if (keygen) return cmd_keygen(out_path);
    if (pubkey) return cmd_pubkey(pubkey_in);
    if (state && strcmp(state, "recipient-v1") == 0) return run_recipient_v1();
    if (state && strcmp(state, "identity-v1") == 0) return run_identity_v1();

    fprintf(stderr, "age-plugin-qsafe: run me via age(1), or use --keygen (see --help)\n");
    return 1;
}
