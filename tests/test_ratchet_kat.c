/* Key-schedule KAT for the Double Ratchet.
 *
 * The expected bytes below were produced by an INDEPENDENT RFC 5869 HKDF-SHA256
 * implementation (Python stdlib hmac/hashlib), not by qsafe — so this is a genuine
 * cross-implementation check of the exact domain-separated derivations the ratchet
 * relies on. The (ikm, salt, info, L) tuples here MUST mirror kdf_rk()/kdf_ck() in
 * src/ratchet.c; that correspondence is a crypto-review anchor.
 *
 * Fixed inputs: rk = 00..1f, dh_out = 40..5f, ck = 80..9f. */

#include <stdio.h>
#include <string.h>

#include "ratchet.h"        /* RATCHET_LABEL_* */
#include "crypto_utils.h"   /* crypto_hkdf_sha256, size constants */

static int fails = 0;
static void check(const char *name, const unsigned char *got,
                  const unsigned char *want, size_t n) {
    if (memcmp(got, want, n) == 0) { printf("  ok   %s\n", name); }
    else { printf("  FAIL %s\n", name); fails++; }
}

int main(void) {
    unsigned char rk[32], dh_out[32], ck[32];
    for (int i = 0; i < 32; i++) { rk[i]=(unsigned char)i; dh_out[i]=(unsigned char)(0x40+i); ck[i]=(unsigned char)(0x80+i); }

    /* KDF_RK: HKDF(ikm=dh_out, salt=rk, info="Veil-RK-v1", L=64) -> rk' || ck */
    const unsigned char want_rkprime[32] = {
        0xda,0x54,0xeb,0x19,0xfc,0x8f,0x44,0x8e,0x99,0xeb,0xf5,0x49,0x92,0x27,0x66,0x79,
        0x32,0x2b,0xcd,0x7e,0x9f,0x66,0xf3,0x71,0x80,0x03,0x67,0x79,0x02,0xdc,0xc4,0x61 };
    const unsigned char want_rk_ck[32] = {
        0x25,0xd7,0xaa,0x10,0x52,0xdd,0xa5,0x34,0xcc,0xc2,0x3e,0x72,0x0f,0x8c,0x85,0xa4,
        0x41,0x0d,0x7c,0x21,0x52,0xd1,0x09,0xe3,0x57,0x0d,0x1d,0x31,0x22,0xc4,0xe9,0xe1 };
    unsigned char okm[64];
    crypto_hkdf_sha256(dh_out, 32, rk, 32,
                       (const unsigned char *)RATCHET_LABEL_RK, strlen(RATCHET_LABEL_RK),
                       okm, 64);
    check("KDF_RK rk'", okm, want_rkprime, 32);
    check("KDF_RK ck",  okm + 32, want_rk_ck, 32);

    /* KDF_CK message key: HKDF(ikm=ck, salt=empty, info="Veil-CK-msg", L=32) */
    const unsigned char want_mk[32] = {
        0x6a,0x07,0x61,0xad,0xab,0x2a,0xbf,0x9a,0x8c,0x9b,0x3b,0x32,0x7c,0x71,0x5c,0xcc,
        0x52,0x02,0x81,0x8c,0x37,0x12,0x1b,0x94,0xa5,0x33,0x84,0x76,0x89,0x32,0x7a,0xf2 };
    unsigned char mk[32];
    crypto_hkdf_sha256(ck, 32, NULL, 0,
                       (const unsigned char *)RATCHET_LABEL_CK_MSG, strlen(RATCHET_LABEL_CK_MSG),
                       mk, 32);
    check("KDF_CK mk", mk, want_mk, 32);

    /* KDF_CK next chain key: HKDF(ikm=ck, salt=empty, info="Veil-CK-next", L=32) */
    const unsigned char want_next[32] = {
        0x42,0x87,0x80,0x29,0x70,0x20,0xf5,0xd1,0xfd,0xc9,0xd9,0xcc,0x8a,0xac,0x5f,0x83,
        0xeb,0xcf,0x72,0x63,0x24,0x90,0xa4,0x2c,0x9e,0x77,0xc3,0x03,0xfe,0xb8,0xe2,0x23 };
    unsigned char nxt[32];
    crypto_hkdf_sha256(ck, 32, NULL, 0,
                       (const unsigned char *)RATCHET_LABEL_CK_NEXT, strlen(RATCHET_LABEL_CK_NEXT),
                       nxt, 32);
    check("KDF_CK next", nxt, want_next, 32);

    printf("\n%s\n", fails ? "KAT FAILED" : "KAT PASSED");
    return fails ? 1 : 0;
}
