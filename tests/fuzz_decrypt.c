/* libFuzzer harness for Qsafe's untrusted-input parsers.
 *
 * The decrypt path consumes fully attacker-controlled bytes — the magic,
 * recipient count, recipient records, and ciphertext — so it is the primary
 * attack surface. This harness feeds arbitrary inputs to:
 *   - crypto_decrypt_file   (header + record + AEAD parsing)
 *   - crypto_inspect_file   (header sniffing)
 *   - crypto_dearmor        (base64 framing)
 * under AddressSanitizer/UBSan, where any out-of-bounds read, leak, or UB
 * aborts the run with a reproducer.
 *
 * Build (needs clang):
 *   make fuzz
 * Run:
 *   tests/fuzz_decrypt -max_len=8192 corpus/
 *
 * The fuzzer never needs to *succeed* at decryption; it exercises the parsing
 * and key-trial logic on malformed data. A real hybrid secret key is generated
 * once so the recipient-record code path (X25519 DH + ML-KEM decaps + unwrap)
 * is reached rather than rejected up front.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <oqs/oqs.h>
#include "crypto_utils.h"

static OQS_KEM *g_kem = NULL;
static unsigned char *g_secret = NULL;   /* hybrid secret blob */
static unsigned char *g_public = NULL;
static char g_in_path[256];
static char g_out_path[256];
static crypto_config_t g_config;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;

    /* Parser errors print to stderr; silence them so fuzzing stays fast. */
    freopen("/dev/null", "w", stderr);

    g_kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
    if (!g_kem) { fprintf(stdout, "fuzz: KEM init failed\n"); _exit(1); }

    size_t plen = 0, slen = 0;
    if (crypto_generate_identity(g_kem, &g_public, &plen, &g_secret, &slen) != CRYPTO_SUCCESS) {
        fprintf(stdout, "fuzz: identity generation failed\n"); _exit(1);
    }

    snprintf(g_in_path, sizeof(g_in_path), "/tmp/qsafe_fuzz_in_%d.bin", (int)getpid());
    snprintf(g_out_path, sizeof(g_out_path), "/tmp/qsafe_fuzz_out_%d.bin", (int)getpid());

    memset(&g_config, 0, sizeof(g_config));
    g_config.force_overwrite = 1;
    g_config.check_only = 1;   /* authenticate only: never write plaintext, never prompt */
    g_config.secret_key_file = "/tmp/qsafe_fuzz_key";
    g_config.public_key_file = "/tmp/qsafe_fuzz_key.pub";
    g_config.passphrase = "fuzz";
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Stage the fuzz input as the on-disk file the parsers read. */
    FILE *f = fopen(g_in_path, "wb");
    if (!f) return 0;
    if (size > 0) fwrite(data, 1, size, f);
    fclose(f);

    /* 1) Full decrypt parse (check-only: parses header, records, AEAD). */
    crypto_decrypt_file(g_in_path, g_out_path, g_kem, g_secret, &g_config);

    /* 2) Header sniffing without a key. */
    crypto_inspect_file(g_in_path, g_kem, &g_config);

    /* 3) Base64 de-armor framing. */
    crypto_dearmor(g_in_path, g_out_path);

    remove(g_out_path);
    return 0;
}

#ifdef QSAFE_STANDALONE
/* Standalone replay driver so the harness can be built and exercised with a
 * plain ASan/UBSan toolchain (e.g. Apple clang) that lacks libFuzzer. Each
 * argument is a file whose bytes are fed once through the parsers. */
int main(int argc, char **argv) {
    LLVMFuzzerInitialize(&argc, &argv);
    for (int i = 1; i < argc; i++) {
        FILE *f = fopen(argv[i], "rb");
        if (!f) continue;
        fseek(f, 0, SEEK_END);
        long n = ftell(f);
        rewind(f);
        if (n < 0) { fclose(f); continue; }
        unsigned char *buf = malloc((size_t)n + 1);
        if (!buf) { fclose(f); continue; }
        size_t got = fread(buf, 1, (size_t)n, f);
        fclose(f);
        LLVMFuzzerTestOneInput(buf, got);
        free(buf);
    }
    return 0;
}
#endif
