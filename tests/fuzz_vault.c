/* libFuzzer harness for qsafe vault's untrusted-input parser.
 *
 * Unlike QSAFE007 (see fuzz_decrypt.c), a vault container is not itself a
 * parsed format with a magic/header — by design (docs/HIDDEN_VOLUMES.md §3):
 * every byte must be indistinguishable from random, whether it holds a slot
 * or not. That means vault_read's *only* untrusted-input surface is the raw
 * container bytes at the (offset, capacity) the caller asks for — there is no
 * header to sniff, no version to dispatch on. This harness writes the fuzz
 * input as a container file and calls vault_read against it with a fixed
 * passphrase and fixed (offset, capacity), so any out-of-bounds read, leak,
 * or UB in the frame-boundary arithmetic or AEAD-open loop aborts the run
 * with a reproducer.
 *
 * The offset/capacity bounds themselves (VAULT_MAX_OFFSET/VAULT_MAX_CAPACITY
 * in vault.h) are deliberately NOT fuzz targets here — an unbounded 64-bit
 * (offset, capacity) pair fuzzed byte-for-byte would spend nearly all of its
 * time on values the up-front bounds check already rejects in O(1). That
 * arithmetic is instead pinned by direct unit tests
 * (test_vault_known_answer_vectors, docs/HIDDEN_VOLUMES.md §7). This harness
 * is for the part fuzzing is actually good at: attacker/corruption-controlled
 * ciphertext bytes at a fixed, valid-shaped location.
 *
 * Build (needs clang + libFuzzer):
 *   make fuzz-vault
 * Run:
 *   tests/fuzz_vault -max_len=300000 corpus/
 *
 * The fuzzer never needs vault_read to *succeed*; a wrong-passphrase/no-data
 * rejection is the overwhelmingly common, correct outcome for random bytes.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "crypto_utils.h"
#include "vault.h"

/* Fixed to match the frozen fixture's decoy slot (tests/fixtures/vault/),
 * which doubles as a seed corpus entry: real ciphertext the mutator can
 * perturb, rather than starting from nothing but random bytes. */
#define FUZZ_OFFSET 0
#define FUZZ_CAPACITY 140000

static char g_container_path[256];
static char g_out_path[256];
static crypto_config_t g_config;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;

    /* Parser errors print to stderr; silence them so fuzzing stays fast. */
    freopen("/dev/null", "w", stderr);

    snprintf(g_container_path, sizeof(g_container_path), "/tmp/qsafe_fuzz_vault_%d.bin", (int)getpid());
    snprintf(g_out_path, sizeof(g_out_path), "/tmp/qsafe_fuzz_vault_out_%d.bin", (int)getpid());

    memset(&g_config, 0, sizeof(g_config));
    g_config.force_overwrite = 1;
    g_config.passphrase = "vault-fixture-decoy-pass"; /* matches the seed fixture */
    g_config.scrypt_n = 1ULL << 14;                    /* matches the seed fixture */
    g_config.scrypt_r = SCRYPT_DEFAULT_R;
    g_config.scrypt_p = SCRYPT_DEFAULT_P;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Stage the fuzz input as the on-disk container vault_read parses. A
     * short/empty input exercises the "container too small" rejection path;
     * libFuzzer will also grow inputs on its own via the corpus. */
    FILE *f = fopen(g_container_path, "wb");
    if (!f) return 0;
    if (size > 0) fwrite(data, 1, size, f);
    fclose(f);

    vault_read(g_container_path, FUZZ_OFFSET, FUZZ_CAPACITY, g_out_path, &g_config);

    remove(g_out_path);
    return 0;
}

#ifdef QSAFE_STANDALONE
/* Standalone replay driver for toolchains without libFuzzer (e.g. Apple
 * clang) — see fuzz_decrypt.c's identical fallback. Each argument is a file
 * whose bytes are fed once through vault_read. */
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
