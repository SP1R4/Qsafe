/* libFuzzer harness for the vault v2 directory parser (vault_dir_parse).
 *
 * Once a volume's anchor decrypts, its plaintext is a directory block whose
 * fields — version, entry_count, and per-entry offset/capacity/scrypt_log_n/
 * name_len — are attacker-influenced: anyone who can craft an anchor plaintext
 * (e.g. a holder of the passphrase building a malicious container, or a bug
 * that lets a wrong block reach the parser) controls these bytes. This harness
 * feeds arbitrary bytes as a directory block and calls vault_dir_parse under
 * AddressSanitizer/UBSan, so any out-of-bounds read or UB in the bound checks
 * or entry loop aborts with a reproducer.
 *
 * vault_dir_parse reads exactly VAULT_ANCHOR_CAPACITY bytes, so the fuzz input
 * is copied into a fixed block (zero-padded or truncated). On a valid parse we
 * additionally round-trip through vault_dir_serialize and re-parse, exercising
 * the writer on fuzzer-discovered valid directories too.
 *
 * Build (needs clang + libFuzzer):
 *   make fuzz-vault-dir
 * Run:
 *   tests/fuzz_vault_dir -max_len=4096 corpus/
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto_utils.h"
#include "vault.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    unsigned char block[VAULT_ANCHOR_CAPACITY];
    memset(block, 0, sizeof(block));
    size_t n = size < sizeof(block) ? size : sizeof(block);
    if (n > 0) memcpy(block, data, n);

    vault_dir_t dir;
    if (vault_dir_parse(block, &dir)) {
        /* A valid directory must survive a serialize + re-parse unchanged in
         * its structural fields (the padding is random, so bytes differ). */
        unsigned char out[VAULT_ANCHOR_CAPACITY];
        vault_dir_t again;
        if (vault_dir_serialize(&dir, out) && vault_dir_parse(out, &again)) {
            if (again.entry_count != dir.entry_count) abort(); /* writer/reader disagree */
        }
    }
    return 0;
}

#ifdef QSAFE_STANDALONE
/* Standalone replay driver for toolchains without libFuzzer — see
 * fuzz_decrypt.c's identical fallback. Each argument is a file whose bytes are
 * fed once through the parser. */
int main(int argc, char **argv) {
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
