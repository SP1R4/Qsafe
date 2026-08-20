# OSS-Fuzz integration

This directory holds the [OSS-Fuzz](https://github.com/google/oss-fuzz)
project files for Qsafe. OSS-Fuzz runs the fuzzers continuously on Google
infrastructure and reports crashes with reproducers — far more CPU-hours than
the daily `fuzz.yml` job.

## What's fuzzed

Three harnesses (all built by `build.sh`, all with a seed corpus):

- `tests/fuzz_decrypt.c` (`fuzz_decrypt`) — the QSAFE005/006/007 container
  parser: header, recipient records, framing, and the v7 metadata / trailer /
  padding declarations. Seeded from the checked-in `tests/fixtures/*.qsafe`.
- `tests/fuzz_vault.c` (`fuzz_vault`) — the hidden-volume reader: `vault_read`
  over attacker/corruption-controlled container bytes at a fixed, valid-shaped
  `(offset, capacity)`. Seeded from the frozen `tests/fixtures/vault/container.bin`.
- `tests/fuzz_vault_dir.c` (`fuzz_vault_dir`) — the vault v2 directory parser,
  the attacker-influenced surface once an anchor decrypts (`vault_dir_parse`).

## Enrolling

OSS-Fuzz accepts projects via PR to `google/oss-fuzz`:

1. Fork https://github.com/google/oss-fuzz
2. Create `projects/qsafe/` containing this directory's `project.yaml`,
   `Dockerfile`, and `build.sh`
3. Open the PR; the criteria are at
   https://google.github.io/oss-fuzz/getting-started/accepting-new-projects/
   (security-relevant C code parsing untrusted input qualifies)

`primary_contact` in `project.yaml` receives the (initially private) crash
reports.

## Testing the build locally

```sh
git clone https://github.com/google/oss-fuzz
cd oss-fuzz
python infra/helper.py build_image --external /path/to/Qsafe
python infra/helper.py build_fuzzers --external /path/to/Qsafe
python infra/helper.py check_build --external /path/to/Qsafe          # what reviewers run
python infra/helper.py run_fuzzer --external /path/to/Qsafe fuzz_vault
```

The OSS-Fuzz base image is `linux/amd64`; on an Apple-Silicon host it runs
under QEMU emulation where `cmake` segfaults mid-configure, so the full
Dockerized build can only be verified on a native x86-64 host (or in CI). For
a quick arch-independent smoke test of the harnesses + seed corpora, build the
standalone replay drivers instead (each `main` under `-DQSAFE_STANDALONE`
replays every file argument once):

```sh
clang -fsanitize=address,undefined -DQSAFE_STANDALONE -Iinclude \
  tests/fuzz_vault.c src/vault.c src/crypto_utils.c -loqs -lcrypto -o sa_vault
./sa_vault tests/fixtures/vault/container.bin
```
