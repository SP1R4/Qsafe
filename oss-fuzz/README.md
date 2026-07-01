# OSS-Fuzz integration

This directory holds the [OSS-Fuzz](https://github.com/google/oss-fuzz)
project files for Qsafe. OSS-Fuzz runs the fuzzers continuously on Google
infrastructure and reports crashes with reproducers — far more CPU-hours than
the daily `fuzz.yml` job.

## What's fuzzed

`tests/fuzz_decrypt.c` — the untrusted-input parsers: the QSAFE005/006/007
container header, recipient records, framing, and the v7 metadata /
trailer / padding declarations.

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
python infra/helper.py run_fuzzer --external /path/to/Qsafe fuzz_decrypt
```
