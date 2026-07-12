#!/bin/bash
# Qsafe 5.0 - End-to-end integration tests

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BINARY="$PROJECT_DIR/qsafe"
[ -x "$BINARY" ] || BINARY="$PROJECT_DIR/qsafe.exe"   # Windows/MSYS2
TMPDIR=$(mktemp -d "${TMPDIR:-/tmp}/qsafe_test_XXXXXX")
export QSAFE_PASSPHRASE="test-passphrase-e2e"
KEYFILE="$TMPDIR/key.bin"
TESTS_RUN=0
TESTS_PASSED=0
FAILED=0

cleanup() {
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

pass() {
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_PASSED=$((TESTS_PASSED + 1))
    echo "  PASS: $1"
}

fail() {
    TESTS_RUN=$((TESTS_RUN + 1))
    FAILED=1
    echo "  FAIL: $1"
}

# check_ok <description> <command...> : passes if the command succeeds
check_ok() {
    local desc="$1"; shift
    if "$@" > /dev/null 2>&1; then pass "$desc"; else fail "$desc"; fi
}

# check_fail <description> <command...> : passes if the command fails
check_fail() {
    local desc="$1"; shift
    if "$@" > /dev/null 2>&1; then fail "$desc"; else pass "$desc"; fi
}

echo ""
echo "=== Qsafe 5.0 Integration Tests ==="

if [ ! -x "$BINARY" ]; then
    echo "ERROR: $BINARY not found or not executable"
    exit 1
fi

# --- Test 0: keygen ---
echo ""
echo "[test: keygen]"
check_ok "keygen succeeds" \
    "$BINARY" --key-file "$KEYFILE" keygen
check_ok "secret key created" test -f "$KEYFILE"
check_ok "public key created" test -f "$KEYFILE.pub"

# --- Test 1: file encrypt/decrypt round-trip ---
echo ""
echo "[test: file encrypt/decrypt round-trip]"
echo "Hello, Qsafe integration test!" > "$TMPDIR/test_input.txt"

check_ok "encrypt file succeeds" \
    "$BINARY" --force --key-file "$KEYFILE" \
    encrypt "$TMPDIR/test_input.txt" "$TMPDIR/test_input.enc"
check_ok "decrypt file succeeds" \
    "$BINARY" --force --key-file "$KEYFILE" \
    decrypt "$TMPDIR/test_input.enc" "$TMPDIR/test_output.txt"
check_ok "decrypted file matches original" \
    diff -q "$TMPDIR/test_input.txt" "$TMPDIR/test_output.txt"

# --- Test 1b: encrypt needs no passphrase (public-key only) ---
echo ""
echo "[test: encrypt does not require a passphrase]"
check_ok "encrypt succeeds with no passphrase available" \
    env -u QSAFE_PASSPHRASE "$BINARY" --force --key-file "$KEYFILE" \
    encrypt "$TMPDIR/test_input.txt" "$TMPDIR/nopass.enc"
check_ok "that ciphertext still decrypts" \
    "$BINARY" --force --key-file "$KEYFILE" \
    decrypt "$TMPDIR/nopass.enc" "$TMPDIR/nopass.out"
check_ok "no-passphrase-encrypt round-trip matches" \
    diff -q "$TMPDIR/test_input.txt" "$TMPDIR/nopass.out"

# --- Test 1c: default output paths ---
echo ""
echo "[test: default output paths]"
cp "$TMPDIR/test_input.txt" "$TMPDIR/defname.txt"
check_ok "encrypt with default output (.qsafe)" \
    "$BINARY" --force --key-file "$KEYFILE" encrypt "$TMPDIR/defname.txt"
check_ok "default ciphertext exists" test -f "$TMPDIR/defname.txt.qsafe"
rm -f "$TMPDIR/defname.txt"
check_ok "decrypt with default output (strip .qsafe)" \
    "$BINARY" --force --key-file "$KEYFILE" decrypt "$TMPDIR/defname.txt.qsafe"
check_ok "default-restored file matches" \
    diff -q "$TMPDIR/test_input.txt" "$TMPDIR/defname.txt"

# --- Test 2: empty file round-trip ---
echo ""
echo "[test: empty file round-trip]"
: > "$TMPDIR/empty.txt"
check_ok "encrypt empty file succeeds" \
    "$BINARY" --force --key-file "$KEYFILE" encrypt "$TMPDIR/empty.txt" "$TMPDIR/empty.enc"
check_ok "decrypt empty file succeeds" \
    "$BINARY" --force --key-file "$KEYFILE" decrypt "$TMPDIR/empty.enc" "$TMPDIR/empty.out"
check_ok "decrypted empty file matches original" \
    diff -q "$TMPDIR/empty.txt" "$TMPDIR/empty.out"

# --- Test 3: large multi-chunk file round-trip (streaming) ---
echo ""
echo "[test: large file round-trip]"
dd if=/dev/urandom of="$TMPDIR/large.bin" bs=1024 count=2048 > /dev/null 2>&1
check_ok "encrypt 2 MiB file succeeds" \
    "$BINARY" --force --key-file "$KEYFILE" encrypt "$TMPDIR/large.bin" "$TMPDIR/large.enc"
check_ok "decrypt 2 MiB file succeeds" \
    "$BINARY" --force --key-file "$KEYFILE" decrypt "$TMPDIR/large.enc" "$TMPDIR/large.out"
check_ok "decrypted large file matches original" \
    cmp -s "$TMPDIR/large.bin" "$TMPDIR/large.out"

# --- Test 4: stdin/stdout pipe round-trip ---
echo ""
echo "[test: stdin/stdout pipe round-trip]"
echo "streamed through a pipe" > "$TMPDIR/pipe_in.txt"
"$BINARY" --key-file "$KEYFILE" encrypt - - < "$TMPDIR/pipe_in.txt" \
    | "$BINARY" --key-file "$KEYFILE" decrypt - - > "$TMPDIR/pipe_out.txt" 2>/dev/null
check_ok "pipe round-trip matches original" \
    diff -q "$TMPDIR/pipe_in.txt" "$TMPDIR/pipe_out.txt"

# --- Test 5: directory encrypt/decrypt round-trip ---
echo ""
echo "[test: directory encrypt/decrypt round-trip]"
mkdir -p "$TMPDIR/input_dir/sub"
echo "File A content" > "$TMPDIR/input_dir/a.txt"
echo "File B content" > "$TMPDIR/input_dir/b.txt"
echo "Nested file"    > "$TMPDIR/input_dir/sub/c.txt"

check_ok "encrypt directory succeeds (auto-detected)" \
    "$BINARY" --force --key-file "$KEYFILE" encrypt "$TMPDIR/input_dir" "$TMPDIR/encrypted_dir"
check_ok "decrypt directory succeeds (auto-detected)" \
    "$BINARY" --force --key-file "$KEYFILE" decrypt "$TMPDIR/encrypted_dir" "$TMPDIR/decrypted_dir"
check_ok "decrypted dir file a.txt matches" \
    diff -q "$TMPDIR/input_dir/a.txt" "$TMPDIR/decrypted_dir/a.txt"
check_ok "decrypted dir file b.txt matches" \
    diff -q "$TMPDIR/input_dir/b.txt" "$TMPDIR/decrypted_dir/b.txt"
check_ok "decrypted nested file sub/c.txt matches (recursive)" \
    diff -q "$TMPDIR/input_dir/sub/c.txt" "$TMPDIR/decrypted_dir/sub/c.txt"

# --- Test 5b: restore into a directory using the stored filename ---
echo ""
echo "[test: restore original filename into a directory]"
mkdir -p "$TMPDIR/restore_here"
check_ok "decrypt into a directory succeeds" \
    "$BINARY" --force --key-file "$KEYFILE" decrypt "$TMPDIR/test_input.enc" "$TMPDIR/restore_here/"
check_ok "original filename restored inside directory" \
    diff -q "$TMPDIR/test_input.txt" "$TMPDIR/restore_here/test_input.txt"

# --- Test 5c: permission bits preserved (POSIX only) ---
# Windows has no POSIX mode bits, so Qsafe restores only the mtime there.
echo ""
echo "[test: permission metadata preserved]"
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    pass "permission preservation skipped (no POSIX mode bits on Windows)"
    ;;
  *)
echo "perm test" > "$TMPDIR/perm.txt"
chmod 600 "$TMPDIR/perm.txt"
"$BINARY" --force --key-file "$KEYFILE" encrypt "$TMPDIR/perm.txt" "$TMPDIR/perm.enc" >/dev/null 2>&1
rm -f "$TMPDIR/perm.txt"
"$BINARY" --force --key-file "$KEYFILE" decrypt "$TMPDIR/perm.enc" "$TMPDIR/perm.txt" >/dev/null 2>&1
# GNU stat uses -c "%a"; BSD/macOS stat uses -f "%Lp". Try GNU first because
# GNU's -f means --file-system and would succeed with the wrong output.
MODE=$(stat -c "%a" "$TMPDIR/perm.txt" 2>/dev/null || stat -f "%Lp" "$TMPDIR/perm.txt" 2>/dev/null)
if [ "$MODE" = "600" ]; then pass "decrypted file mode is 600"; else fail "decrypted file mode is 600 (got $MODE)"; fi
    ;;
esac

# --- Test 6: wrong passphrase rejection ---
echo ""
echo "[test: wrong passphrase rejection]"
check_fail "wrong passphrase rejects decryption" \
    env QSAFE_PASSPHRASE="wrong-pass" "$BINARY" --force --key-file "$KEYFILE" \
    decrypt "$TMPDIR/test_input.enc" "$TMPDIR/wrong_pass_out.txt"

# --- Test 7: tampered ciphertext rejection ---
echo ""
echo "[test: tampered ciphertext rejection]"
cp "$TMPDIR/test_input.enc" "$TMPDIR/tampered.enc"
# Flip a byte in the AES ciphertext area (past 8-byte magic + 12-byte nonce +
# 1568-byte KEM ciphertext + 272-byte metadata block).
OFF=1861
python3 -c "
with open('$TMPDIR/tampered.enc', 'r+b') as f:
    f.seek($OFF)
    b = f.read(1)
    f.seek($OFF)
    f.write(bytes([b[0] ^ 0xFF]))
" 2>/dev/null || dd if=/dev/urandom of="$TMPDIR/tampered.enc" bs=1 count=1 seek=$OFF conv=notrunc 2>/dev/null

check_fail "tampered ciphertext rejects decryption" \
    "$BINARY" --force --key-file "$KEYFILE" \
    decrypt "$TMPDIR/tampered.enc" "$TMPDIR/tampered_out.txt"
check_ok "no plaintext left behind after rejected decrypt" \
    test ! -f "$TMPDIR/tampered_out.txt"

# --- Test 8: argument / state validation ---
echo ""
echo "[test: argument validation]"
check_fail "unknown command is rejected" \
    "$BINARY" frobnicate "$TMPDIR/test_input.txt"
check_fail "encrypt without a public key is rejected" \
    "$BINARY" --force --key-file "$TMPDIR/nonexistent.key" \
    encrypt "$TMPDIR/test_input.txt" "$TMPDIR/x.enc"
check_fail "nonexistent input is rejected" \
    "$BINARY" --force --key-file "$KEYFILE" encrypt "$TMPDIR/does_not_exist"

# --- Test 9: inspect ---
echo ""
echo "[test: inspect]"
check_ok "inspect public key succeeds" \
    "$BINARY" inspect "$KEYFILE.pub"
"$BINARY" inspect "$KEYFILE.pub" 2>/dev/null | grep -q "hybrid public key" \
    && pass "inspect identifies public key" || fail "inspect identifies public key"
"$BINARY" inspect "$TMPDIR/test_input.enc" 2>/dev/null | grep -q "QSAFE007" \
    && pass "inspect identifies encrypted file" || fail "inspect identifies encrypted file"
FP1=$("$BINARY" inspect "$KEYFILE.pub" 2>/dev/null | grep -i fingerprint)
FP2=$("$BINARY" inspect "$KEYFILE.pub" 2>/dev/null | grep -i fingerprint)
[ -n "$FP1" ] && [ "$FP1" = "$FP2" ] && pass "fingerprint is stable" || fail "fingerprint is stable"

# --- Test 10: verify / --check ---
echo ""
echo "[test: verify and --check]"
check_ok "verify accepts a valid file" \
    "$BINARY" --key-file "$KEYFILE" verify "$TMPDIR/test_input.enc"
check_fail "verify rejects a tampered file" \
    "$BINARY" --key-file "$KEYFILE" verify "$TMPDIR/tampered.enc"
rm -f "$TMPDIR/check_out.txt"
check_ok "decrypt --check authenticates" \
    "$BINARY" --key-file "$KEYFILE" decrypt --check "$TMPDIR/test_input.enc" "$TMPDIR/check_out.txt"
check_ok "decrypt --check writes no plaintext" \
    test ! -f "$TMPDIR/check_out.txt"

# --- Test 11: rekey ---
echo ""
echo "[test: rekey]"
echo "$QSAFE_PASSPHRASE" > "$TMPDIR/oldpp.txt"
printf 'new-rekey-pass\nnew-rekey-pass\n' | \
    "$BINARY" --key-file "$KEYFILE" rekey --passphrase-file "$TMPDIR/oldpp.txt" > /dev/null 2>&1 \
    && pass "rekey succeeds" || fail "rekey succeeds"
check_fail "old passphrase no longer works" \
    env QSAFE_PASSPHRASE="$QSAFE_PASSPHRASE" "$BINARY" --key-file "$KEYFILE" verify "$TMPDIR/test_input.enc"
check_ok "new passphrase decrypts existing ciphertext" \
    env QSAFE_PASSPHRASE="new-rekey-pass" "$BINARY" --key-file "$KEYFILE" verify "$TMPDIR/test_input.enc"
# Restore the original passphrase so the suite ends in a known state. Use a real
# file (not process substitution) for --passphrase-file, since a native Windows
# binary cannot read /dev/fd/* from MSYS process substitution.
echo "new-rekey-pass" > "$TMPDIR/curpp.txt"
printf '%s\n%s\n' "$QSAFE_PASSPHRASE" "$QSAFE_PASSPHRASE" | \
    "$BINARY" --key-file "$KEYFILE" rekey --passphrase-file "$TMPDIR/curpp.txt" > /dev/null 2>&1
if "$BINARY" --key-file "$KEYFILE" verify "$TMPDIR/test_input.enc" >/dev/null 2>&1; then
    pass "passphrase restored after rekey"
else
    fail "passphrase restored after rekey"
fi

# --- Test 12: configurable scrypt cost ---
echo ""
echo "[test: scrypt cost]"
SCKEY="$TMPDIR/sc.bin"
check_ok "keygen with --scrypt-cost 16 succeeds" \
    env QSAFE_PASSPHRASE="sc-pass" "$BINARY" keygen --key-file "$SCKEY" --scrypt-cost 16
# Key file carries the versioned header magic.
head -c 8 "$SCKEY" 2>/dev/null | grep -q "QSAFEK01" \
    && pass "key file has versioned header" || fail "key file has versioned header"
env QSAFE_PASSPHRASE="sc-pass" "$BINARY" encrypt --key-file "$SCKEY" "$TMPDIR/test_input.txt" "$TMPDIR/sc.enc" > /dev/null 2>&1
check_ok "high-cost key decrypts its ciphertext" \
    env QSAFE_PASSPHRASE="sc-pass" "$BINARY" --key-file "$SCKEY" verify "$TMPDIR/sc.enc"
check_fail "out-of-range --scrypt-cost is rejected" \
    env QSAFE_PASSPHRASE="sc-pass" "$BINARY" keygen --key-file "$TMPDIR/bad.bin" --scrypt-cost 99
# Corrupting the authenticated cost header makes the key unusable.
cp "$SCKEY" "$TMPDIR/sc_bad.bin"
printf '\xff' | dd of="$TMPDIR/sc_bad.bin" bs=1 seek=8 count=1 conv=notrunc 2>/dev/null
check_fail "tampered key header is rejected" \
    env QSAFE_PASSPHRASE="sc-pass" "$BINARY" --key-file "$TMPDIR/sc_bad.bin" verify "$TMPDIR/sc.enc"

# --- Test 13: multi-recipient encryption ---
echo ""
echo "[test: multi-recipient]"
A="$TMPDIR/alice.bin"; B="$TMPDIR/bob.bin"
env QSAFE_PASSPHRASE="alice-pass" "$BINARY" keygen --key-file "$A" > /dev/null 2>&1
env QSAFE_PASSPHRASE="bob-pass"   "$BINARY" keygen --key-file "$B" > /dev/null 2>&1
echo "shared secret message" > "$TMPDIR/shared.txt"
check_ok "encrypt to two recipients" \
    "$BINARY" encrypt -r "$A.pub" -r "$B.pub" "$TMPDIR/shared.txt" "$TMPDIR/shared.qsafe"
"$BINARY" inspect "$TMPDIR/shared.qsafe" 2>/dev/null | grep -q "Recipients: 2" \
    && pass "inspect reports 2 recipients" || fail "inspect reports 2 recipients"
check_ok "alice can decrypt" \
    env QSAFE_PASSPHRASE="alice-pass" "$BINARY" --key-file "$A" verify "$TMPDIR/shared.qsafe"
check_ok "bob can decrypt" \
    env QSAFE_PASSPHRASE="bob-pass" "$BINARY" --key-file "$B" verify "$TMPDIR/shared.qsafe"
# A non-recipient key (the suite's main key) must NOT decrypt.
check_fail "non-recipient cannot decrypt" \
    "$BINARY" --key-file "$KEYFILE" verify "$TMPDIR/shared.qsafe"

# --- Test 14: detached signatures (ML-DSA-87) ---
echo ""
echo "[test: signatures]"
SK="$TMPDIR/sign.bin"
check_ok "sign-keygen succeeds" \
    env QSAFE_PASSPHRASE="sign-pass" "$BINARY" sign-keygen --key-file "$SK"
echo "document to be signed" > "$TMPDIR/doc.txt"
check_ok "sign produces a signature" \
    env QSAFE_PASSPHRASE="sign-pass" "$BINARY" sign --key-file "$SK" "$TMPDIR/doc.txt" "$TMPDIR/doc.sig"
check_ok "verify-sig accepts a valid signature" \
    "$BINARY" --key-file "$SK" verify-sig "$TMPDIR/doc.txt" "$TMPDIR/doc.sig"
# Modify the document; the signature must no longer verify.
echo "tampered" >> "$TMPDIR/doc.txt"
check_fail "verify-sig rejects an altered document" \
    "$BINARY" --key-file "$SK" verify-sig "$TMPDIR/doc.txt" "$TMPDIR/doc.sig"

# --- Test 15: armored (base64) output ---
echo ""
echo "[test: armor]"
echo "armor round-trip payload" > "$TMPDIR/armor.txt"
check_ok "encrypt --armor produces text" \
    "$BINARY" encrypt --armor --key-file "$KEYFILE" "$TMPDIR/armor.txt" "$TMPDIR/armor.asc"
head -1 "$TMPDIR/armor.asc" 2>/dev/null | grep -q "BEGIN QSAFE MESSAGE" \
    && pass "armor has PEM header" || fail "armor has PEM header"
"$BINARY" decrypt --armor --key-file "$KEYFILE" "$TMPDIR/armor.asc" "$TMPDIR/armor.out" > /dev/null 2>&1
if cmp -s "$TMPDIR/armor.txt" "$TMPDIR/armor.out"; then pass "armor round-trip matches"; else fail "armor round-trip matches"; fi
# Armored pipe round-trip.
"$BINARY" encrypt --armor --key-file "$KEYFILE" - < "$TMPDIR/armor.txt" 2>/dev/null \
    | "$BINARY" decrypt --armor --key-file "$KEYFILE" - 2>/dev/null > "$TMPDIR/armor.pipe.out"
if cmp -s "$TMPDIR/armor.txt" "$TMPDIR/armor.pipe.out"; then pass "armored pipe round-trip"; else fail "armored pipe round-trip"; fi

# --- Test 16: no unverified plaintext released to a pipe ---
echo ""
echo "[test: no unverified plaintext to pipe]"
# Decrypt a tampered ciphertext to stdout; auth must fail AND nothing may be
# emitted (verify-before-release for the pipe path).
"$BINARY" --key-file "$KEYFILE" decrypt - < "$TMPDIR/tampered.enc" > "$TMPDIR/pipe_tamper.out" 2>/dev/null
rc=$?
SZ=$(wc -c < "$TMPDIR/pipe_tamper.out" | tr -d ' ')
[ "$rc" -ne 0 ] && pass "tampered pipe decrypt fails (nonzero exit)" || fail "tampered pipe decrypt fails (nonzero exit)"
[ "$SZ" -eq 0 ] && pass "no plaintext emitted to pipe on auth failure" || fail "no plaintext emitted to pipe on auth failure (got $SZ bytes)"
# Sanity: a valid ciphertext still round-trips correctly through the pipe.
"$BINARY" --key-file "$KEYFILE" decrypt - < "$TMPDIR/test_input.enc" > "$TMPDIR/pipe_ok.out" 2>/dev/null
check_ok "valid pipe decrypt still matches original" \
    diff -q "$TMPDIR/test_input.txt" "$TMPDIR/pipe_ok.out"

# --- Test 17: framed format (QSAFE007) ---
echo ""
echo "[test: framed format]"
# Multi-frame round-trip (well over one 64 KiB frame).
dd if=/dev/urandom of="$TMPDIR/multi.in" bs=1024 count=300 >/dev/null 2>&1
"$BINARY" --force --key-file "$KEYFILE" encrypt "$TMPDIR/multi.in" "$TMPDIR/multi.q" >/dev/null 2>&1
"$BINARY" --force --key-file "$KEYFILE" decrypt "$TMPDIR/multi.q" "$TMPDIR/multi.out" >/dev/null 2>&1
check_ok "multi-frame round-trip matches" cmp -s "$TMPDIR/multi.in" "$TMPDIR/multi.out"
"$BINARY" inspect "$TMPDIR/multi.q" 2>/dev/null | grep -q "framed" \
    && pass "inspect reports framed AEAD" || fail "inspect reports framed AEAD"
# Edge: META(288) + file == 65536 forces a full frame plus an empty final frame.
dd if=/dev/urandom of="$TMPDIR/exact.in" bs=65248 count=1 >/dev/null 2>&1
"$BINARY" --force --key-file "$KEYFILE" encrypt "$TMPDIR/exact.in" "$TMPDIR/exact.q" >/dev/null 2>&1
"$BINARY" --force --key-file "$KEYFILE" decrypt "$TMPDIR/exact.q" "$TMPDIR/exact.out" >/dev/null 2>&1
check_ok "frame-multiple round-trip matches" cmp -s "$TMPDIR/exact.in" "$TMPDIR/exact.out"
# Truncation (dropping the tail of the final frame) must be detected.
SZ=$(wc -c < "$TMPDIR/multi.q"); head -c $((SZ-40)) "$TMPDIR/multi.q" > "$TMPDIR/multi.trunc.q"
check_fail "truncated framed file is rejected" \
    "$BINARY" --key-file "$KEYFILE" verify "$TMPDIR/multi.trunc.q"
# Tampering a frame byte must be detected.
cp "$TMPDIR/multi.q" "$TMPDIR/multi.bad.q"
# Flip a byte to its complement so the corruption is guaranteed to differ from
# the original (writing a fixed byte is a no-op ~1/256 of the time -> flaky).
orig=$(dd if="$TMPDIR/multi.bad.q" bs=1 skip=2000 count=1 2>/dev/null | od -An -tu1 | tr -d ' \n')
new=$(( orig ^ 255 ))
printf "$(printf '\\%03o' "$new")" | dd of="$TMPDIR/multi.bad.q" bs=1 seek=2000 count=1 conv=notrunc 2>/dev/null
check_fail "tampered framed file is rejected" \
    "$BINARY" --key-file "$KEYFILE" verify "$TMPDIR/multi.bad.q"

# --- Test 18: v5 backward-compatible decrypt (dual-read) ---
echo ""
echo "[test: v5 interop]"
FIX="$PROJECT_DIR/tests/fixtures"
env QSAFE_PASSPHRASE="v5-fixture-pass" "$BINARY" --key-file "$FIX/v5_key" \
    decrypt "$FIX/v5_msg.qsafe" "$TMPDIR/v5.out" >/dev/null 2>&1
check_ok "decrypts a QSAFE005 file produced by v5.0.0" \
    cmp -s "$FIX/v5_msg.expected" "$TMPDIR/v5.out"
env QSAFE_PASSPHRASE="v6-fixture-pass" "$BINARY" --key-file "$FIX/v6_key" \
    decrypt "$FIX/v6_msg.qsafe" "$TMPDIR/v6.out" >/dev/null 2>&1
check_ok "decrypts a QSAFE006 file produced by v7.0.0" \
    cmp -s "$FIX/v6_msg.expected" "$TMPDIR/v6.out"
# Frozen QSAFE007 vectors: plain, signed, and padded fixtures must keep
# decrypting bit-for-bit as the reader evolves.
for VAR in "" "_signed" "_padded"; do
    env QSAFE_PASSPHRASE="v7-fixture-pass" "$BINARY" --force --key-file "$FIX/v7_key" \
        decrypt "$FIX/v7_msg$VAR.qsafe" "$TMPDIR/v7$VAR.out" >/dev/null 2>&1
    check_ok "decrypts the frozen QSAFE007${VAR:-_plain} fixture" \
        cmp -s "$FIX/v7_msg.expected" "$TMPDIR/v7$VAR.out"
done
env QSAFE_PASSPHRASE="v7-fixture-pass" "$BINARY" --key-file "$FIX/v7_key" \
    --signer "$FIX/v7_sign_key.pub" verify "$FIX/v7_msg_signed.qsafe" >/dev/null 2>&1 \
    && pass "frozen signed fixture verifies against its signer" \
    || fail "frozen signed fixture verifies against its signer"

# --- Test 18b: embedded sender signatures (QSAFE007 signed mode) ---
echo ""
echo "[test: signed-sender mode]"
SIGKEY="$TMPDIR/signer_key.bin"
"$BINARY" --force --key-file "$SIGKEY" sign-keygen >/dev/null 2>&1
SIGKEY2="$TMPDIR/signer2_key.bin"
"$BINARY" --force --key-file "$SIGKEY2" sign-keygen >/dev/null 2>&1

check_ok "encrypt --sign-with succeeds" \
    "$BINARY" --force --key-file "$KEYFILE" encrypt --sign-with "$SIGKEY" \
    -r "$KEYFILE.pub" "$TMPDIR/test_input.txt" "$TMPDIR/signed.q"
"$BINARY" --force --key-file "$KEYFILE" decrypt "$TMPDIR/signed.q" "$TMPDIR/signed.out" 2>"$TMPDIR/signed.err"
check_ok "signed round-trip matches" cmp -s "$TMPDIR/test_input.txt" "$TMPDIR/signed.out"
grep -q "Signed by" "$TMPDIR/signed.err" \
    && pass "decrypt reports the signer fingerprint" || fail "decrypt reports the signer fingerprint"
check_ok "verify authenticates a signed file" \
    "$BINARY" --key-file "$KEYFILE" verify "$TMPDIR/signed.q"
check_ok "--signer accepts the right signer" \
    "$BINARY" --force --key-file "$KEYFILE" decrypt --signer "$SIGKEY.pub" \
    "$TMPDIR/signed.q" "$TMPDIR/signed2.out"
check_fail "--signer rejects the wrong signer" \
    "$BINARY" --force --key-file "$KEYFILE" decrypt --signer "$SIGKEY2.pub" \
    "$TMPDIR/signed.q" "$TMPDIR/signed3.out"
[ ! -f "$TMPDIR/signed3.out" ] \
    && pass "no plaintext left after signer rejection" || fail "no plaintext left after signer rejection"
# A tampered payload byte must fail frame auth before any signature check.
cp "$TMPDIR/signed.q" "$TMPDIR/signed.bad.q"
orig=$(dd if="$TMPDIR/signed.bad.q" bs=1 skip=1800 count=1 2>/dev/null | od -An -tu1 | tr -d ' \n')
new=$(( orig ^ 255 ))
printf "$(printf '\\%03o' "$new")" | dd of="$TMPDIR/signed.bad.q" bs=1 seek=1800 count=1 conv=notrunc 2>/dev/null
check_fail "tampered signed file is rejected" \
    "$BINARY" --key-file "$KEYFILE" verify "$TMPDIR/signed.bad.q"
# Signed stdin stream (unknown length -> trailer holdback path).
cat "$TMPDIR/test_input.txt" | "$BINARY" --force --key-file "$KEYFILE" encrypt \
    --sign-with "$SIGKEY" - "$TMPDIR/signed_pipe.q" >/dev/null 2>&1
"$BINARY" --key-file "$KEYFILE" decrypt "$TMPDIR/signed_pipe.q" - 2>/dev/null > "$TMPDIR/signed_pipe.out"
check_ok "signed stdin stream round-trips" cmp -s "$TMPDIR/test_input.txt" "$TMPDIR/signed_pipe.out"

# --- Test 18c: size-hiding padding (QSAFE007 --pad) ---
echo ""
echo "[test: padding]"
dd if=/dev/urandom of="$TMPDIR/pad.in" bs=1000 count=100 >/dev/null 2>&1
check_ok "encrypt --pad succeeds" \
    "$BINARY" --force --key-file "$KEYFILE" encrypt --pad "$TMPDIR/pad.in" "$TMPDIR/pad.q"
check_ok "padded round-trip matches" sh -c \
    "\"$BINARY\" --force --key-file \"$KEYFILE\" decrypt \"$TMPDIR/pad.q\" \"$TMPDIR/pad.out\" >/dev/null 2>&1 && cmp -s \"$TMPDIR/pad.in\" \"$TMPDIR/pad.out\""
# Padmé rounds 100000 up to 100352, so the ciphertext must grow accordingly.
PSZ=$(wc -c < "$TMPDIR/pad.q")
USZ=$(wc -c < "$TMPDIR/multi.q"); : "$USZ"
[ "$PSZ" -gt 101000 ] && pass "padding increases ciphertext size" || fail "padding increases ciphertext size"
check_fail "--pad on stdin is rejected" \
    sh -c "echo x | \"$BINARY\" --key-file \"$KEYFILE\" encrypt --pad - \"$TMPDIR/padpipe.q\""
# Padded + signed together.
check_ok "padded + signed round-trip" sh -c \
    "\"$BINARY\" --force --key-file \"$KEYFILE\" encrypt --pad --sign-with \"$SIGKEY\" -r \"$KEYFILE.pub\" \"$TMPDIR/pad.in\" \"$TMPDIR/padsig.q\" >/dev/null 2>&1 && \
     \"$BINARY\" --force --key-file \"$KEYFILE\" decrypt \"$TMPDIR/padsig.q\" \"$TMPDIR/padsig.out\" >/dev/null 2>&1 && \
     cmp -s \"$TMPDIR/pad.in\" \"$TMPDIR/padsig.out\""

# --- Test 18c2: adversarial QSAFE007 files (malicious encryptor) ---
# Frozen fixtures with VALID recipient wraps and VALID frame AEAD but hostile
# payload declarations (signed-but-no-trailer, pad-flag mismatches, length
# over/under-runs, bad signature lengths, huge declared lengths). Each MUST be
# rejected and leave no plaintext; case 11 is a well-formed control.
echo ""
echo "[test: adversarial QSAFE007]"
EVIL="$PROJECT_DIR/tests/fixtures/evil"
if [ -f "$EVIL/case_1.qsafe" ]; then
    for c in 1 2 3 4 5 6 7 8 9 10; do
        rm -f "$TMPDIR/evil_$c.out"
        check_fail "malicious case $c is rejected" \
            env QSAFE_PASSPHRASE="evil-fixture-pass" "$BINARY" --force \
            --key-file "$EVIL/key" decrypt "$EVIL/case_$c.qsafe" "$TMPDIR/evil_$c.out"
        [ ! -f "$TMPDIR/evil_$c.out" ] \
            && pass "malicious case $c leaves no plaintext" \
            || fail "malicious case $c leaves no plaintext"
    done
    # Control: the well-formed file MUST decrypt.
    rm -f "$TMPDIR/evil_ctrl.out"
    env QSAFE_PASSPHRASE="evil-fixture-pass" "$BINARY" --force \
        --key-file "$EVIL/key" decrypt "$EVIL/case_11.qsafe" "$TMPDIR/evil_ctrl.out" >/dev/null 2>&1
    if grep -q "adversarial payload" "$TMPDIR/evil_ctrl.out" 2>/dev/null; then
        pass "adversarial control file decrypts"
    else
        # the crafted metadata sets mode 000; read via a copy the test owns
        chmod u+r "$TMPDIR/evil_ctrl.out" 2>/dev/null
        grep -q "adversarial payload" "$TMPDIR/evil_ctrl.out" 2>/dev/null \
            && pass "adversarial control file decrypts" \
            || fail "adversarial control file decrypts"
    fi
else
    pass "adversarial QSAFE007 fixtures skipped (not present)"
fi

# --- Test 18d: Shamir key splitting (split-key / join-key) ---
echo ""
echo "[test: split-key / join-key]"
check_ok "split-key 2-of-3 succeeds" \
    "$BINARY" --key-file "$KEYFILE" split-key --threshold 2 --shares 3 "$TMPDIR/kshare"
[ -f "$TMPDIR/kshare.share1" ] && [ -f "$TMPDIR/kshare.share3" ] \
    && pass "share files are created" || fail "share files are created"
check_ok "join-key from shares 1+3 succeeds" \
    env QSAFE_PASSPHRASE="rejoined-pass" "$BINARY" --force --key-file "$TMPDIR/rejoined_key.bin" \
    join-key "$TMPDIR/kshare.share1" "$TMPDIR/kshare.share3"
env QSAFE_PASSPHRASE="rejoined-pass" "$BINARY" --force --key-file "$TMPDIR/rejoined_key.bin" \
    decrypt "$TMPDIR/test_input.enc" "$TMPDIR/rejoined.out" >/dev/null 2>&1
check_ok "reconstructed key decrypts existing files" \
    cmp -s "$TMPDIR/test_input.txt" "$TMPDIR/rejoined.out"
check_fail "join-key with one share is rejected" \
    env QSAFE_PASSPHRASE="x" "$BINARY" --force --key-file "$TMPDIR/r2.bin" \
    join-key "$TMPDIR/kshare.share1"
# Shares from different splits must not combine.
"$BINARY" --key-file "$KEYFILE" split-key --threshold 2 --shares 2 "$TMPDIR/othershare" >/dev/null 2>&1
check_fail "shares from different sets are rejected" \
    env QSAFE_PASSPHRASE="x" "$BINARY" --force --key-file "$TMPDIR/r3.bin" \
    join-key "$TMPDIR/kshare.share1" "$TMPDIR/othershare.share2"
# A corrupted share must fail the reconstruction digest.
cp "$TMPDIR/kshare.share2" "$TMPDIR/kshare.bad"
orig=$(dd if="$TMPDIR/kshare.bad" bs=1 skip=100 count=1 2>/dev/null | od -An -tu1 | tr -d ' \n')
new=$(( orig ^ 255 ))
printf "$(printf '\\%03o' "$new")" | dd of="$TMPDIR/kshare.bad" bs=1 seek=100 count=1 conv=notrunc 2>/dev/null
check_fail "corrupt share is rejected" \
    env QSAFE_PASSPHRASE="x" "$BINARY" --force --key-file "$TMPDIR/r4.bin" \
    join-key "$TMPDIR/kshare.share1" "$TMPDIR/kshare.bad"

# --- Test 19: keyring / named identities ---
echo ""
echo "[test: keyring]"
# Env vars are not MSYS path-translated, so on Windows a native binary cannot use
# an MSYS "/tmp/..." path. Use a CWD-relative keyring dir (works everywhere).
QSAFE_HOME_DIR="qsafe_keyring_test_$$"
rm -rf "$QSAFE_HOME_DIR"
export QSAFE_HOME="$QSAFE_HOME_DIR"
check_ok "keygen --identity alice" "$BINARY" keygen --identity alice
check_ok "keygen --identity bob"   "$BINARY" keygen --identity bob
"$BINARY" keys list 2>/dev/null | grep -q "alice" \
    && pass "keys list shows identities" || fail "keys list shows identities"
echo "keyring secret" > "$TMPDIR/kr_msg.txt"
check_ok "encrypt to keyring names (-r alice -r bob)" \
    "$BINARY" encrypt -r alice -r bob "$TMPDIR/kr_msg.txt" "$TMPDIR/kr_msg.q"
"$BINARY" inspect "$TMPDIR/kr_msg.q" 2>/dev/null | grep -q "Recipients: 2" \
    && pass "two named recipients encoded" || fail "two named recipients encoded"
check_ok "decrypt --identity alice" \
    "$BINARY" decrypt --identity alice "$TMPDIR/kr_msg.q" "$TMPDIR/kr_alice.out"
check_ok "keyring round-trip matches (alice)" \
    diff -q "$TMPDIR/kr_msg.txt" "$TMPDIR/kr_alice.out"
check_ok "decrypt --identity bob" \
    "$BINARY" decrypt --identity bob "$TMPDIR/kr_msg.q" "$TMPDIR/kr_bob.out"
check_ok "keyring round-trip matches (bob)" \
    diff -q "$TMPDIR/kr_msg.txt" "$TMPDIR/kr_bob.out"
# Import an external public key as a named recipient, use it, then remove it.
check_ok "keys import recipient" "$BINARY" keys import friend "$KEYFILE.pub"
check_ok "encrypt to imported recipient" \
    "$BINARY" encrypt -r friend "$TMPDIR/kr_msg.txt" "$TMPDIR/kr_friend.q"
check_ok "imported recipient's key decrypts" \
    "$BINARY" --key-file "$KEYFILE" verify "$TMPDIR/kr_friend.q"
check_ok "keys remove recipient" "$BINARY" keys remove friend
check_fail "encrypt to unknown name is rejected" \
    "$BINARY" encrypt -r nobody "$TMPDIR/kr_msg.txt" "$TMPDIR/kr_x.q"
unset QSAFE_HOME
rm -rf "$QSAFE_HOME_DIR"

# --- Test 20: age interop (X25519) ---
echo ""
echo "[test: age interop]"
"$BINARY" age-keygen "$TMPDIR/agekey.txt" >/dev/null 2>&1
APUB=$(grep -o 'age1[a-z0-9]*' "$TMPDIR/agekey.txt" | head -1)
echo "age interop round-trip plaintext" > "$TMPDIR/age_pt.txt"
check_ok "age-encrypt to a recipient" \
    "$BINARY" age-encrypt -r "$APUB" "$TMPDIR/age_pt.txt" "$TMPDIR/age_ct.age"
check_ok "age-decrypt round-trips" \
    "$BINARY" age-decrypt -i "$TMPDIR/agekey.txt" "$TMPDIR/age_ct.age" "$TMPDIR/age_out.txt"
check_ok "age round-trip matches" \
    diff -q "$TMPDIR/age_pt.txt" "$TMPDIR/age_out.txt"
check_fail "age-decrypt with wrong identity is rejected" \
    sh -c '"$1" age-keygen "$2" >/dev/null 2>&1; "$1" age-decrypt -i "$2" "$3" "$4"' \
    _ "$BINARY" "$TMPDIR/agekey2.txt" "$TMPDIR/age_ct.age" "$TMPDIR/age_bad.txt"
# Cross-validate against the real `age` binary when it is installed.
if command -v age >/dev/null 2>&1; then
    age -d -i "$TMPDIR/agekey.txt" -o "$TMPDIR/age_real.txt" "$TMPDIR/age_ct.age" >/dev/null 2>&1
    check_ok "real age decrypts qsafe output" \
        diff -q "$TMPDIR/age_pt.txt" "$TMPDIR/age_real.txt"
    age -r "$APUB" -o "$TMPDIR/age_from_real.age" "$TMPDIR/age_pt.txt" >/dev/null 2>&1
    "$BINARY" age-decrypt -i "$TMPDIR/agekey.txt" "$TMPDIR/age_from_real.age" "$TMPDIR/age_from_real.txt" >/dev/null 2>&1
    check_ok "qsafe decrypts real age output" \
        diff -q "$TMPDIR/age_pt.txt" "$TMPDIR/age_from_real.txt"
else
    pass "real-age cross-check skipped (age not installed)"
fi

# --- Test 20b: age-plugin-qsafe (post-quantum age recipients) ---
echo ""
echo "[test: age plugin]"
PLUGIN_BIN="$PROJECT_DIR/age-plugin-qsafe"
if [ -x "$PLUGIN_BIN" ]; then
    "$PLUGIN_BIN" --keygen -o "$TMPDIR/plug_id.txt" 2>"$TMPDIR/plug_pub.txt"
    PREC=$(grep -o 'age1qsafe1[a-z0-9]*' "$TMPDIR/plug_pub.txt" | head -1)
    [ -n "$PREC" ] && pass "plugin keygen emits a recipient" || fail "plugin keygen emits a recipient"
    DERIVED=$("$PLUGIN_BIN" -y "$TMPDIR/plug_id.txt")
    [ "$DERIVED" = "$PREC" ] && pass "plugin -y derives the recipient" || fail "plugin -y derives the recipient"
    if command -v age >/dev/null 2>&1; then
        echo "post-quantum age plugin round-trip" > "$TMPDIR/plug_pt.txt"
        PATH="$PROJECT_DIR:$PATH" age -r "$PREC" -o "$TMPDIR/plug_ct.age" "$TMPDIR/plug_pt.txt" >/dev/null 2>&1
        PATH="$PROJECT_DIR:$PATH" age -d -i "$TMPDIR/plug_id.txt" -o "$TMPDIR/plug_out.txt" "$TMPDIR/plug_ct.age" >/dev/null 2>&1
        check_ok "age round-trips through the qsafe plugin" \
            diff -q "$TMPDIR/plug_pt.txt" "$TMPDIR/plug_out.txt"
        "$PLUGIN_BIN" --keygen -o "$TMPDIR/plug_id2.txt" 2>/dev/null
        check_fail "wrong plugin identity is rejected" \
            env PATH="$PROJECT_DIR:$PATH" age -d -i "$TMPDIR/plug_id2.txt" -o "$TMPDIR/plug_bad.txt" "$TMPDIR/plug_ct.age"
    else
        pass "age plugin protocol test skipped (age not installed)"
    fi
else
    pass "age plugin tests skipped (plugin not built)"
fi

# --- Test 21: macOS Keychain-backed passphrase ---
echo ""
echo "[test: keychain]"
case "$(uname -s)" in
  Darwin)
    KCKEY="$TMPDIR/kc_key.bin"
    security delete-generic-password -s qsafe -a "$KCKEY" >/dev/null 2>&1
    # --keychain takes precedence over $QSAFE_PASSPHRASE: keygen generates and
    # stores a random passphrase; decrypt retrieves it.
    "$BINARY" keygen --keychain --key-file "$KCKEY" >/dev/null 2>&1
    check_ok "keygen --keychain stores a passphrase" \
        security find-generic-password -s qsafe -a "$KCKEY"
    echo "keychain-protected secret" > "$TMPDIR/kc_pt.txt"
    "$BINARY" encrypt --key-file "$KCKEY" "$TMPDIR/kc_pt.txt" "$TMPDIR/kc.q" >/dev/null 2>&1
    check_ok "decrypt --keychain round-trips" \
        "$BINARY" decrypt --keychain --key-file "$KCKEY" "$TMPDIR/kc.q" "$TMPDIR/kc.out"
    check_ok "keychain round-trip matches" \
        diff -q "$TMPDIR/kc_pt.txt" "$TMPDIR/kc.out"
    security delete-generic-password -s qsafe -a "$KCKEY" >/dev/null 2>&1
    check_fail "decrypt --keychain fails after the item is removed" \
        "$BINARY" decrypt --keychain --key-file "$KCKEY" "$TMPDIR/kc.q" "$TMPDIR/kc.bad"
    ;;
  MINGW*|MSYS*|CYGWIN*)
    # Windows DPAPI backend: functional round-trip (no CLI inspector like
    # `security`, so assert behavior end to end).
    KCKEY="$TMPDIR/kc_key.bin"
    "$BINARY" keygen --keychain --key-file "$KCKEY" >/dev/null 2>&1
    echo "keychain-protected secret" > "$TMPDIR/kc_pt.txt"
    "$BINARY" encrypt --key-file "$KCKEY" "$TMPDIR/kc_pt.txt" "$TMPDIR/kc.q" >/dev/null 2>&1
    check_ok "decrypt --keychain round-trips (DPAPI)" \
        "$BINARY" decrypt --keychain --key-file "$KCKEY" "$TMPDIR/kc.q" "$TMPDIR/kc.out"
    check_ok "keychain round-trip matches" \
        diff -q "$TMPDIR/kc_pt.txt" "$TMPDIR/kc.out"
    # A different account (key path) must not resolve to the same item.
    check_fail "keychain item is bound to the key path" \
        "$BINARY" decrypt --keychain --key-file "$TMPDIR/other_key.bin" "$TMPDIR/kc.q" "$TMPDIR/kc.bad"
    ;;
  *)
    pass "keychain test skipped (no backend on this platform)"
    ;;
esac

# --- Test 22: vault (hidden volumes) ---
echo ""
echo "[test: vault init/write/read round-trip]"
VC="$TMPDIR/vault_container.bin"
check_ok "vault init succeeds" \
    "$BINARY" vault init "$VC" --size 300000 --force
check_ok "container has the declared size" \
    sh -c "[ \"\$(wc -c < \"$VC\")\" -eq 300000 ]"
check_fail "vault init without --force refuses to overwrite" \
    "$BINARY" vault init "$VC" --size 1000

echo "outer decoy payload for the integration test" > "$TMPDIR/vault_outer.in"
echo "inner secret payload for the integration test" > "$TMPDIR/vault_inner.in"
printf 'outer-pass-1' > "$TMPDIR/vault_outer.pass"
printf 'inner-pass-2' > "$TMPDIR/vault_inner.pass"

check_ok "vault write (outer slot) succeeds" \
    "$BINARY" vault write "$VC" --offset 0 --capacity 20000 \
    --passphrase-file "$TMPDIR/vault_outer.pass" "$TMPDIR/vault_outer.in"
check_ok "vault write (inner slot, non-overlapping) succeeds" \
    "$BINARY" vault write "$VC" --offset 100000 --capacity 20000 \
    --passphrase-file "$TMPDIR/vault_inner.pass" "$TMPDIR/vault_inner.in"

check_ok "vault read (outer slot) succeeds" \
    "$BINARY" vault read "$VC" --offset 0 --capacity 20000 \
    --passphrase-file "$TMPDIR/vault_outer.pass" "$TMPDIR/vault_outer.out"
check_ok "outer round-trip matches" \
    cmp -s "$TMPDIR/vault_outer.in" "$TMPDIR/vault_outer.out"
check_ok "vault read (inner slot) succeeds" \
    "$BINARY" vault read "$VC" --offset 100000 --capacity 20000 \
    --passphrase-file "$TMPDIR/vault_inner.pass" "$TMPDIR/vault_inner.out"
check_ok "inner round-trip matches" \
    cmp -s "$TMPDIR/vault_inner.in" "$TMPDIR/vault_inner.out"

echo ""
echo "[test: vault deniability — indistinguishable failure modes]"
rm -f "$TMPDIR/vault_wrongpass.out" "$TMPDIR/vault_empty.out"
check_fail "wrong passphrase against the inner slot's coordinates is rejected" \
    "$BINARY" vault read "$VC" --offset 100000 --capacity 20000 \
    --passphrase-file "$TMPDIR/vault_outer.pass" "$TMPDIR/vault_wrongpass.out"
[ ! -f "$TMPDIR/vault_wrongpass.out" ] \
    && pass "wrong passphrase leaves no output file" || fail "wrong passphrase leaves no output file"

check_fail "correct passphrase at an untouched region is rejected" \
    "$BINARY" vault read "$VC" --offset 50000 --capacity 20000 \
    --passphrase-file "$TMPDIR/vault_inner.pass" "$TMPDIR/vault_empty.out"
[ ! -f "$TMPDIR/vault_empty.out" ] \
    && pass "correct passphrase at an untouched region leaves no output file" \
    || fail "correct passphrase at an untouched region leaves no output file"

# The whole point of deniability: a wrong passphrase and a right passphrase
# pointed at empty space must be byte-for-byte indistinguishable to the caller.
"$BINARY" vault read "$VC" --offset 100000 --capacity 20000 \
    --passphrase-file "$TMPDIR/vault_outer.pass" "$TMPDIR/vault_wrongpass2.out" \
    2> "$TMPDIR/vault_wrongpass.err"
"$BINARY" vault read "$VC" --offset 50000 --capacity 20000 \
    --passphrase-file "$TMPDIR/vault_inner.pass" "$TMPDIR/vault_empty2.out" \
    2> "$TMPDIR/vault_empty.err"
rm -f "$TMPDIR/vault_wrongpass2.out" "$TMPDIR/vault_empty2.out"
if diff -q "$TMPDIR/vault_wrongpass.err" "$TMPDIR/vault_empty.err" > /dev/null 2>&1; then
    pass "wrong-passphrase and untouched-region errors are identical"
else
    fail "wrong-passphrase and untouched-region errors are identical"
fi

check_fail "vault write rejects input larger than the slot's capacity" \
    "$BINARY" --force vault write "$VC" --offset 200000 --capacity 9 \
    --passphrase-file "$TMPDIR/vault_outer.pass" "$TMPDIR/vault_outer.in"
check_fail "vault write rejects stdin (capacity needs a known input length)" \
    sh -c "echo x | \"$BINARY\" vault write \"$VC\" --offset 200000 --capacity 20000 --passphrase-file \"$TMPDIR/vault_outer.pass\" -"

echo ""
echo "[test: vault footprint]"
FP=$("$BINARY" vault footprint --capacity 100000)
[ "$FP" = "100032" ] && pass "vault footprint --capacity 100000 == 100032" \
    || fail "vault footprint --capacity 100000 == 100032 (got $FP)"

# --- Test 22b: frozen vault fixture ---
# A container built once (--scrypt-cost 14, to keep CI fast) with two
# non-overlapping slots at fixed coordinates. Must keep decrypting bit-for-bit
# as vault.c evolves, the same guarantee the QSAFE007 fixtures give the main
# format (§18 above).
echo ""
echo "[test: frozen vault fixture]"
VFIX="$PROJECT_DIR/tests/fixtures/vault"
if [ -f "$VFIX/container.bin" ]; then
    cp "$VFIX/container.bin" "$TMPDIR/vfix_container.bin"
    "$BINARY" vault read "$TMPDIR/vfix_container.bin" --offset 0 --capacity 140000 \
        --scrypt-cost 14 --passphrase-file "$VFIX/decoy.pass" "$TMPDIR/vfix_decoy.out" >/dev/null 2>&1
    check_ok "decrypts the frozen vault fixture's decoy slot" \
        cmp -s "$VFIX/decoy.expected" "$TMPDIR/vfix_decoy.out"
    "$BINARY" vault read "$TMPDIR/vfix_container.bin" --offset 200000 --capacity 90000 \
        --scrypt-cost 14 --passphrase-file "$VFIX/hidden.pass" "$TMPDIR/vfix_hidden.out" >/dev/null 2>&1
    check_ok "decrypts the frozen vault fixture's hidden slot" \
        cmp -s "$VFIX/hidden.expected" "$TMPDIR/vfix_hidden.out"
else
    pass "frozen vault fixture skipped (not present)"
fi

# --- Test 22c: vault v2 volumes (anchor + directory + whole-container rewrite) ---
# All at --scrypt-cost 14 to keep the anchor scrypt fast in CI.
echo ""
echo "[test: vault v2 volume create/add/ls/extract/rm]"
V2C="$TMPDIR/v2vol.bin"
printf 'v2-volume-A-pass' > "$TMPDIR/v2a.pass"
printf 'v2-volume-B-pass' > "$TMPDIR/v2b.pass"
printf 'wrong-v2-pass'    > "$TMPDIR/v2w.pass"
echo "engagement loot payload for the v2 test" > "$TMPDIR/v2_loot.txt"

check_ok "vault create makes a volume" \
    "$BINARY" vault create "$V2C" --size 2000000 --scrypt-cost 14 --passphrase-file "$TMPDIR/v2a.pass"
"$BINARY" vault ls "$V2C" --scrypt-cost 14 --passphrase-file "$TMPDIR/v2a.pass" 2>/dev/null | grep -q "0 entries" \
    && pass "a fresh volume lists no entries" || fail "a fresh volume lists no entries"
check_fail "wrong passphrase cannot open the volume" \
    "$BINARY" vault ls "$V2C" --scrypt-cost 14 --passphrase-file "$TMPDIR/v2w.pass"

check_ok "vault add stores a named slot" \
    "$BINARY" vault add "$V2C" "$TMPDIR/v2_loot.txt" --name loot --offset 500000 --capacity 100000 \
    --scrypt-cost 14 --passphrase-file "$TMPDIR/v2a.pass"
"$BINARY" vault ls "$V2C" --scrypt-cost 14 --passphrase-file "$TMPDIR/v2a.pass" 2>/dev/null | grep -q "loot" \
    && pass "ls shows the added slot" || fail "ls shows the added slot"
check_ok "vault extract round-trips the slot" sh -c \
    "\"$BINARY\" vault extract \"$V2C\" --name loot \"$TMPDIR/v2_loot.out\" --scrypt-cost 14 --passphrase-file \"$TMPDIR/v2a.pass\" >/dev/null 2>&1 && cmp -s \"$TMPDIR/v2_loot.txt\" \"$TMPDIR/v2_loot.out\""
check_fail "vault add rejects a slot overlapping an existing one" \
    "$BINARY" vault add "$V2C" "$TMPDIR/v2_loot.txt" --name clash --offset 550000 --capacity 30000 \
    --scrypt-cost 14 --passphrase-file "$TMPDIR/v2a.pass"

# Snapshot-diff invariant: a mutating write re-randomizes the WHOLE container,
# so almost every byte differs (not just the touched slot).
cp "$V2C" "$TMPDIR/v2_before.bin"
echo "a second payload" > "$TMPDIR/v2_second.txt"
"$BINARY" vault add "$V2C" "$TMPDIR/v2_second.txt" --name second --offset 900000 --capacity 40000 \
    --scrypt-cost 14 --passphrase-file "$TMPDIR/v2a.pass" >/dev/null 2>&1
DIFFPCT=$(python3 - "$TMPDIR/v2_before.bin" "$V2C" << 'PYEOF'
import sys
a=open(sys.argv[1],'rb').read(); b=open(sys.argv[2],'rb').read()
same=sum(1 for x,y in zip(a,b) if x==y)
print(int(100*(len(a)-same)/len(a)))
PYEOF
)
[ "${DIFFPCT:-0}" -ge 99 ] \
    && pass "a mutating write re-randomizes the whole container (${DIFFPCT}% of bytes differ)" \
    || fail "a mutating write re-randomizes the whole container (only ${DIFFPCT}% differ)"

echo ""
echo "[test: vault v2 multi-volume --keep semantics]"
# Add a second volume B, preserving A via --keep.
check_ok "vault create --keep adds a second volume, preserving the first" \
    "$BINARY" vault create "$V2C" --keep "$TMPDIR/v2a.pass" --scrypt-cost 14 --passphrase-file "$TMPDIR/v2b.pass"
check_ok "volume A still opens after B is created with --keep" \
    "$BINARY" vault ls "$V2C" --scrypt-cost 14 --passphrase-file "$TMPDIR/v2a.pass"
check_ok "volume B opens" \
    "$BINARY" vault ls "$V2C" --scrypt-cost 14 --passphrase-file "$TMPDIR/v2b.pass"
# A's data must survive B's creation.
check_ok "volume A's slot survives the rewrite that created B" sh -c \
    "\"$BINARY\" vault extract \"$V2C\" --name loot \"$TMPDIR/v2_keep.out\" --scrypt-cost 14 --passphrase-file \"$TMPDIR/v2a.pass\" >/dev/null 2>&1 && cmp -s \"$TMPDIR/v2_loot.txt\" \"$TMPDIR/v2_keep.out\""
# Writing to A WITHOUT --keep B destroys B (documented VeraCrypt-style behavior).
echo "third payload" > "$TMPDIR/v2_third.txt"
"$BINARY" vault add "$V2C" "$TMPDIR/v2_third.txt" --name third --offset 1300000 --capacity 40000 \
    --scrypt-cost 14 --passphrase-file "$TMPDIR/v2a.pass" >/dev/null 2>&1
check_ok "the write target (A) still opens" \
    "$BINARY" vault ls "$V2C" --scrypt-cost 14 --passphrase-file "$TMPDIR/v2a.pass"
check_fail "a write omitting --keep destroys the un-kept volume B" \
    "$BINARY" vault ls "$V2C" --scrypt-cost 14 --passphrase-file "$TMPDIR/v2b.pass"

# rm drops one entry, preserving the rest.
check_ok "vault rm removes a named slot" \
    "$BINARY" vault rm "$V2C" --name third --scrypt-cost 14 --passphrase-file "$TMPDIR/v2a.pass"
"$BINARY" vault ls "$V2C" --scrypt-cost 14 --passphrase-file "$TMPDIR/v2a.pass" 2>/dev/null | grep -q "third" \
    && fail "rm removed the entry" || pass "rm removed the entry"
check_ok "other slots survive rm" sh -c \
    "\"$BINARY\" vault extract \"$V2C\" --name loot \"$TMPDIR/v2_rm.out\" --scrypt-cost 14 --passphrase-file \"$TMPDIR/v2a.pass\" >/dev/null 2>&1 && cmp -s \"$TMPDIR/v2_loot.txt\" \"$TMPDIR/v2_rm.out\""

# --- Test 22d: frozen v2 fixture ---
# A checked-in two-volume container. v2 containers are NOT byte-reproducible
# (each slot carries a fresh random nonce salt), so this fixture pins decrypt
# *behavior* — both volumes must keep opening and yielding their slots — rather
# than exact bytes. A format/derivation change that breaks compatibility trips
# this.
echo ""
echo "[test: frozen v2 fixture]"
V2FIX="$PROJECT_DIR/tests/fixtures/vault_v2"
if [ -f "$V2FIX/container.bin" ]; then
    cp "$V2FIX/container.bin" "$TMPDIR/v2fix.bin"
    "$BINARY" vault extract "$TMPDIR/v2fix.bin" --name notes "$TMPDIR/v2fix_a.out" \
        --scrypt-cost 14 --passphrase-file "$V2FIX/volA.pass" >/dev/null 2>&1
    check_ok "frozen v2 fixture: volume A opens and yields its slot" \
        cmp -s "$V2FIX/a_notes.expected" "$TMPDIR/v2fix_a.out"
    "$BINARY" vault extract "$TMPDIR/v2fix.bin" --name keys "$TMPDIR/v2fix_b.out" \
        --scrypt-cost 14 --passphrase-file "$V2FIX/volB.pass" >/dev/null 2>&1
    check_ok "frozen v2 fixture: volume B opens and yields its slot" \
        cmp -s "$V2FIX/b_keys.expected" "$TMPDIR/v2fix_b.out"
    check_fail "frozen v2 fixture: volume A's passphrase does not open volume B's slot" \
        "$BINARY" vault extract "$TMPDIR/v2fix.bin" --name keys "$TMPDIR/v2fix_x.out" \
        --scrypt-cost 14 --passphrase-file "$V2FIX/volA.pass"
else
    pass "frozen v2 fixture skipped (not present)"
fi

# --- Test 22e: vault v2 keyfile (two-factor) ---
# With a keyfile, the passphrase alone can neither locate the anchor nor open a
# slot: both factors are required.
echo ""
echo "[test: vault v2 keyfile two-factor]"
KFC="$TMPDIR/v2kf.bin"
printf 'v2-keyfile-volume-pass' > "$TMPDIR/kf.pass"
printf 'wrong-kf-volume-pass'   > "$TMPDIR/kf_wrong.pass"
head -c 64 /dev/urandom > "$TMPDIR/kf_key.bin"
head -c 64 /dev/urandom > "$TMPDIR/kf_wrong.bin"
echo "two-factor protected loot" > "$TMPDIR/kf_loot.txt"

check_ok "vault create --keyfile" \
    "$BINARY" vault create "$KFC" --size 1500000 --scrypt-cost 14 \
    --passphrase-file "$TMPDIR/kf.pass" --keyfile "$TMPDIR/kf_key.bin"
check_ok "vault add --keyfile" \
    "$BINARY" vault add "$KFC" "$TMPDIR/kf_loot.txt" --name loot --offset 400000 --capacity 80000 \
    --scrypt-cost 14 --passphrase-file "$TMPDIR/kf.pass" --keyfile "$TMPDIR/kf_key.bin"
check_ok "correct passphrase + correct keyfile extracts" sh -c \
    "\"$BINARY\" vault extract \"$KFC\" --name loot \"$TMPDIR/kf_loot.out\" --scrypt-cost 14 --passphrase-file \"$TMPDIR/kf.pass\" --keyfile \"$TMPDIR/kf_key.bin\" >/dev/null 2>&1 && cmp -s \"$TMPDIR/kf_loot.txt\" \"$TMPDIR/kf_loot.out\""
check_fail "passphrase alone (no keyfile) cannot open a keyfile volume" \
    "$BINARY" vault ls "$KFC" --scrypt-cost 14 --passphrase-file "$TMPDIR/kf.pass"
check_fail "wrong keyfile cannot open" \
    "$BINARY" vault ls "$KFC" --scrypt-cost 14 --passphrase-file "$TMPDIR/kf.pass" --keyfile "$TMPDIR/kf_wrong.bin"
check_fail "keyfile alone (wrong passphrase) cannot open" \
    "$BINARY" vault ls "$KFC" --scrypt-cost 14 --passphrase-file "$TMPDIR/kf_wrong.pass" --keyfile "$TMPDIR/kf_key.bin"
check_ok "both factors correct opens" \
    "$BINARY" vault ls "$KFC" --scrypt-cost 14 --passphrase-file "$TMPDIR/kf.pass" --keyfile "$TMPDIR/kf_key.bin"

# --- Test 22f: vault v2 passwd (change a volume's passphrase) ---
echo ""
echo "[test: vault v2 passwd]"
PWC="$TMPDIR/v2pw.bin"
printf 'passwd-old-secret' > "$TMPDIR/pw_old.pass"
printf 'passwd-new-secret' > "$TMPDIR/pw_new.pass"
echo "loot that must survive a passphrase change" > "$TMPDIR/pw_loot.txt"
check_ok "passwd: create + add" sh -c \
    "\"$BINARY\" vault create \"$PWC\" --size 3000000 --scrypt-cost 14 --passphrase-file \"$TMPDIR/pw_old.pass\" >/dev/null 2>&1 && \
     \"$BINARY\" vault add \"$PWC\" \"$TMPDIR/pw_loot.txt\" --name loot --offset 500000 --capacity 80000 --scrypt-cost 14 --passphrase-file \"$TMPDIR/pw_old.pass\" >/dev/null 2>&1"
check_ok "vault passwd changes the passphrase" \
    "$BINARY" vault passwd "$PWC" --scrypt-cost 14 \
    --passphrase-file "$TMPDIR/pw_old.pass" --new-passphrase-file "$TMPDIR/pw_new.pass"
check_fail "old passphrase no longer opens the volume" \
    "$BINARY" vault ls "$PWC" --scrypt-cost 14 --passphrase-file "$TMPDIR/pw_old.pass"
check_ok "new passphrase opens the volume" \
    "$BINARY" vault ls "$PWC" --scrypt-cost 14 --passphrase-file "$TMPDIR/pw_new.pass"
check_ok "slot content survives the passphrase change" sh -c \
    "\"$BINARY\" vault extract \"$PWC\" --name loot \"$TMPDIR/pw_loot.out\" --scrypt-cost 14 --passphrase-file \"$TMPDIR/pw_new.pass\" >/dev/null 2>&1 && cmp -s \"$TMPDIR/pw_loot.txt\" \"$TMPDIR/pw_loot.out\""

# --- Test 22g: vault v2 auto-placement (add without --offset/--capacity) ---
echo ""
echo "[test: vault v2 auto-placement]"
APC="$TMPDIR/v2ap.bin"
printf 'auto-place-pass' > "$TMPDIR/ap.pass"
echo "alpha payload" > "$TMPDIR/ap_a.txt"
echo "bravo payload, a little longer than alpha for variety" > "$TMPDIR/ap_b.txt"
head -c 30000 /dev/urandom > "$TMPDIR/ap_c.bin"
check_ok "auto-place: create" \
    "$BINARY" vault create "$APC" --size 2000000 --scrypt-cost 14 --passphrase-file "$TMPDIR/ap.pass"
check_ok "add with no --offset/--capacity (alpha)" \
    "$BINARY" vault add "$APC" "$TMPDIR/ap_a.txt" --name alpha --scrypt-cost 14 --passphrase-file "$TMPDIR/ap.pass"
check_ok "add with no --offset/--capacity (bravo)" \
    "$BINARY" vault add "$APC" "$TMPDIR/ap_b.txt" --name bravo --scrypt-cost 14 --passphrase-file "$TMPDIR/ap.pass"
check_ok "add with no --offset/--capacity (charlie, binary)" \
    "$BINARY" vault add "$APC" "$TMPDIR/ap_c.bin" --name charlie --scrypt-cost 14 --passphrase-file "$TMPDIR/ap.pass"
# All three auto-placed slots must round-trip (i.e. they did not overlap).
check_ok "auto-placed alpha round-trips" sh -c \
    "\"$BINARY\" vault extract \"$APC\" --name alpha \"$TMPDIR/ap_a.out\" --scrypt-cost 14 --passphrase-file \"$TMPDIR/ap.pass\" >/dev/null 2>&1 && cmp -s \"$TMPDIR/ap_a.txt\" \"$TMPDIR/ap_a.out\""
check_ok "auto-placed bravo round-trips" sh -c \
    "\"$BINARY\" vault extract \"$APC\" --name bravo \"$TMPDIR/ap_b.out\" --scrypt-cost 14 --passphrase-file \"$TMPDIR/ap.pass\" >/dev/null 2>&1 && cmp -s \"$TMPDIR/ap_b.txt\" \"$TMPDIR/ap_b.out\""
check_ok "auto-placed charlie round-trips" sh -c \
    "\"$BINARY\" vault extract \"$APC\" --name charlie \"$TMPDIR/ap_c.out\" --scrypt-cost 14 --passphrase-file \"$TMPDIR/ap.pass\" >/dev/null 2>&1 && cmp -s \"$TMPDIR/ap_c.bin\" \"$TMPDIR/ap_c.out\""
# Default capacity is an exact fit: content_len + 8. "alpha payload\n" is 14
# bytes, so capacity = 22.
"$BINARY" vault ls "$APC" --scrypt-cost 14 --passphrase-file "$TMPDIR/ap.pass" 2>/dev/null | grep alpha | grep -q "capacity=22" \
    && pass "auto capacity is an exact fit (14 + 8)" || fail "auto capacity is an exact fit (14 + 8)"
# No-free-space is reported, not a crash.
check_ok "auto-place: create small" \
    "$BINARY" vault create "$TMPDIR/v2small.bin" --size 10000 --scrypt-cost 14 --passphrase-file "$TMPDIR/ap.pass"
head -c 8000 /dev/urandom > "$TMPDIR/ap_big.bin"
check_fail "auto-place rejects a slot with no room" \
    "$BINARY" vault add "$TMPDIR/v2small.bin" "$TMPDIR/ap_big.bin" --name toobig \
    --scrypt-cost 14 --passphrase-file "$TMPDIR/ap.pass"

# --- Test 22h: vault v2 overflow directories (> 46 slots per volume) ---
# Crossing the 46-slot boundary requires ~47 adds, each a whole-container
# rewrite, so this is slow (~30-60s). It runs only when QSAFE_SLOW_TESTS=1; the
# flag mechanism itself is covered fast by the C unit tests. Set the env var in
# a scheduled/nightly job to exercise the full chain end to end.
echo ""
echo "[test: vault v2 overflow directories]"
if [ "${QSAFE_SLOW_TESTS:-0}" = "1" ]; then
    OFC="$TMPDIR/v2overflow.bin"
    printf 'overflow-pass' > "$TMPDIR/of.pass"
    printf 'DATA' > "$TMPDIR/of_d.txt"
    "$BINARY" vault create "$OFC" --size 3000000 --scrypt-cost 14 --passphrase-file "$TMPDIR/of.pass" >/dev/null 2>&1
    of_ok=1
    for i in $(seq 1 48); do
        "$BINARY" vault add "$OFC" "$TMPDIR/of_d.txt" --name "s$i" --scrypt-cost 14 \
            --passphrase-file "$TMPDIR/of.pass" >/dev/null 2>&1 || { of_ok=0; break; }
    done
    [ "$of_ok" = 1 ] && pass "added 48 slots (past the 46-per-block boundary)" \
        || fail "added 48 slots (past the 46-per-block boundary)"
    N=$("$BINARY" vault ls "$OFC" --scrypt-cost 14 --passphrase-file "$TMPDIR/of.pass" 2>/dev/null | grep -c "^  s")
    [ "$N" = 48 ] && pass "all 48 slots listed across the directory chain" \
        || fail "all 48 slots listed across the directory chain (got $N)"
    # s48 lives in the overflow block (index >= 46).
    check_ok "an overflow-block slot extracts correctly" sh -c \
        "\"$BINARY\" vault extract \"$OFC\" --name s48 \"$TMPDIR/of_s48\" --scrypt-cost 14 --passphrase-file \"$TMPDIR/of.pass\" >/dev/null 2>&1 && [ \"\$(cat \"$TMPDIR/of_s48\")\" = DATA ]"
else
    pass "overflow-directory e2e skipped (set QSAFE_SLOW_TESTS=1 to run)"
fi

# --- Results ---
echo ""
echo "=== Results: $TESTS_PASSED/$TESTS_RUN passed ==="
exit $FAILED
