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
"$BINARY" inspect "$TMPDIR/test_input.enc" 2>/dev/null | grep -q "QSAFE006" \
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

# --- Test 17: framed format (QSAFE006) ---
echo ""
echo "[test: framed format]"
# Multi-frame round-trip (well over one 64 KiB frame).
dd if=/dev/urandom of="$TMPDIR/multi.in" bs=1024 count=300 >/dev/null 2>&1
"$BINARY" --force --key-file "$KEYFILE" encrypt "$TMPDIR/multi.in" "$TMPDIR/multi.q" >/dev/null 2>&1
"$BINARY" --force --key-file "$KEYFILE" decrypt "$TMPDIR/multi.q" "$TMPDIR/multi.out" >/dev/null 2>&1
check_ok "multi-frame round-trip matches" cmp -s "$TMPDIR/multi.in" "$TMPDIR/multi.out"
"$BINARY" inspect "$TMPDIR/multi.q" 2>/dev/null | grep -q "framed" \
    && pass "inspect reports framed AEAD" || fail "inspect reports framed AEAD"
# Edge: META(272) + file == 65536 forces a full frame plus an empty final frame.
dd if=/dev/urandom of="$TMPDIR/exact.in" bs=65264 count=1 >/dev/null 2>&1
"$BINARY" --force --key-file "$KEYFILE" encrypt "$TMPDIR/exact.in" "$TMPDIR/exact.q" >/dev/null 2>&1
"$BINARY" --force --key-file "$KEYFILE" decrypt "$TMPDIR/exact.q" "$TMPDIR/exact.out" >/dev/null 2>&1
check_ok "frame-multiple round-trip matches" cmp -s "$TMPDIR/exact.in" "$TMPDIR/exact.out"
# Truncation (dropping the tail of the final frame) must be detected.
SZ=$(wc -c < "$TMPDIR/multi.q"); head -c $((SZ-40)) "$TMPDIR/multi.q" > "$TMPDIR/multi.trunc.q"
check_fail "truncated framed file is rejected" \
    "$BINARY" --key-file "$KEYFILE" verify "$TMPDIR/multi.trunc.q"
# Tampering a frame byte must be detected.
cp "$TMPDIR/multi.q" "$TMPDIR/multi.bad.q"
printf 'X' | dd of="$TMPDIR/multi.bad.q" bs=1 seek=2000 count=1 conv=notrunc 2>/dev/null
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
  *)
    pass "keychain test skipped (macOS only)"
    ;;
esac

# --- Results ---
echo ""
echo "=== Results: $TESTS_PASSED/$TESTS_RUN passed ==="
exit $FAILED
