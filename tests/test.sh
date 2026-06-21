#!/bin/bash
# Qsafe 4.0 - End-to-end integration tests

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BINARY="$PROJECT_DIR/qsafe"
TMPDIR=$(mktemp -d /tmp/qsafe_test_XXXXXX)
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
echo "=== Qsafe 4.0 Integration Tests ==="

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

# --- Test 5c: permission bits preserved ---
echo ""
echo "[test: permission metadata preserved]"
echo "perm test" > "$TMPDIR/perm.txt"
chmod 600 "$TMPDIR/perm.txt"
"$BINARY" --force --key-file "$KEYFILE" encrypt "$TMPDIR/perm.txt" "$TMPDIR/perm.enc" >/dev/null 2>&1
rm -f "$TMPDIR/perm.txt"
"$BINARY" --force --key-file "$KEYFILE" decrypt "$TMPDIR/perm.enc" "$TMPDIR/perm.txt" >/dev/null 2>&1
# GNU stat uses -c "%a"; BSD/macOS stat uses -f "%Lp". Try GNU first because
# GNU's -f means --file-system and would succeed with the wrong output.
MODE=$(stat -c "%a" "$TMPDIR/perm.txt" 2>/dev/null || stat -f "%Lp" "$TMPDIR/perm.txt" 2>/dev/null)
if [ "$MODE" = "600" ]; then pass "decrypted file mode is 600"; else fail "decrypted file mode is 600 (got $MODE)"; fi

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

# --- Results ---
echo ""
echo "=== Results: $TESTS_PASSED/$TESTS_RUN passed ==="
exit $FAILED
