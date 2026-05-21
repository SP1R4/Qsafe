#!/bin/bash
# Qsafe 3.0 - End-to-end integration tests

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BINARY="$PROJECT_DIR/crypto-v2"
TMPDIR=$(mktemp -d /tmp/qsafe_test_XXXXXX)
PASS="test-passphrase-e2e"
KEYFILE="$TMPDIR/default_key.bin"
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

# check <description> : passes if the following command succeeds
check_ok() {
    local desc="$1"; shift
    if "$@" > /dev/null 2>&1; then pass "$desc"; else fail "$desc"; fi
}

# check_fail <description> : passes if the following command fails
check_fail() {
    local desc="$1"; shift
    if "$@" > /dev/null 2>&1; then fail "$desc"; else pass "$desc"; fi
}

echo ""
echo "=== Qsafe 3.0 Integration Tests ==="

if [ ! -x "$BINARY" ]; then
    echo "ERROR: $BINARY not found or not executable"
    exit 1
fi

# --- Test 1: file encrypt/decrypt round-trip ---
echo ""
echo "[test: file encrypt/decrypt round-trip]"
echo "Hello, Qsafe integration test!" > "$TMPDIR/test_input.txt"

check_ok "encrypt file succeeds" \
    "$BINARY" --force --key-file "$KEYFILE" --passphrase "$PASS" \
    encrypt "$TMPDIR/test_input.txt" "$TMPDIR/test_input.enc" file
check_ok "decrypt file succeeds" \
    "$BINARY" --force --key-file "$KEYFILE" --passphrase "$PASS" \
    decrypt "$TMPDIR/test_input.enc" "$TMPDIR/test_output.txt" file
check_ok "decrypted file matches original" \
    diff -q "$TMPDIR/test_input.txt" "$TMPDIR/test_output.txt"

# --- Test 2: empty file round-trip ---
echo ""
echo "[test: empty file round-trip]"
: > "$TMPDIR/empty.txt"
check_ok "encrypt empty file succeeds" \
    "$BINARY" --force --key-file "$KEYFILE" --passphrase "$PASS" \
    encrypt "$TMPDIR/empty.txt" "$TMPDIR/empty.enc" file
check_ok "decrypt empty file succeeds" \
    "$BINARY" --force --key-file "$KEYFILE" --passphrase "$PASS" \
    decrypt "$TMPDIR/empty.enc" "$TMPDIR/empty.out" file
check_ok "decrypted empty file matches original" \
    diff -q "$TMPDIR/empty.txt" "$TMPDIR/empty.out"

# --- Test 3: large multi-chunk file round-trip (streaming) ---
echo ""
echo "[test: large file round-trip]"
dd if=/dev/urandom of="$TMPDIR/large.bin" bs=1024 count=2048 > /dev/null 2>&1
check_ok "encrypt 2 MiB file succeeds" \
    "$BINARY" --force --key-file "$KEYFILE" --passphrase "$PASS" \
    encrypt "$TMPDIR/large.bin" "$TMPDIR/large.enc" file
check_ok "decrypt 2 MiB file succeeds" \
    "$BINARY" --force --key-file "$KEYFILE" --passphrase "$PASS" \
    decrypt "$TMPDIR/large.enc" "$TMPDIR/large.out" file
check_ok "decrypted large file matches original" \
    cmp -s "$TMPDIR/large.bin" "$TMPDIR/large.out"

# --- Test 4: directory encrypt/decrypt round-trip ---
echo ""
echo "[test: directory encrypt/decrypt round-trip]"
mkdir -p "$TMPDIR/input_dir/sub"
echo "File A content" > "$TMPDIR/input_dir/a.txt"
echo "File B content" > "$TMPDIR/input_dir/b.txt"
echo "Nested file"    > "$TMPDIR/input_dir/sub/c.txt"

check_ok "encrypt directory succeeds" \
    "$BINARY" --force --key-file "$KEYFILE" --passphrase "$PASS" \
    encrypt "$TMPDIR/input_dir" "$TMPDIR/encrypted_dir" dir
check_ok "decrypt directory succeeds" \
    "$BINARY" --force --key-file "$KEYFILE" --passphrase "$PASS" \
    decrypt "$TMPDIR/encrypted_dir" "$TMPDIR/decrypted_dir" dir
check_ok "decrypted dir file a.txt matches" \
    diff -q "$TMPDIR/input_dir/a.txt" "$TMPDIR/decrypted_dir/a.txt"
check_ok "decrypted dir file b.txt matches" \
    diff -q "$TMPDIR/input_dir/b.txt" "$TMPDIR/decrypted_dir/b.txt"
check_ok "decrypted nested file sub/c.txt matches (recursive)" \
    diff -q "$TMPDIR/input_dir/sub/c.txt" "$TMPDIR/decrypted_dir/sub/c.txt"

# --- Test 5: wrong passphrase rejection ---
echo ""
echo "[test: wrong passphrase rejection]"
check_fail "wrong passphrase rejects decryption" \
    "$BINARY" --force --key-file "$KEYFILE" --passphrase "wrong-pass" \
    decrypt "$TMPDIR/test_input.enc" "$TMPDIR/wrong_pass_out.txt" file

# --- Test 6: tampered ciphertext rejection ---
echo ""
echo "[test: tampered ciphertext rejection]"
cp "$TMPDIR/test_input.enc" "$TMPDIR/tampered.enc"
# Flip a byte in the AES ciphertext area (past the 8-byte header + 1568-byte KEM ciphertext)
python3 -c "
with open('$TMPDIR/tampered.enc', 'r+b') as f:
    f.seek(1600)
    b = f.read(1)
    f.seek(1600)
    f.write(bytes([b[0] ^ 0xFF]))
" 2>/dev/null || dd if=/dev/urandom of="$TMPDIR/tampered.enc" bs=1 count=1 seek=1600 conv=notrunc 2>/dev/null

check_fail "tampered ciphertext rejects decryption" \
    "$BINARY" --force --key-file "$KEYFILE" --passphrase "$PASS" \
    decrypt "$TMPDIR/tampered.enc" "$TMPDIR/tampered_out.txt" file

# --- Test 7: custom key file ---
echo ""
echo "[test: custom key file]"
echo "Custom key test data" > "$TMPDIR/custom_input.txt"

check_ok "encrypt with custom key file succeeds" \
    "$BINARY" --force --key-file "$TMPDIR/custom.key" --passphrase "$PASS" \
    encrypt "$TMPDIR/custom_input.txt" "$TMPDIR/custom_input.enc" file
check_ok "custom key file created" \
    test -f "$TMPDIR/custom.key"
check_ok "decrypt with custom key file succeeds" \
    "$BINARY" --force --key-file "$TMPDIR/custom.key" --passphrase "$PASS" \
    decrypt "$TMPDIR/custom_input.enc" "$TMPDIR/custom_output.txt" file
check_ok "custom key file round-trip matches" \
    diff -q "$TMPDIR/custom_input.txt" "$TMPDIR/custom_output.txt"

# --- Test 8: invalid arguments rejected ---
echo ""
echo "[test: argument validation]"
check_fail "missing passphrase is rejected" \
    "$BINARY" encrypt "$TMPDIR/test_input.txt" "$TMPDIR/x.enc" file
check_fail "invalid operation is rejected" \
    "$BINARY" --passphrase "$PASS" frobnicate "$TMPDIR/test_input.txt" "$TMPDIR/x.enc" file

# --- Results ---
echo ""
echo "=== Results: $TESTS_PASSED/$TESTS_RUN passed ==="
exit $FAILED
