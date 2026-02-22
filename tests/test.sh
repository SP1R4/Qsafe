#!/bin/bash
# Qsafe 2.0 - End-to-end integration tests

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

echo ""
echo "=== Qsafe 2.0 Integration Tests ==="

# Check binary exists
if [ ! -x "$BINARY" ]; then
    echo "ERROR: $BINARY not found or not executable"
    exit 1
fi

# --- Test 1: Encrypt and decrypt a single file ---
echo ""
echo "[test: file encrypt/decrypt round-trip]"
echo "Hello, Qsafe integration test!" > "$TMPDIR/test_input.txt"

if "$BINARY" --key-file "$KEYFILE" --passphrase "$PASS" encrypt "$TMPDIR/test_input.txt" "$TMPDIR/test_input.enc" file > /dev/null 2>&1; then
    pass "encrypt file succeeds"
else
    fail "encrypt file succeeds"
fi

if "$BINARY" --key-file "$KEYFILE" --passphrase "$PASS" decrypt "$TMPDIR/test_input.enc" "$TMPDIR/test_output.txt" file > /dev/null 2>&1; then
    pass "decrypt file succeeds"
else
    fail "decrypt file succeeds"
fi

if diff -q "$TMPDIR/test_input.txt" "$TMPDIR/test_output.txt" > /dev/null 2>&1; then
    pass "decrypted file matches original"
else
    fail "decrypted file matches original"
fi

# --- Test 2: Encrypt and decrypt a directory ---
echo ""
echo "[test: directory encrypt/decrypt round-trip]"
mkdir -p "$TMPDIR/input_dir"
echo "File A content" > "$TMPDIR/input_dir/a.txt"
echo "File B content" > "$TMPDIR/input_dir/b.txt"

if "$BINARY" --key-file "$KEYFILE" --passphrase "$PASS" encrypt "$TMPDIR/input_dir" "$TMPDIR/encrypted_dir" dir > /dev/null 2>&1; then
    pass "encrypt directory succeeds"
else
    fail "encrypt directory succeeds"
fi

if "$BINARY" --key-file "$KEYFILE" --passphrase "$PASS" decrypt "$TMPDIR/encrypted_dir" "$TMPDIR/decrypted_dir" dir > /dev/null 2>&1; then
    pass "decrypt directory succeeds"
else
    fail "decrypt directory succeeds"
fi

if diff -q "$TMPDIR/input_dir/a.txt" "$TMPDIR/decrypted_dir/a.txt" > /dev/null 2>&1; then
    pass "decrypted dir file a.txt matches"
else
    fail "decrypted dir file a.txt matches"
fi

if diff -q "$TMPDIR/input_dir/b.txt" "$TMPDIR/decrypted_dir/b.txt" > /dev/null 2>&1; then
    pass "decrypted dir file b.txt matches"
else
    fail "decrypted dir file b.txt matches"
fi

# --- Test 3: Wrong passphrase fails ---
echo ""
echo "[test: wrong passphrase rejection]"
if "$BINARY" --key-file "$KEYFILE" --passphrase "wrong-pass" decrypt "$TMPDIR/test_input.enc" "$TMPDIR/wrong_pass_out.txt" file > /dev/null 2>&1; then
    fail "wrong passphrase rejects decryption"
else
    pass "wrong passphrase rejects decryption"
fi

# --- Test 4: Tampered ciphertext fails ---
echo ""
echo "[test: tampered ciphertext rejection]"
cp "$TMPDIR/test_input.enc" "$TMPDIR/tampered.enc"
# Flip a byte in the AES ciphertext area (past header + KEM ciphertext)
python3 -c "
with open('$TMPDIR/tampered.enc', 'r+b') as f:
    f.seek(1600)
    b = f.read(1)
    f.seek(1600)
    f.write(bytes([b[0] ^ 0xFF]))
" 2>/dev/null || dd if=/dev/urandom of="$TMPDIR/tampered.enc" bs=1 count=1 seek=1600 conv=notrunc 2>/dev/null

if "$BINARY" --key-file "$KEYFILE" --passphrase "$PASS" decrypt "$TMPDIR/tampered.enc" "$TMPDIR/tampered_out.txt" file > /dev/null 2>&1; then
    fail "tampered ciphertext rejects decryption"
else
    pass "tampered ciphertext rejects decryption"
fi

# --- Test 5: Custom key file ---
echo ""
echo "[test: custom key file]"
echo "Custom key test data" > "$TMPDIR/custom_input.txt"

if "$BINARY" --key-file "$TMPDIR/custom.key" --passphrase "$PASS" encrypt "$TMPDIR/custom_input.txt" "$TMPDIR/custom_input.enc" file > /dev/null 2>&1; then
    pass "encrypt with custom key file succeeds"
else
    fail "encrypt with custom key file succeeds"
fi

if [ -f "$TMPDIR/custom.key" ]; then
    pass "custom key file created"
else
    fail "custom key file created"
fi

if "$BINARY" --key-file "$TMPDIR/custom.key" --passphrase "$PASS" decrypt "$TMPDIR/custom_input.enc" "$TMPDIR/custom_output.txt" file > /dev/null 2>&1; then
    pass "decrypt with custom key file succeeds"
else
    fail "decrypt with custom key file succeeds"
fi

if diff -q "$TMPDIR/custom_input.txt" "$TMPDIR/custom_output.txt" > /dev/null 2>&1; then
    pass "custom key file round-trip matches"
else
    fail "custom key file round-trip matches"
fi

# --- Results ---
echo ""
echo "=== Results: $TESTS_PASSED/$TESTS_RUN passed ==="
exit $FAILED
