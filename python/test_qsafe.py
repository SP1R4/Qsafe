"""Tests for the libqsafe Python bindings.

Run after building the library:
    make lib
    QSAFE_LIB=./libqsafe.so python3 python/test_qsafe.py     # .dylib on macOS
"""

import os
import shutil
import sys
import tempfile
import unittest

# For in-repo runs, prefer the source package. Set QSAFE_TEST_INSTALLED=1 to
# test an installed wheel instead (used by the wheels CI) — that also has to
# undo Python's automatic script-directory sys.path entry, which would shadow
# the installed package with the source one.
_here = os.path.dirname(os.path.abspath(__file__))
if os.environ.get("QSAFE_TEST_INSTALLED"):
    sys.path[:] = [p for p in sys.path if os.path.abspath(p or os.getcwd()) != _here]
else:
    sys.path.insert(0, _here)
import qsafe  # noqa: E402


class TestQsafeBindings(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="qsafe-test-")
        self.sk = os.path.join(self.d, "sk.bin")
        self.pk = os.path.join(self.d, "pk.bin")
        self.pw = "bindings-pass"
        qsafe.keygen(self.sk, self.pk, self.pw)

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def test_version(self):
        self.assertRegex(qsafe.version(), r"^\d+\.\d+\.\d+$")

    def test_bytes_roundtrip(self):
        data = b"hello, post-quantum world\x00\x01\x02"
        ct = qsafe.encrypt_bytes(data, [self.pk])
        self.assertNotEqual(ct, data)
        self.assertEqual(qsafe.decrypt_bytes(ct, self.sk, self.pw), data)

    def test_file_roundtrip(self):
        src = os.path.join(self.d, "m.txt")
        with open(src, "wb") as f:
            f.write(b"file data")
        enc = os.path.join(self.d, "m.q")
        dec = os.path.join(self.d, "m.out")
        qsafe.encrypt(src, enc, [self.pk])
        qsafe.decrypt(enc, dec, self.sk, self.pw)
        with open(dec, "rb") as f:
            self.assertEqual(f.read(), b"file data")
        qsafe.verify(enc, self.sk, self.pw)  # must not raise

    def test_multi_recipient(self):
        sk2 = os.path.join(self.d, "sk2")
        pk2 = os.path.join(self.d, "pk2")
        qsafe.keygen(sk2, pk2, "pw2")
        ct = qsafe.encrypt_bytes(b"shared secret", [self.pk, pk2])
        self.assertEqual(qsafe.decrypt_bytes(ct, self.sk, self.pw), b"shared secret")
        self.assertEqual(qsafe.decrypt_bytes(ct, sk2, "pw2"), b"shared secret")

    def test_large_buffer(self):
        data = os.urandom(300 * 1024)  # multi-frame
        ct = qsafe.encrypt_bytes(data, [self.pk])
        self.assertEqual(qsafe.decrypt_bytes(ct, self.sk, self.pw), data)

    def test_wrong_passphrase_raises(self):
        ct = qsafe.encrypt_bytes(b"x", [self.pk])
        with self.assertRaises(qsafe.QsafeError):
            qsafe.decrypt_bytes(ct, self.sk, "wrong-pass")

    def test_tampered_ciphertext_raises(self):
        ct = bytearray(qsafe.encrypt_bytes(b"a reasonably long plaintext here", [self.pk]))
        ct[-1] ^= 0xFF  # corrupt the trailing tag
        with self.assertRaises(qsafe.QsafeError):
            qsafe.decrypt_bytes(bytes(ct), self.sk, self.pw)

    def test_signatures(self):
        ssk = os.path.join(self.d, "ssk")
        spk = os.path.join(self.d, "spk")
        qsafe.sign_keygen(ssk, spk, "spass")
        doc = os.path.join(self.d, "doc")
        with open(doc, "wb") as f:
            f.write(b"please sign me")
        sig = os.path.join(self.d, "doc.sig")
        qsafe.sign(doc, sig, ssk, "spass")
        qsafe.verify_signature(doc, sig, spk)  # must not raise
        with open(doc, "ab") as f:
            f.write(b"tampered")
        with self.assertRaises(qsafe.QsafeError):
            qsafe.verify_signature(doc, sig, spk)


if __name__ == "__main__":
    unittest.main(verbosity=2)
