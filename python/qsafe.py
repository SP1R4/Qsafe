"""Python bindings for libqsafe (hybrid post-quantum file encryption).

Loads the libqsafe shared library via ctypes and exposes Pythonic wrappers,
including byte-buffer helpers (which stage data through temp files, since the
engine is file-oriented).

The library is located via, in order: the ``QSAFE_LIB`` env var, the directory
of this module and its parent, then the system loader path.

Example
-------
>>> import qsafe
>>> qsafe.keygen("sk.bin", "pk.bin", "passphrase")
>>> blob = qsafe.encrypt_bytes(b"hello", ["pk.bin"])
>>> qsafe.decrypt_bytes(blob, "sk.bin", "passphrase")
b'hello'
"""

import ctypes
import os
import tempfile

__all__ = [
    "QsafeError", "version",
    "keygen", "encrypt", "decrypt", "verify",
    "sign_keygen", "sign", "verify_signature",
    "encrypt_bytes", "decrypt_bytes",
]

_MESSAGES = {
    0: "ok", 1: "I/O error", 2: "out of memory",
    3: "cryptographic operation failed", 4: "invalid input",
    5: "authentication failed",
}


class QsafeError(Exception):
    """Raised when a libqsafe call returns a non-zero status."""

    def __init__(self, code: int):
        self.code = code
        super().__init__(_MESSAGES.get(code, f"error {code}"))


def _find_library() -> str:
    names = ("libqsafe.so", "libqsafe.dylib", "libqsafe.dll")
    env = os.environ.get("QSAFE_LIB")
    if env:
        return env
    here = os.path.dirname(os.path.abspath(__file__))
    for d in (here, os.path.dirname(here)):
        for name in names:
            p = os.path.join(d, name)
            if os.path.exists(p):
                return p
    for name in names:  # let the loader search standard paths
        try:
            ctypes.CDLL(name)
            return name
        except OSError:
            continue
    raise OSError("libqsafe not found; build it with `make lib` or set QSAFE_LIB")


_lib = ctypes.CDLL(_find_library())

_C = ctypes.c_char_p
_INT = ctypes.c_int

_lib.qsafe_version.restype = _C
_lib.qsafe_strerror.restype = _C
_lib.qsafe_strerror.argtypes = [_INT]
_lib.qsafe_keygen.restype = _INT
_lib.qsafe_keygen.argtypes = [_C, _C, _C]
_lib.qsafe_encrypt.restype = _INT
_lib.qsafe_encrypt.argtypes = [_C, _C, ctypes.POINTER(_C), ctypes.c_size_t]
_lib.qsafe_decrypt.restype = _INT
_lib.qsafe_decrypt.argtypes = [_C, _C, _C, _C]
_lib.qsafe_verify.restype = _INT
_lib.qsafe_verify.argtypes = [_C, _C, _C]
_lib.qsafe_sign_keygen.restype = _INT
_lib.qsafe_sign_keygen.argtypes = [_C, _C, _C]
_lib.qsafe_sign.restype = _INT
_lib.qsafe_sign.argtypes = [_C, _C, _C, _C]
_lib.qsafe_verify_signature.restype = _INT
_lib.qsafe_verify_signature.argtypes = [_C, _C, _C]


def _b(s):
    return s.encode() if isinstance(s, str) else s


def _check(code: int) -> None:
    if code != 0:
        raise QsafeError(code)


def version() -> str:
    return _lib.qsafe_version().decode()


def keygen(secret_path, public_path, passphrase) -> None:
    _check(_lib.qsafe_keygen(_b(secret_path), _b(public_path), _b(passphrase)))


def encrypt(in_path, out_path, recipient_public_paths) -> None:
    recips = list(recipient_public_paths)
    arr = (_C * len(recips))(*[_b(r) for r in recips])
    _check(_lib.qsafe_encrypt(_b(in_path), _b(out_path), arr, len(recips)))


def decrypt(in_path, out_path, secret_path, passphrase) -> None:
    _check(_lib.qsafe_decrypt(_b(in_path), _b(out_path), _b(secret_path), _b(passphrase)))


def verify(in_path, secret_path, passphrase) -> None:
    """Authenticate an encrypted file; raises QsafeError if not intact."""
    _check(_lib.qsafe_verify(_b(in_path), _b(secret_path), _b(passphrase)))


def sign_keygen(secret_path, public_path, passphrase) -> None:
    _check(_lib.qsafe_sign_keygen(_b(secret_path), _b(public_path), _b(passphrase)))


def sign(in_path, sig_path, sign_secret_path, passphrase) -> None:
    _check(_lib.qsafe_sign(_b(in_path), _b(sig_path), _b(sign_secret_path), _b(passphrase)))


def verify_signature(in_path, sig_path, sign_public_path) -> None:
    """Verify a detached signature; raises QsafeError if invalid."""
    _check(_lib.qsafe_verify_signature(_b(in_path), _b(sig_path), _b(sign_public_path)))


# --- byte-buffer convenience (staged through temp files) ---

def _tmp(data: bytes = None) -> str:
    fd, path = tempfile.mkstemp(prefix="qsafe-py-")
    try:
        if data is not None:
            os.write(fd, data)
    finally:
        os.close(fd)
    return path


def encrypt_bytes(data: bytes, recipient_public_paths) -> bytes:
    src = _tmp(data)
    dst = _tmp()
    try:
        encrypt(src, dst, recipient_public_paths)
        with open(dst, "rb") as f:
            return f.read()
    finally:
        os.remove(src)
        os.remove(dst)


def decrypt_bytes(ciphertext: bytes, secret_path, passphrase) -> bytes:
    src = _tmp(ciphertext)
    dst = _tmp()
    try:
        decrypt(src, dst, secret_path, passphrase)
        with open(dst, "rb") as f:
            return f.read()
    finally:
        os.remove(src)
        os.remove(dst)
