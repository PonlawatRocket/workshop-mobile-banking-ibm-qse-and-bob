"""
legacy_core.py – Simulated legacy core-banking crypto.
LEGACY – demo finding: TripleDES CBC (quantum-vulnerable, small block size)
LEGACY – demo finding: SHA-1 checksum (collision-weak)
"""
import base64
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend

# TripleDES 24-byte (3×DES) key                       # LEGACY – demo finding
_3DES_KEY = os.urandom(24)


def encrypt_core_3des(plaintext: str) -> str:
    """
    TripleDES-CBC encrypt a core-banking message.
    LEGACY – demo finding: TripleDES CBC, 64-bit block size.
    """
    iv = os.urandom(8)                                 # 3DES block = 8 bytes

    padder = sym_padding.PKCS7(64).padder()            # LEGACY – demo finding
    padded = padder.update(plaintext.encode()) + padder.finalize()

    cipher = Cipher(
        algorithms.TripleDES(_3DES_KEY),               # LEGACY – demo finding
        modes.CBC(iv),
        backend=default_backend(),
    )
    enc = cipher.encryptor()
    ciphertext = enc.update(padded) + enc.finalize()
    return base64.b64encode(iv + ciphertext).decode()


def checksum_sha1(message: str) -> str:
    """SHA-1 message checksum – LEGACY – demo finding."""
    from cryptography.hazmat.primitives.hashes import Hash, SHA1   # LEGACY – demo finding
    digest = Hash(SHA1(), backend=default_backend())               # LEGACY – demo finding
    digest.update(message.encode())
    return digest.finalize().hex()
