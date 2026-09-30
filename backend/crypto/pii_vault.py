"""
pii_vault.py – PII encryption with AES-128 ECB mode.
LEGACY – demo finding: ECB mode leaks block patterns (quantum-vulnerable symmetric key)
"""
import base64
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend

# AES-128 → 16-byte key                               # LEGACY – demo finding
_AES128_KEY = os.urandom(16)


def encrypt_pii_ecb(plaintext: str) -> str:
    """AES-128-ECB encrypt PII string; return base64. LEGACY – demo finding."""
    padder = sym_padding.PKCS7(128).padder()           # LEGACY – demo finding
    padded = padder.update(plaintext.encode()) + padder.finalize()

    cipher = Cipher(
        algorithms.AES(_AES128_KEY),                   # LEGACY – demo finding
        modes.ECB(),                                   # LEGACY – demo finding
        backend=default_backend(),
    )
    enc = cipher.encryptor()
    ciphertext = enc.update(padded) + enc.finalize()
    return base64.b64encode(ciphertext).decode()


def decrypt_pii_ecb(ciphertext_b64: str) -> str:
    """AES-128-ECB decrypt PII string. LEGACY – demo finding."""
    ciphertext = base64.b64decode(ciphertext_b64)

    cipher = Cipher(
        algorithms.AES(_AES128_KEY),                   # LEGACY – demo finding
        modes.ECB(),                                   # LEGACY – demo finding
        backend=default_backend(),
    )
    dec = cipher.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    return (unpadder.update(padded) + unpadder.finalize()).decode()
