"""
audit.py – Audit log integrity and encryption.
  • HMAC-SHA256 → log entry integrity
  • AES-256-GCM → encrypt audit entries
"""
import base64
import json
import os

from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# Keys generated once at startup
_HMAC_KEY = os.urandom(32)
_AES_GCM_KEY = os.urandom(32)                         # AES-256 → 32 bytes


def sign_audit_hmac(entry: dict) -> str:
    """HMAC-SHA256 over serialised audit entry; return hex digest."""
    message = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()
    h = crypto_hmac.HMAC(_HMAC_KEY, hashes.SHA256(), backend=default_backend())
    h.update(message)
    return h.finalize().hex()


def encrypt_audit_gcm(entry: dict) -> str:
    """AES-256-GCM encrypt audit entry JSON; return base64(nonce+ciphertext+tag)."""
    plaintext = json.dumps(entry, separators=(",", ":")).encode()
    nonce = os.urandom(12)                             # 96-bit nonce for GCM
    aesgcm = AESGCM(_AES_GCM_KEY)                     # AES-256-GCM
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return base64.b64encode(nonce + ciphertext).decode()


def decrypt_audit_gcm(blob_b64: str) -> dict:
    """Decrypt AES-256-GCM audit entry; return dict."""
    raw = base64.b64decode(blob_b64)
    nonce, ciphertext = raw[:12], raw[12:]
    aesgcm = AESGCM(_AES_GCM_KEY)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return json.loads(plaintext)
