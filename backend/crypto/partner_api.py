"""
partner_api.py – Simulated partner-bank key exchange.
  • ECDH on SECP256R1 + HKDF-SHA256 → shared key
  • RSA-2048 OAEP (SHA-256) → wrap session key for partner
"""
import base64
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

# ── Partner's RSA-2048 key pair (simulated partner bank) ─────────────────────
_partner_rsa_private = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,                                     # LEGACY – demo finding
    backend=default_backend(),
)
_partner_rsa_public = _partner_rsa_private.public_key()


def derive_shared_key_ecdh() -> bytes:
    """
    Simulate ECDH handshake on SECP256R1 + HKDF-SHA256 key derivation.
    Returns 32-byte shared key.
    """
    our_private = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
    partner_private = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
    partner_public = partner_private.public_key()

    shared_secret = our_private.exchange(ec.ECDH(), partner_public)  # ECDH on SECP256R1

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"thaipay-partner-v1",
        backend=default_backend(),
    ).derive(shared_secret)
    return derived_key


def wrap_key_rsa_oaep(session_key: bytes) -> str:
    """
    Wrap a session key with partner's RSA-2048 OAEP (SHA-256).
    Returns base64-encoded wrapped key.
    """
    wrapped = _partner_rsa_public.encrypt(
        session_key,
        padding.OAEP(                                  # RSA-OAEP
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return base64.b64encode(wrapped).decode()
