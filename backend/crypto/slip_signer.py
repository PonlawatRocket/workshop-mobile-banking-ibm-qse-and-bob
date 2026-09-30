"""
slip_signer.py – e-Slip signing with ECDSA SECP256R1 / SHA-256.
"""
import base64
import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

# ── ECDSA key pair on SECP256R1 ───────────────────────────────────────────────
_ec_private_key = ec.generate_private_key(
    ec.SECP256R1(),                                    # curve selection – literal class
    backend=default_backend(),
)
_ec_public_key = _ec_private_key.public_key()


def sign_slip_ecdsa(slip_dict: dict) -> str:
    """Sign a slip dict with ECDSA SECP256R1+SHA-256; return base64url signature."""
    message = json.dumps(slip_dict, sort_keys=True, separators=(",", ":")).encode()
    signature = _ec_private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256()),                     # ECDSA with SHA-256 – literal
    )
    return base64.urlsafe_b64encode(signature).decode()


def verify_slip_ecdsa(slip_dict: dict, signature_b64: str) -> bool:
    """Verify ECDSA signature; returns True if valid, False if tampered."""
    message = json.dumps(slip_dict, sort_keys=True, separators=(",", ":")).encode()
    sig_bytes = base64.urlsafe_b64decode(signature_b64 + "==")
    try:
        _ec_public_key.verify(
            sig_bytes,
            message,
            ec.ECDSA(hashes.SHA256()),
        )
        return True
    except Exception:
        return False
