"""
auth.py – Registration/Login crypto helpers.
LEGACY – demo finding: MD5 password hashing (quantum-vulnerable / collision-weak)
LEGACY – demo finding: RSA-2048 PKCS1v15 JWT signing (quantum-vulnerable)
"""
import base64
import json
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend

# ── RSA-2048 key pair generated once at import time ──────────────────────────
_rsa_private_key = rsa.generate_private_key(          # LEGACY – demo finding
    public_exponent=65537,
    key_size=2048,                                      # LEGACY – demo finding
    backend=default_backend(),
)
_rsa_public_key = _rsa_private_key.public_key()


def hash_password_md5(password: str) -> str:
    """MD5 password hash – LEGACY – demo finding."""
    from cryptography.hazmat.primitives.hashes import Hash, MD5   # LEGACY – demo finding
    digest = Hash(MD5(), backend=default_backend())                # LEGACY – demo finding
    digest.update(password.encode())
    return digest.finalize().hex()


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def sign_jwt_rs256(payload: dict) -> str:
    """Build and sign a JWT manually with RSA-2048 PKCS1v15+SHA-256 – LEGACY – demo finding."""
    header = {"alg": "RS256", "typ": "JWT"}
    header_enc = _b64url(json.dumps(header, separators=(",", ":")).encode())
    payload_enc = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_enc}.{payload_enc}".encode()

    signature = _rsa_private_key.sign(                 # LEGACY – demo finding
        signing_input,
        padding.PKCS1v15(),                            # LEGACY – demo finding
        hashes.SHA256(),
    )
    return f"{header_enc}.{payload_enc}.{_b64url(signature)}"


def verify_jwt_rs256(token: str) -> dict:
    """Verify RS256 JWT; raises ValueError if invalid/expired."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Malformed token")
    header_enc, payload_enc, sig_enc = parts
    signing_input = f"{header_enc}.{payload_enc}".encode()

    # Re-pad base64url
    def _decode(s):
        s += "=" * (-len(s) % 4)
        return base64.urlsafe_b64decode(s)

    signature = _decode(sig_enc)
    try:
        _rsa_public_key.verify(                        # LEGACY – demo finding
            signature,
            signing_input,
            padding.PKCS1v15(),                        # LEGACY – demo finding
            hashes.SHA256(),
        )
    except Exception:
        raise ValueError("Invalid signature")

    payload = json.loads(_decode(payload_enc))
    if payload.get("exp", 0) < time.time():
        raise ValueError("Token expired")
    return payload
