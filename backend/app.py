"""
app.py – ThaiPay Lite FastAPI application.
All crypto is delegated to the crypto/ package.
"""
import time
import uuid
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

from backend.crypto.auth import hash_password_md5, sign_jwt_rs256, verify_jwt_rs256
from backend.crypto.slip_signer import sign_slip_ecdsa, verify_slip_ecdsa
from backend.crypto.pii_vault import encrypt_pii_ecb, decrypt_pii_ecb
from backend.crypto.partner_api import derive_shared_key_ecdh, wrap_key_rsa_oaep
from backend.crypto.legacy_core import encrypt_core_3des, checksum_sha1
from backend.crypto.audit import sign_audit_hmac, encrypt_audit_gcm, decrypt_audit_gcm

# ── In-memory stores ──────────────────────────────────────────────────────────
USERS: dict[str, dict] = {}          # username → {pw_hash, balance, pii_...}
AUDIT_LOG: list[str] = []            # list of encrypted audit blobs

# ── Seed two demo users ───────────────────────────────────────────────────────
def _seed_user(username, password, display_name, nat_id, phone, balance):
    USERS[username] = {
        "pw_hash": hash_password_md5(password),
        "display_name": display_name,
        "nat_id_enc": encrypt_pii_ecb(nat_id),
        "phone_enc": encrypt_pii_ecb(phone),
        "balance": balance,
    }

_seed_user("somchai", "demo1234", "สมชาย ใจดี",    "1234567890123", "0812345678", 125_000.00)
_seed_user("nattaya", "demo5678", "ณัฐยา วงษ์ใหญ่", "9876543210987", "0898765432",  58_500.50)

# ── FastAPI app ───────────────────────────────────────────────────────────────
app = FastAPI(title="ThaiPay Lite")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

FRONTEND_DIR = Path(__file__).parent.parent / "frontend"

# ── Auth helpers ──────────────────────────────────────────────────────────────
TOKEN_TTL = 3600  # 1 hour

def _make_token(username: str) -> str:
    return sign_jwt_rs256({
        "sub": username,
        "exp": int(time.time()) + TOKEN_TTL,
        "iat": int(time.time()),
    })

def _require_auth(authorization: Optional[str]) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing or invalid Authorization header")
    token = authorization[len("Bearer "):]
    try:
        payload = verify_jwt_rs256(token)
    except ValueError as e:
        raise HTTPException(401, str(e))
    return payload["sub"]

def _append_audit(action: str, actor: str, detail: str):
    entry = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "action": action,
        "actor": actor,
        "detail": detail,
    }
    hmac_tag = sign_audit_hmac(entry)
    entry["hmac"] = hmac_tag
    blob = encrypt_audit_gcm(entry)
    AUDIT_LOG.append(blob)

# ── Pydantic models ───────────────────────────────────────────────────────────
class RegisterRequest(BaseModel):
    username: str
    password: str
    display_name: str = "Demo User"
    nat_id: str = "0000000000000"
    phone: str = "0800000000"

class LoginRequest(BaseModel):
    username: str
    password: str

class TransferRequest(BaseModel):
    to_user: str
    amount: float

class VerifySlipRequest(BaseModel):
    slip: dict
    signature: str

# ── Routes ────────────────────────────────────────────────────────────────────

@app.post("/api/register")
def register(req: RegisterRequest):
    if req.username in USERS:
        raise HTTPException(400, "Username already exists")
    USERS[req.username] = {
        "pw_hash": hash_password_md5(req.password),
        "display_name": req.display_name,
        "nat_id_enc": encrypt_pii_ecb(req.nat_id),
        "phone_enc": encrypt_pii_ecb(req.phone),
        "balance": 0.0,
    }
    _append_audit("REGISTER", req.username, "New account created")
    return {"message": "Registered successfully"}


@app.post("/api/login")
def login(req: LoginRequest):
    user = USERS.get(req.username)
    if not user or user["pw_hash"] != hash_password_md5(req.password):
        raise HTTPException(401, "Invalid credentials")
    token = _make_token(req.username)
    _append_audit("LOGIN", req.username, "Login successful")
    return {"token": token, "display_name": user["display_name"]}


@app.get("/api/balance")
def get_balance(authorization: Optional[str] = Header(None)):
    username = _require_auth(authorization)
    user = USERS[username]
    return {
        "username": username,
        "display_name": user["display_name"],
        "balance": user["balance"],
        "currency": "THB",
    }


@app.post("/api/transfer")
def transfer(req: TransferRequest, authorization: Optional[str] = Header(None)):
    from_user = _require_auth(authorization)
    if req.to_user not in USERS:
        raise HTTPException(404, "Recipient not found")
    if req.to_user == from_user:
        raise HTTPException(400, "Cannot transfer to yourself")
    if req.amount <= 0:
        raise HTTPException(400, "Amount must be positive")
    sender = USERS[from_user]
    if sender["balance"] < req.amount:
        raise HTTPException(400, "Insufficient balance")

    # Legacy core-banking call – 3DES + SHA-1
    core_msg = f"TXN|{from_user}|{req.to_user}|{req.amount:.2f}"
    encrypted_msg = encrypt_core_3des(core_msg)
    checksum     = checksum_sha1(core_msg)

    # Update balances
    sender["balance"] -= req.amount
    USERS[req.to_user]["balance"] += req.amount

    # Build slip
    slip = {
        "ref":       str(uuid.uuid4())[:8].upper(),
        "from_user": from_user,
        "from_name": sender["display_name"],
        "to_user":   req.to_user,
        "to_name":   USERS[req.to_user]["display_name"],
        "amount":    req.amount,
        "currency":  "THB",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    signature = sign_slip_ecdsa(slip)

    _append_audit(
        "TRANSFER", from_user,
        f"→ {req.to_user} amount={req.amount:.2f} ref={slip['ref']} core_sha1={checksum[:8]}",
    )

    return {
        "slip": slip,
        "signature": signature,
        "core_encrypted": encrypted_msg[:32] + "...",
        "core_checksum": checksum,
    }


@app.post("/api/slip/verify")
def verify_slip(req: VerifySlipRequest):
    valid = verify_slip_ecdsa(req.slip, req.signature)
    return {"valid": valid, "message": "Slip is authentic ✔" if valid else "Slip has been tampered ✘"}


@app.get("/api/profile")
def get_profile(authorization: Optional[str] = Header(None)):
    username = _require_auth(authorization)
    user = USERS[username]
    nat_id = decrypt_pii_ecb(user["nat_id_enc"])
    phone  = decrypt_pii_ecb(user["phone_enc"])
    # Mask: show only last 4 digits
    masked_nat_id = "*" * 9 + nat_id[-4:]
    masked_phone  = phone[:3] + "****" + phone[-3:]
    return {
        "username": username,
        "display_name": user["display_name"],
        "national_id_masked": masked_nat_id,
        "phone_masked": masked_phone,
    }


@app.post("/api/partner/handshake")
def partner_handshake(authorization: Optional[str] = Header(None)):
    username = _require_auth(authorization)
    shared_key   = derive_shared_key_ecdh()
    wrapped_key  = wrap_key_rsa_oaep(shared_key)
    _append_audit("PARTNER_HANDSHAKE", username, "ECDH + RSA-OAEP key exchange completed")
    return {
        "status": "success",
        "algorithm": "ECDH-SECP256R1 + HKDF-SHA256 → RSA-2048-OAEP",
        "shared_key_hex": shared_key.hex(),
        "wrapped_key_b64": wrapped_key[:40] + "...",
        "message": "Partner key exchange completed successfully",
    }


@app.get("/api/admin/audit")
def admin_audit(authorization: Optional[str] = Header(None)):
    _require_auth(authorization)          # any logged-in user can view demo audit
    entries = []
    for blob in AUDIT_LOG:
        entry = decrypt_audit_gcm(blob)
        hmac_stored = entry.pop("hmac", "")
        hmac_valid  = sign_audit_hmac(entry) == hmac_stored
        entry["hmac_valid"] = hmac_valid
        entries.append(entry)
    return {"entries": entries}


# ── Static files (frontend) ───────────────────────────────────────────────────
@app.get("/")
def root():
    return FileResponse(FRONTEND_DIR / "index.html")

app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="static")
