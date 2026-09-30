# ThaiPay Lite – IBM QSE Demo Application

A minimal mobile-banking web app intentionally using **quantum-vulnerable and weak cryptography** so that IBM Quantum Safe Explorer (QSE) can scan the source and generate a rich Cryptography Bill of Materials (CBOM).

---

## Quick Start

```bash
cd thaipay-lite
pip install -r requirements.txt
uvicorn backend.app:app --reload
```

Open **http://127.0.0.1:8000** in your browser.

---

## Demo Script Steps

| Step | Action | What to show |
|------|--------|-------------|
| 1 | Open http://127.0.0.1:8000 | Mobile banking login screen |
| 2 | Login as **somchai / demo1234** | RS256 JWT issued (RSA-2048 PKCS1v15) |
| 3 | Home tab → balance card | Balance ฿125,000.00 displayed |
| 4 | Click **Partner Key Exchange** | ECDH SECP256R1 + HKDF-SHA256 + RSA-OAEP result shown |
| 5 | Transfer tab → recipient **nattaya**, amount **5000** → โอนเงิน | 3DES CBC legacy call + SHA-1 checksum executed; e-Slip created |
| 6 | Slip tab auto-navigates | QR code rendered with ECDSA-signed slip |
| 7 | Verify tab → slip + sig pre-filled → ตรวจสอบ | **VALID ✔** badge |
| 8 | Click **Tamper Amount** → ตรวจสอบ again | **TAMPERED ✘** badge |
| 9 | Profile tab → โหลดข้อมูล | Masked national ID + phone (AES-128 ECB decrypted) |
| 10 | Admin tab → โหลด Audit Log | Decrypted entries, HMAC-SHA256 ✔ per row |
| 11 | Register tab → create new user | MD5 password hash + AES-128 ECB PII stored |

---

## Crypto Function Map (CBOM reference)

| File | Function | Algorithm | Key/Curve | Feature |
|------|----------|-----------|-----------|---------|
| `backend/crypto/auth.py` | `hash_password_md5()` | MD5 | – | Register / Login |
| `backend/crypto/auth.py` | `sign_jwt_rs256()` | RSA-2048 PKCS1v15 + SHA-256 | 2048-bit | Session JWT sign |
| `backend/crypto/auth.py` | `verify_jwt_rs256()` | RSA-2048 PKCS1v15 + SHA-256 | 2048-bit | Session JWT verify |
| `backend/crypto/slip_signer.py` | `sign_slip_ecdsa()` | ECDSA + SHA-256 | SECP256R1 | e-Slip signing |
| `backend/crypto/slip_signer.py` | `verify_slip_ecdsa()` | ECDSA + SHA-256 | SECP256R1 | Slip verification |
| `backend/crypto/pii_vault.py` | `encrypt_pii_ecb()` | AES-128 ECB + PKCS7 | 128-bit | Store national ID, phone |
| `backend/crypto/pii_vault.py` | `decrypt_pii_ecb()` | AES-128 ECB + PKCS7 | 128-bit | Read national ID, phone |
| `backend/crypto/partner_api.py` | `derive_shared_key_ecdh()` | ECDH SECP256R1 + HKDF-SHA256 | SECP256R1 | Partner key exchange |
| `backend/crypto/partner_api.py` | `wrap_key_rsa_oaep()` | RSA-2048 OAEP (SHA-256) | 2048-bit | Wrap session key |
| `backend/crypto/legacy_core.py` | `encrypt_core_3des()` | TripleDES CBC + PKCS7 | 192-bit | Legacy core-banking call |
| `backend/crypto/legacy_core.py` | `checksum_sha1()` | SHA-1 | – | Legacy message checksum |
| `backend/crypto/audit.py` | `sign_audit_hmac()` | HMAC-SHA256 | 256-bit | Audit log integrity |
| `backend/crypto/audit.py` | `encrypt_audit_gcm()` | AES-256-GCM | 256-bit | Encrypt audit entries |

---

## TripleDES Import Note

`cryptography==42.x` ships TripleDES as `cryptography.hazmat.primitives.ciphers.algorithms.TripleDES`.
For older versions (< 3.x) the class was `cryptography.hazmat.primitives.ciphers.algorithms.TripleDES` as well, but it was deprecated and re-exported. The pinned version `42.0.8` in `requirements.txt` uses the current import location already present in `legacy_core.py`.

---

## Project Structure

```
thaipay-lite/
├── frontend/
│   └── index.html          # SPA – plain HTML/CSS/vanilla JS
├── backend/
│   ├── app.py              # FastAPI routes (no crypto logic here)
│   └── crypto/
│       ├── __init__.py
│       ├── auth.py         # MD5 + RSA-2048 JWT
│       ├── slip_signer.py  # ECDSA SECP256R1
│       ├── pii_vault.py    # AES-128 ECB
│       ├── partner_api.py  # ECDH + RSA-OAEP
│       ├── legacy_core.py  # TripleDES CBC + SHA-1
│       └── audit.py        # HMAC-SHA256 + AES-256-GCM
├── requirements.txt
└── README.md
```

---

## Notes for QSE Scanning

- All algorithm instantiations use **literal class names and literal key sizes** (no config-driven selection).
- Every crypto function is exercised by at least one API route.
- No `pyjwt` or other JWT library — JWT is built manually so RSA signing is visible to the scanner.
- Comments marked `# LEGACY – demo finding` flag intentional weak-crypto sites.
