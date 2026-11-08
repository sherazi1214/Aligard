"""Crypto helpers: Argon2id hashing, random tokens, SHA-256, Fernet encryption."""
import base64
import hashlib
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from backend.app.config import get_settings

_ph = PasswordHasher()  # default Argon2id


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    try:
        return _ph.verify(stored_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    return _ph.check_needs_rehash(stored_hash)


# Maujood na hone wale user par bhi itna hi kaam karte hain (timing se enumeration na ho).
# Har start par random, kahin hardcode nahi.
DUMMY_HASH = _ph.hash(secrets.token_urlsafe(24))


def new_token() -> str:
    return secrets.token_urlsafe(32)  # 32 random bytes


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _fernet() -> Fernet | MultiFernet:
    s = get_settings()
    if s.encryption_key:
        # Rotation: naya ENCRYPTION_KEY encrypt karta hai; ENCRYPTION_KEYS_OLD ki purani keys sirf decrypt ke liye
        keys = [Fernet(s.encryption_key.encode())] + [Fernet(k.encode()) for k in s.old_encryption_key_list]
        return keys[0] if len(keys) == 1 else MultiFernet(keys)
    if s.is_production:
        raise RuntimeError("ENCRYPTION_KEY set nahi")
    # Sirf dev/test: SECRET_KEY se key derive
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(s.secret_key.encode()).digest()))


def encrypt_secret(plain: str) -> str:
    return _fernet().encrypt(plain.encode()).decode()


def decrypt_secret(token: str) -> str | None:
    try:
        return _fernet().decrypt(token.encode()).decode()
    except InvalidToken:
        return None
