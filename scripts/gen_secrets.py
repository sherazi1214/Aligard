"""Naye production secrets banata hai. Output kahin commit/paste-log mat karein; seedha platform env vars mein dalein.
    python -m scripts.gen_secrets
"""
import secrets

from cryptography.fernet import Fernet

print("SECRET_KEY=" + secrets.token_urlsafe(48))
print("ENCRYPTION_KEY=" + Fernet.generate_key().decode())
print("POSTGRES_PASSWORD=" + secrets.token_urlsafe(24))
print("REDIS_PASSWORD=" + secrets.token_urlsafe(24))
