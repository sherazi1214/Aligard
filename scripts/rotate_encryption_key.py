"""Usage (key rotation ke baad, docs/KEY_ROTATION.md dekhein):
    python -m scripts.rotate_encryption_key --dry-run
    python -m scripts.rotate_encryption_key
"""
import argparse
import json

from backend.app.db import SessionLocal
from backend.app.rotation import reencrypt_all


def main() -> None:
    parser = argparse.ArgumentParser(description="Re-encrypt TOTP/Gmail secrets with the current ENCRYPTION_KEY")
    parser.add_argument("--dry-run", action="store_true", help="Sirf ginti dikhao, kuch likho mat")
    args = parser.parse_args()
    with SessionLocal() as db:
        print(json.dumps(reencrypt_all(db, dry_run=args.dry_run)))


if __name__ == "__main__":
    main()
