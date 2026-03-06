"""Encryption for local cache using password-derived keys."""

import base64
import hashlib
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

_CONFIG_DIR = Path.home() / ".snippets_cli"
_SALT_FILE = _CONFIG_DIR / "crypto.salt"
_VERIFY_FILE = _CONFIG_DIR / "crypto.verify"

_fernet: Fernet | None = None


def _get_or_create_salt() -> bytes:
    if _SALT_FILE.exists():
        return _SALT_FILE.read_bytes()
    salt = os.urandom(16)
    _SALT_FILE.parent.mkdir(exist_ok=True)
    _SALT_FILE.write_bytes(salt)
    return salt


def derive_key(password: str) -> bool:
    """Derive encryption key from password.

    Returns True if the password is correct (or first-time setup).
    Returns False if the password doesn't match the stored verification.
    """
    global _fernet
    salt = _get_or_create_salt()
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations=600_000)
    key = base64.urlsafe_b64encode(dk)
    candidate = Fernet(key)

    if _VERIFY_FILE.exists():
        try:
            candidate.decrypt(_VERIFY_FILE.read_bytes())
        except InvalidToken:
            return False
        _fernet = candidate
        return True

    # First-time setup
    _fernet = candidate
    _VERIFY_FILE.parent.mkdir(exist_ok=True)
    _VERIFY_FILE.write_bytes(candidate.encrypt(b"snippets-cli"))
    return True


def has_encryption() -> bool:
    """Whether encryption has been set up previously."""
    return _SALT_FILE.exists() and _VERIFY_FILE.exists()


def is_ready() -> bool:
    """Whether the encryption key is available in memory."""
    return _fernet is not None


def encrypt(data: str) -> bytes:
    if _fernet is None:
        raise RuntimeError("Encryption key not derived")
    return _fernet.encrypt(data.encode("utf-8"))


def decrypt(data: bytes) -> str:
    if _fernet is None:
        raise RuntimeError("Encryption key not derived")
    return _fernet.decrypt(data).decode("utf-8")


def clear():
    """Clear the in-memory key (on logout)."""
    global _fernet
    _fernet = None


def rekey(new_password: str):
    """Re-encrypt all local files with a new password-derived key."""
    global _fernet
    if _fernet is None:
        raise RuntimeError("No active encryption key")

    old_fernet = _fernet

    salt = _get_or_create_salt()
    dk = hashlib.pbkdf2_hmac("sha256", new_password.encode("utf-8"), salt, iterations=600_000)
    new_fernet = Fernet(base64.urlsafe_b64encode(dk))

    for fpath in _CONFIG_DIR.glob("*.enc"):
        try:
            plaintext = old_fernet.decrypt(fpath.read_bytes())
            fpath.write_bytes(new_fernet.encrypt(plaintext))
        except InvalidToken:
            continue

    _fernet = new_fernet
    _VERIFY_FILE.write_bytes(new_fernet.encrypt(b"snippets-cli"))
