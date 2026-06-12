"""
At-rest encryption for the session store.

Threat model: an attacker who gains read access to data/sessions.db (lost laptop,
backup leak, supply-chain compromise) should NOT be able to read engagement
findings or tool outputs. Many findings contain sensitive client data — PoCs
with real cookies, dumped credentials, internal hostnames.

Choice of primitive: AES-256-GCM.
  - Symmetric → safe against Harvest-Now-Decrypt-Later (Grover halves key
    strength but 256-bit AES keeps 128-bit post-quantum security).
  - GCM gives authenticated encryption (any tamper detected on read).

Key management:
  - Key is derived from ARGUS_SESSION_KEY (passphrase) via PBKDF2-HMAC-SHA256.
  - Salt is a per-install random value stored at data/.salt (chmod 600).
  - 600,000 iterations (matches OWASP 2023 minimum for SHA-256).

Degradation: if ARGUS_SESSION_KEY is unset, seal/unseal pass through unchanged.
This keeps backward compatibility with existing sessions and developer setups,
but logs a warning so operators don't unknowingly run in cleartext mode.

Format: encrypted blobs are wrapped as "v1$<nonce_b64>$<ciphertext_b64>"
so reads can detect cleartext rows (from before encryption was enabled) and
return them untouched.
"""
from __future__ import annotations

import base64
import os
import secrets
import threading
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PREFIX = "v1$"
KDF_ITERATIONS = 600_000
KEY_LEN = 32  # AES-256

_lock = threading.Lock()
_cached_key: Optional[bytes] = None
_warned_cleartext = False


def _salt_path() -> Path:
    """data/.salt — created on first use, chmod 600."""
    from config import DATA_DIR
    return DATA_DIR / ".salt"


def _load_or_create_salt() -> bytes:
    p = _salt_path()
    if p.exists():
        return p.read_bytes()
    p.parent.mkdir(parents=True, exist_ok=True)
    salt = secrets.token_bytes(16)
    p.write_bytes(salt)
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
    return salt


def _derive_key(passphrase: str) -> bytes:
    salt = _load_or_create_salt()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def _get_key() -> Optional[bytes]:
    """Return the AES key, or None if encryption is disabled."""
    global _cached_key, _warned_cleartext
    if _cached_key is not None:
        return _cached_key
    with _lock:
        if _cached_key is not None:
            return _cached_key
        passphrase = os.getenv("ARGUS_SESSION_KEY", "").strip()
        if not passphrase:
            if not _warned_cleartext:
                _warned_cleartext = True
                try:
                    from shared.logger import audit
                    audit.error(
                        "at_rest",
                        "ARGUS_SESSION_KEY not set — session store is CLEARTEXT. "
                        "Set ARGUS_SESSION_KEY in .env to enable AES-256-GCM at-rest encryption."
                    )
                except Exception:
                    pass
            return None
        _cached_key = _derive_key(passphrase)
        return _cached_key


def seal(plaintext: str) -> str:
    """
    Encrypt plaintext with AES-256-GCM. Returns a string safe to store in TEXT
    SQLite columns. If no key is configured, returns plaintext unchanged.
    """
    key = _get_key()
    if key is None:
        return plaintext
    aes = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ct = aes.encrypt(nonce, plaintext.encode("utf-8"), associated_data=None)
    return PREFIX + base64.b64encode(nonce).decode() + "$" + base64.b64encode(ct).decode()


def unseal(blob: str) -> str:
    """
    Decrypt a blob produced by seal(). Cleartext (legacy) rows pass through.
    Raises ValueError if a sealed blob is detected but no key is configured,
    or if authentication fails (tampering / wrong key).
    """
    if not isinstance(blob, str) or not blob.startswith(PREFIX):
        return blob  # Legacy cleartext row — pass through
    key = _get_key()
    if key is None:
        raise ValueError(
            "Encrypted session row found but ARGUS_SESSION_KEY is not set. "
            "Set the passphrase used to encrypt this session to read it."
        )
    try:
        _, nonce_b64, ct_b64 = blob.split("$", 2)
        nonce = base64.b64decode(nonce_b64)
        ct = base64.b64decode(ct_b64)
        aes = AESGCM(key)
        pt = aes.decrypt(nonce, ct, associated_data=None)
        return pt.decode("utf-8")
    except Exception as e:
        raise ValueError(f"Failed to unseal session row (wrong key or tampered data): {e}") from e


def is_enabled() -> bool:
    return _get_key() is not None
