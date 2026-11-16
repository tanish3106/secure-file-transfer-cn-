"""All cryptography lives here: AES-256-GCM, key derivation, hashing, HMAC, password hashing."""
import hashlib
import hmac
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import config

NONCE_SIZE = 12   # bytes, recommended size for GCM
TAG_SIZE = 16     # bytes, appended to the ciphertext by GCM


def derive_key(passphrase: str) -> bytes:
    """Turn a passphrase into a 32-byte (256-bit) AES key using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=config.KDF_SALT, iterations=config.KDF_ITERATIONS)
    return kdf.derive(passphrase.encode())


def encrypt(key: bytes, data: bytes, aad: bytes = b"") -> bytes:
    """AES-256-GCM encrypt. Output = nonce (12) + ciphertext + tag (16).
    `aad` (associated data) is authenticated but not encrypted; we use it for the chunk number
    so chunks cannot be reordered or swapped without detection."""
    nonce = os.urandom(NONCE_SIZE)
    return nonce + AESGCM(key).encrypt(nonce, data, aad)


def decrypt(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    """AES-256-GCM decrypt. Raises cryptography.exceptions.InvalidTag if the key is wrong
    or the data / aad was modified."""
    return AESGCM(key).decrypt(blob[:NONCE_SIZE], blob[NONCE_SIZE:], aad)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(config.CHUNK_SIZE), b""):
            h.update(block)
    return h.hexdigest()


def auth_response(key: bytes, nonce: bytes) -> bytes:
    """HMAC-SHA256(key, nonce): proves we know the key without sending it."""
    return hmac.new(key, nonce, hashlib.sha256).digest()


def hash_password(password: str, salt: bytes = None):
    """Salted PBKDF2 hash for storing user passwords. Returns (salt_hex, hash_hex)."""
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return salt.hex(), digest.hex()


def verify_password(password: str, salt_hex: str, hash_hex: str) -> bool:
    _, digest = hash_password(password, bytes.fromhex(salt_hex))
    return hmac.compare_digest(digest, hash_hex)
