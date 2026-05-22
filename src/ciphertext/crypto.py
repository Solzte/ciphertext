"""Core encryption routines with versioned binary format and legacy Fernet support."""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"CPT1"
VERSION = 1
SALT_SIZE = 16
NONCE_SIZE = 12
PBKDF2_ITERATIONS = 100_000
DEFAULT_ENC_SUFFIX = ".enc"


class CryptoError(Exception):
    """Raised when encryption or decryption fails."""


def derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=32,
    )


def _pack_v1(salt: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    return MAGIC + bytes([VERSION]) + salt + nonce + ciphertext


def _unpack_v1(payload: bytes) -> tuple[bytes, bytes, bytes]:
    header_size = len(MAGIC) + 1 + SALT_SIZE + NONCE_SIZE
    if len(payload) < header_size:
        raise CryptoError("Payload is too short.")

    if not payload.startswith(MAGIC):
        raise CryptoError("Unknown ciphertext format.")

    version = payload[len(MAGIC)]
    if version != VERSION:
        raise CryptoError(f"Unsupported format version: {version}.")

    offset = len(MAGIC) + 1
    salt = payload[offset : offset + SALT_SIZE]
    offset += SALT_SIZE
    nonce = payload[offset : offset + NONCE_SIZE]
    ciphertext = payload[offset + NONCE_SIZE :]
    if not ciphertext:
        raise CryptoError("Missing encrypted payload.")

    return salt, nonce, ciphertext


def encrypt_bytes(data: bytes, password: str) -> bytes:
    if not password:
        raise CryptoError("Password cannot be empty.")

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)
    encrypted = AESGCM(key).encrypt(nonce, data, None)
    return _pack_v1(salt, nonce, encrypted)


def decrypt_bytes(payload: bytes, password: str) -> bytes:
    if not password:
        raise CryptoError("Password cannot be empty.")

    if payload.startswith(MAGIC):
        salt, nonce, ciphertext = _unpack_v1(payload)
        key = derive_key(password, salt)
        try:
            return AESGCM(key).decrypt(nonce, ciphertext, None)
        except InvalidTag as exc:
            raise CryptoError("Wrong password or corrupted ciphertext.") from exc

    return _decrypt_legacy_fernet(payload, password)


def _decrypt_legacy_fernet(payload: bytes, password: str) -> bytes:
    if len(payload) < SALT_SIZE:
        raise CryptoError("Invalid legacy ciphertext.")

    salt, encrypted = payload[:SALT_SIZE], payload[SALT_SIZE:]
    fernet_key = base64.urlsafe_b64encode(derive_key(password, salt))
    try:
        return Fernet(fernet_key).decrypt(encrypted)
    except InvalidToken as exc:
        raise CryptoError("Wrong password or invalid ciphertext.") from exc


def encrypt(plaintext: str, password: str) -> str:
    payload = encrypt_bytes(plaintext.encode("utf-8"), password)
    return base64.urlsafe_b64encode(payload).decode("utf-8")


def decrypt(ciphertext: str, password: str) -> str:
    try:
        payload = base64.urlsafe_b64decode(ciphertext.encode("utf-8"))
    except Exception as exc:
        raise CryptoError("Invalid base64 ciphertext.") from exc

    return decrypt_bytes(payload, password).decode("utf-8")


def encrypt_file(
    input_path: str | Path,
    password: str,
    output_path: str | Path | None = None,
) -> Path:
    source = Path(input_path)
    if not source.is_file():
        raise CryptoError(f"Input file not found: {source}")

    destination = Path(output_path) if output_path else source.with_suffix(source.suffix + DEFAULT_ENC_SUFFIX)
    encrypted = encrypt_bytes(source.read_bytes(), password)
    destination.write_bytes(encrypted)
    return destination


def decrypt_file(
    input_path: str | Path,
    password: str,
    output_path: str | Path | None = None,
) -> Path:
    source = Path(input_path)
    if not source.is_file():
        raise CryptoError(f"Input file not found: {source}")

    if output_path:
        destination = Path(output_path)
    elif source.suffix == DEFAULT_ENC_SUFFIX:
        destination = source.with_suffix("")
    else:
        destination = source.with_name(source.name + ".decrypted")

    decrypted = decrypt_bytes(source.read_bytes(), password)
    destination.write_bytes(decrypted)
    return destination
