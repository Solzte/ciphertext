import base64
import os
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from ciphertext.crypto import (
    SALT_SIZE,
    MAGIC,
    CryptoError,
    decrypt,
    decrypt_bytes,
    decrypt_file,
    derive_key,
    encrypt,
    encrypt_bytes,
    encrypt_file,
)


def test_encrypt_decrypt_roundtrip():
    ciphertext = encrypt("Hello, world!", "secret-password")
    assert decrypt(ciphertext, "secret-password") == "Hello, world!"


def test_encrypt_bytes_roundtrip():
    payload = encrypt_bytes(b"binary-data", "secret-password")
    assert decrypt_bytes(payload, "secret-password") == b"binary-data"


def test_wrong_password_fails():
    ciphertext = encrypt("classified", "right-password")
    with pytest.raises(CryptoError):
        decrypt(ciphertext, "wrong-password")


def test_v1_payload_has_magic_header():
    payload = encrypt_bytes(b"test", "secret")
    assert payload.startswith(MAGIC)


def test_legacy_fernet_ciphertext_still_decrypts():
    salt = os.urandom(SALT_SIZE)
    key = base64.urlsafe_b64encode(derive_key("legacy-pass", salt))
    encrypted = Fernet(key).encrypt(b"legacy message")
    legacy_payload = salt + encrypted
    encoded = base64.urlsafe_b64encode(legacy_payload).decode("utf-8")
    assert decrypt(encoded, "legacy-pass") == "legacy message"


def test_file_encryption_roundtrip(tmp_path: Path):
    source = tmp_path / "note.txt"
    source.write_text("file contents", encoding="utf-8")

    encrypted_path = encrypt_file(source, "file-password")
    assert encrypted_path.exists()
    assert encrypted_path.suffix == ".enc"

    decrypted_path = decrypt_file(encrypted_path, "file-password")
    assert decrypted_path.read_text(encoding="utf-8") == "file contents"


def test_empty_password_rejected():
    with pytest.raises(CryptoError):
        encrypt("hello", "")
