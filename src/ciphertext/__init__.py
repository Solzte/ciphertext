"""Password-based encryption toolkit."""

from ciphertext.crypto import (
    CryptoError,
    decrypt,
    decrypt_bytes,
    decrypt_file,
    encrypt,
    encrypt_bytes,
    encrypt_file,
)

__all__ = [
    "CryptoError",
    "decrypt",
    "decrypt_bytes",
    "decrypt_file",
    "encrypt",
    "encrypt_bytes",
    "encrypt_file",
]
__version__ = "2.0.0"
