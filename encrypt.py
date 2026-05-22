"""
Simple text encryption program.
Encrypts plaintext into ciphertext using a password you choose.
"""

import base64
import hashlib
import os
import sys

from cryptography.fernet import Fernet, InvalidToken


def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """Derives a secure key from the password."""
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        100_000,
        dklen=32,
    )
    return base64.urlsafe_b64encode(key)


def encrypt(plaintext: str, password: str) -> str:
    """Encrypts text and returns salt + ciphertext combined."""
    salt = os.urandom(16)
    key = derive_key_from_password(password, salt)
    f = Fernet(key)
    encrypted = f.encrypt(plaintext.encode("utf-8"))
    return base64.urlsafe_b64encode(salt + encrypted).decode("utf-8")


def decrypt(ciphertext: str, password: str) -> str:
    """Decrypts ciphertext back to plaintext."""
    raw = base64.urlsafe_b64decode(ciphertext.encode("utf-8"))
    salt, encrypted = raw[:16], raw[16:]
    key = derive_key_from_password(password, salt)
    f = Fernet(key)
    return f.decrypt(encrypted).decode("utf-8")


def main() -> None:
    print("=" * 40)
    print("  Text Encryption Program")
    print("=" * 40)
    print()
    print("1) Encrypt (plaintext -> ciphertext)")
    print("2) Decrypt (ciphertext -> plaintext)")
    print()

    choice = input("Your choice (1 or 2): ").strip()

    if choice not in ("1", "2"):
        print("Invalid choice.")
        sys.exit(1)

    password = input("Enter your password: ")
    if not password:
        print("Password cannot be empty.")
        sys.exit(1)

    if choice == "1":
        text = input("Text to encrypt: ")
        if not text:
            print("Text cannot be empty.")
            sys.exit(1)
        result = encrypt(text, password)
        print()
        print("Ciphertext:")
        print(result)
    else:
        ciphertext = input("Ciphertext to decrypt: ").strip()
        if not ciphertext:
            print("Ciphertext cannot be empty.")
            sys.exit(1)
        try:
            result = decrypt(ciphertext, password)
        except (InvalidToken, ValueError):
            print("Error: Wrong password or invalid ciphertext.")
            sys.exit(1)
        print()
        print("Plaintext:")
        print(result)


if __name__ == "__main__":
    main()
