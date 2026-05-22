"""Command-line interface for the ciphertext toolkit."""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from ciphertext import __version__
from ciphertext.crypto import CryptoError, decrypt, decrypt_file, encrypt, encrypt_file


def _read_password(provided: str | None) -> str:
    password = provided if provided is not None else getpass.getpass("Enter password: ")
    if not password:
        raise CryptoError("Password cannot be empty.")
    return password


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ciphertext",
        description="Encrypt and decrypt text or files with a password.",
    )
    parser.add_argument("--version", action="version", version=f"ciphertext {__version__}")

    subparsers = parser.add_subparsers(dest="command", required=False)

    encrypt_text = subparsers.add_parser("encrypt", help="Encrypt plaintext to base64 ciphertext")
    encrypt_text.add_argument("text", help="Plaintext to encrypt")
    encrypt_text.add_argument("-p", "--password", help="Password (hidden prompt if omitted)")

    decrypt_text = subparsers.add_parser("decrypt", help="Decrypt base64 ciphertext to plaintext")
    decrypt_text.add_argument("ciphertext", help="Base64 ciphertext")
    decrypt_text.add_argument("-p", "--password", help="Password (hidden prompt if omitted)")

    encrypt_file_cmd = subparsers.add_parser("encrypt-file", help="Encrypt a file")
    encrypt_file_cmd.add_argument("input", type=Path, help="Input file path")
    encrypt_file_cmd.add_argument("-o", "--output", type=Path, help="Output .enc file path")
    encrypt_file_cmd.add_argument("-p", "--password", help="Password (hidden prompt if omitted)")

    decrypt_file_cmd = subparsers.add_parser("decrypt-file", help="Decrypt a .enc file")
    decrypt_file_cmd.add_argument("input", type=Path, help="Encrypted input file path")
    decrypt_file_cmd.add_argument("-o", "--output", type=Path, help="Output file path")
    decrypt_file_cmd.add_argument("-p", "--password", help="Password (hidden prompt if omitted)")

    subparsers.add_parser("interactive", help="Run the classic interactive menu")

    return parser


def _run_interactive() -> int:
    print("=" * 40)
    print("  Text Encryption Program")
    print("=" * 40)
    print()
    print("1) Encrypt (plaintext -> ciphertext)")
    print("2) Decrypt (ciphertext -> plaintext)")
    print("3) Encrypt file")
    print("4) Decrypt file")
    print()

    choice = input("Your choice (1-4): ").strip()
    password = _read_password(None)

    try:
        if choice == "1":
            text = input("Text to encrypt: ")
            if not text:
                raise CryptoError("Text cannot be empty.")
            print("\nCiphertext:")
            print(encrypt(text, password))
        elif choice == "2":
            ciphertext = input("Ciphertext to decrypt: ").strip()
            if not ciphertext:
                raise CryptoError("Ciphertext cannot be empty.")
            print("\nPlaintext:")
            print(decrypt(ciphertext, password))
        elif choice == "3":
            path = input("File to encrypt: ").strip()
            output = encrypt_file(path, password)
            print(f"\nEncrypted file written to: {output}")
        elif choice == "4":
            path = input("File to decrypt: ").strip()
            output = decrypt_file(path, password)
            print(f"\nDecrypted file written to: {output}")
        else:
            print("Invalid choice.")
            return 1
    except CryptoError as exc:
        print(f"Error: {exc}")
        return 1

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        return _run_interactive()

    if args.command == "interactive":
        return _run_interactive()

    try:
        password = _read_password(getattr(args, "password", None))

        if args.command == "encrypt":
            print(encrypt(args.text, password))
        elif args.command == "decrypt":
            print(decrypt(args.ciphertext, password))
        elif args.command == "encrypt-file":
            output = encrypt_file(args.input, password, args.output)
            print(output)
        elif args.command == "decrypt-file":
            output = decrypt_file(args.input, password, args.output)
            print(output)
    except CryptoError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
