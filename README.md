# Ciphertext

A simple command-line tool that encrypts plaintext into ciphertext (and decrypts it back) using a password you choose.

## Features

- Password-based encryption and decryption
- Secure key derivation with PBKDF2-HMAC-SHA256
- AES encryption via [Fernet](https://cryptography.io/en/latest/fernet/) (from the `cryptography` library)
- Base64-encoded output for easy copy and paste

## Requirements

- Python 3.10 or newer
- `cryptography` (see `requirements.txt`)

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/Solzte/ciphertext.git
   cd ciphertext
   ```

2. (Recommended) Create a virtual environment:

   ```bash
   python -m venv .venv
   ```

   **Windows (PowerShell):**

   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```

   **macOS / Linux:**

   ```bash
   source .venv/bin/activate
   ```

3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

## Usage

Run the program:

```bash
python encrypt.py
```

You will be prompted to:

1. Choose **Encrypt** or **Decrypt**
2. Enter your password
3. Enter the text or ciphertext

### Example

```
========================================
  Text Encryption Program
========================================

1) Encrypt (plaintext -> ciphertext)
2) Decrypt (ciphertext -> plaintext)

Your choice (1 or 2): 1
Enter your password: my-secret-password
Text to encrypt: Hello, world!

Ciphertext:
Aj-K3gZyQOxKs62Vz58gQ2dBQUFBQUJx...
```

Use option **2** with the same password to recover the original text.

## How it works

1. A random 16-byte salt is generated for each encryption.
2. Your password and the salt are used to derive a 256-bit key (PBKDF2, 100,000 iterations).
3. The plaintext is encrypted with Fernet (symmetric AES).
4. Salt and ciphertext are combined and encoded as base64.

## Security notes

- Keep your password safe. If you lose it, the ciphertext cannot be recovered.
- Do not commit passwords or `.env` files to version control.
- This tool is intended for learning and personal use. For production systems, review your threat model and key management practices.

## Project structure

```
ciphertext/
├── encrypt.py          # Main CLI application
├── requirements.txt    # Python dependencies
├── README.md
├── LICENSE
└── .gitignore
```

## License

MIT — see [LICENSE](LICENSE).
