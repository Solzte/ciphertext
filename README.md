# Ciphertext

Password-based encryption toolkit for text and files. Includes a Python CLI, GUI, library, automated tests, CI, and optional Windows executable build.

## Features

- Encrypt and decrypt text (base64 output)
- Encrypt and decrypt any file (`.enc` output)
- Hidden password input with `getpass`
- Versioned binary format (`CPT1`) using PBKDF2 + AES-GCM
- Backward-compatible decryption for legacy Fernet ciphertext
- Interactive menu, argparse CLI, and Tkinter GUI
- Pytest suite and GitHub Actions CI
- Dependabot and CodeQL security automation

## Requirements

- Python 3.10+

## Installation

```bash
git clone https://github.com/Solzte/ciphertext.git
cd ciphertext
python -m venv .venv
```

Windows:

```powershell
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

macOS / Linux:

```bash
source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

### Interactive menu

```bash
python encrypt.py
```

### CLI

```bash
ciphertext encrypt "Hello, world!"
ciphertext decrypt "CPT1..."
ciphertext encrypt-file note.txt
ciphertext decrypt-file note.txt.enc
```

Examples with explicit password:

```bash
ciphertext encrypt "Secret message" -p my-password
ciphertext encrypt-file document.pdf -o document.pdf.enc -p my-password
```

If `-p` is omitted, the password is requested securely.

### GUI

```bash
python gui.py
```

### Library

```python
from ciphertext import encrypt, decrypt, encrypt_file, decrypt_file

token = encrypt("hello", "password")
print(decrypt(token, "password"))
```

## Build a Windows executable

```bash
pip install pyinstaller
pyinstaller ciphertext.spec
```

The GUI executable is created in `dist/Ciphertext.exe`.

## Tests

```bash
pytest
```

## Project structure

```
ciphertext/
├── src/ciphertext/          # Python package
│   ├── crypto.py            # Core crypto + file helpers
│   └── cli.py               # Argparse CLI
├── tests/                   # Pytest suite
├── gui.py                   # Tkinter desktop app
├── encrypt.py               # Backward-compatible entry point
├── pyproject.toml
├── requirements.txt
├── requirements-dev.txt
├── ciphertext.spec          # PyInstaller config
└── .github/
    ├── dependabot.yml       # Automated dependency updates
    └── workflows/
        ├── ci.yml           # Test workflow
        └── codeql.yml       # Security analysis
```

## Format

Current encrypted payloads use this layout:

```
CPT1 | version(1) | salt(16) | nonce(12) | ciphertext+tag
```

Text output is base64-encoded. File output is raw binary.

Legacy Fernet ciphertext from v1 can still be decrypted by the Python tool.

## Security notes

- Keep your password safe. Lost passwords cannot be recovered.
- Do not commit `.env`, secrets, or encrypted files you do not intend to share.
- This project is for learning and personal use. Review your threat model before production use.

## License

MIT — see [LICENSE](LICENSE).
