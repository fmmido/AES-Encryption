# AES Encryption and Decryption with PBKDF2

This repository contains a Python implementation of **AES (Advanced Encryption Standard)** encryption and decryption. It demonstrates secure coding practices by using password-based key derivation (PBKDF2) and incorporating cryptographic best practices for handling sensitive data.

## Features
- **AES Encryption (CBC Mode)**: Securely encrypts data with a 256-bit key.
- **Password-Based Key Derivation**: Uses PBKDF2 with SHA-256 to derive encryption keys from passwords.
- **Salts and IVs**: Generates random salts and initialization vectors (IVs) for each encryption process to enhance security.
- **PKCS7 Padding**: Ensures plaintext is properly padded to match the block size.
- **Decryption Support**: Fully supports decryption of the encrypted ciphertext to retrieve the original plaintext.

## How It Works
1. A cryptographic key is derived from a user-provided password and a randomly generated salt using **PBKDF2-HMAC-SHA256**.
2. The plaintext is padded using **PKCS7** to align with AES block size requirements.
3. **AES encryption** is performed in **CBC mode** using the derived key and a randomly generated IV.
4. The encrypted output is combined with the IV and encoded in Base64 for storage or transmission.
5. Decryption reverses the process to recover the original plaintext.

## Requirements
This script uses the following Python library:
- `cryptography`

Install the required library:
```bash
pip install cryptography

Usage

Clone the repository and use the provided script to encrypt and decrypt data.

Encryption Example

from aes_encryption import encrypt

plaintext = "Confidential Data: Encrypt This!"
password = "HardcorePassword"

ciphertext, salt = encrypt(plaintext, password)
print(f"Encrypted: {ciphertext}")
print(f"Salt: {salt.hex()}")

Decryption Example

from aes_encryption import decrypt

decrypted_text = decrypt(ciphertext, password, salt)
print(f"Decrypted: {decrypted_text.decode()}")

Example Output

Encrypted: qXtA5HZVXxRbCfNuUNvJZ6k0vHCl1NvFYN+xtXBzgLs=
Salt: 8a2c9eb62d9f4a3c97e1a57b06f1c7a8
Decrypted: Confidential Data: Encrypt This!

Security Features

Random Salts and IVs: Ensures that even if the same plaintext and password are used multiple times, the output ciphertext is always unique.

Key Strength: PBKDF2 increases resistance against brute-force attacks by applying multiple iterations (default: 100,000).

AES-256: Strong encryption with a 256-bit key ensures the confidentiality of data.


Limitations

This implementation assumes secure management of the password and salt outside the script.

The script does not handle very large files; additional logic would be needed for file encryption.


License

This project is licensed under the MIT License. See the LICENSE file for details.
