#!/usr/bin/env python3
"""
File Protection Utility
------------------------
A command-line tool that encrypts and decrypts local files using AES-256
symmetric encryption (AES-256-GCM), with a password-derived key via
PBKDF2-HMAC-SHA256 and a random salt per file.

AES-GCM provides both confidentiality (encryption) and integrity/authenticity
(a built-in MAC/authentication tag), so tampering or a wrong password is
detected automatically at decryption time.

File format for a *.enc output file:
    [16 bytes salt][12 bytes nonce][ciphertext + 16-byte GCM tag]

Usage:
    python file_protection.py encrypt -i secret.txt -o secret.txt.enc
    python file_protection.py decrypt -i secret.txt.enc -o secret_restored.txt

Author: <your name>
"""

import argparse
import getpass
import os
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

# ---------------------------------------------------------------------------
# Step 1: standard cryptography library (Python `cryptography`, AES-GCM)
# ---------------------------------------------------------------------------
SALT_SIZE = 16          # bytes
NONCE_SIZE = 12         # bytes, recommended size for AES-GCM
KEY_SIZE = 32           # 32 bytes = 256-bit key (AES-256)
PBKDF2_ITERATIONS = 390_000  # OWASP-recommended minimum for PBKDF2-HMAC-SHA256


# ---------------------------------------------------------------------------
# Step 2: key derivation using PBKDF2 with salt
# ---------------------------------------------------------------------------
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


# ---------------------------------------------------------------------------
# Step 3: encrypt target file into ciphertext output (.enc)
# ---------------------------------------------------------------------------
def encrypt_file(input_path: str, output_path: str, password: str) -> None:
    with open(input_path, "rb") as f:
        plaintext = f.read()

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)

    aesgcm = AESGCM(key)
    # AES-GCM produces ciphertext with a 16-byte authentication tag appended
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    with open(output_path, "wb") as f:
        f.write(salt + nonce + ciphertext)

    print(f"Encrypted '{input_path}' -> '{output_path}' "
          f"({len(plaintext)} bytes plaintext, AES-256-GCM, PBKDF2 {PBKDF2_ITERATIONS} iterations)")


# ---------------------------------------------------------------------------
# Step 4: decryption routine verifying MAC integrity
# ---------------------------------------------------------------------------
def decrypt_file(input_path: str, output_path: str, password: str) -> None:
    with open(input_path, "rb") as f:
        data = f.read()

    if len(data) < SALT_SIZE + NONCE_SIZE:
        raise ValueError("Input file is too short to be a valid .enc file.")

    salt = data[:SALT_SIZE]
    nonce = data[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = data[SALT_SIZE + NONCE_SIZE:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    try:
        # decrypt() verifies the GCM authentication tag automatically;
        # a wrong password or any tampering raises InvalidTag.
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    except InvalidTag:
        raise SystemExit(
            "Decryption failed: wrong password or the file has been "
            "tampered with (MAC integrity check failed)."
        )

    with open(output_path, "wb") as f:
        f.write(plaintext)

    print(f"Decrypted '{input_path}' -> '{output_path}' "
          f"({len(plaintext)} bytes recovered). MAC integrity check: PASSED")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="File Protection Utility — AES-256-GCM file encryption with PBKDF2 key derivation"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    enc_parser = subparsers.add_parser("encrypt", help="Encrypt a file")
    enc_parser.add_argument("-i", "--input", required=True, help="Path to the plaintext input file")
    enc_parser.add_argument("-o", "--output", required=True, help="Path to write the encrypted (.enc) file")
    enc_parser.add_argument("-p", "--password", help="Password (omit to be prompted securely)")

    dec_parser = subparsers.add_parser("decrypt", help="Decrypt a file")
    dec_parser.add_argument("-i", "--input", required=True, help="Path to the encrypted (.enc) input file")
    dec_parser.add_argument("-o", "--output", required=True, help="Path to write the decrypted output file")
    dec_parser.add_argument("-p", "--password", help="Password (omit to be prompted securely)")

    args = parser.parse_args()

    password = args.password or getpass.getpass("Enter password: ")

    if not os.path.exists(args.input):
        print(f"Error: input file not found: {args.input}")
        sys.exit(1)

    if args.command == "encrypt":
        encrypt_file(args.input, args.output, password)
    elif args.command == "decrypt":
        decrypt_file(args.input, args.output, password)


if __name__ == "__main__":
    main()
