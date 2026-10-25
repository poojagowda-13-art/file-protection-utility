# File Protection Utility

A command-line tool that encrypts and decrypts local files using
**AES-256-GCM** symmetric encryption, with a password-derived key via
**PBKDF2-HMAC-SHA256** and a random salt per file.

## Objective

Implement standard AES-256 symmetric file encryption and password key
derivation (PBKDF2).

## How it works

1. **Cryptography library** — built on Python's `cryptography` package
   (`AESGCM`, `PBKDF2HMAC`), the standard library for this in Python.
2. **Key derivation (PBKDF2 + salt)** — a random 16-byte salt is generated
   per file, and the password is stretched into a 256-bit key using
   PBKDF2-HMAC-SHA256 with 390,000 iterations (OWASP 2023 minimum
   recommendation).
3. **Encryption (.enc output)** — the file is encrypted with AES-256-GCM.
   The output file stores `[salt][nonce][ciphertext + auth tag]` so it's
   fully self-contained — only the password is needed to decrypt it.
4. **Decryption with MAC integrity check** — AES-GCM includes a built-in
   authentication tag. On decrypt, this tag is verified automatically: a
   wrong password *or* any tampering with the encrypted file causes
   decryption to fail safely, with no partial/corrupt output ever written.

## Usage

```bash
# Encrypt a file (prompts for password if -p is omitted)
python file_protection.py encrypt -i secret.txt -o secret.txt.enc

# Decrypt it back
python file_protection.py decrypt -i secret.txt.enc -o secret_restored.txt

# Non-interactive (password on command line — fine for testing, not recommended for real secrets)
python file_protection.py encrypt -i secret.txt -o secret.txt.enc -p "MyStr0ng!Passw0rd"
python file_protection.py decrypt -i secret.txt.enc -o secret_restored.txt -p "MyStr0ng!Passw0rd"
```

## Verification performed

- ✅ Encrypt → decrypt round-trip: decrypted file is byte-for-byte
  identical to the original (`diff` confirms no differences).
- ✅ Wrong password: decryption is rejected with a clear error, no output
  file is written.
- ✅ Tampered ciphertext: flipping bits in the encrypted file causes the
  MAC check to fail and decryption is rejected, no output file is written.

## Example output

```
=== Encrypting ===
Encrypted 'secret.txt' -> 'secret.txt.enc' (91 bytes plaintext, AES-256-GCM, PBKDF2 390000 iterations)

=== Decrypting with correct password ===
Decrypted 'secret.txt.enc' -> 'secret_restored.txt' (91 bytes recovered). MAC integrity check: PASSED

=== Decrypting with wrong password ===
Decryption failed: wrong password or the file has been tampered with (MAC integrity check failed).
```

## Project structure

```
file-protection-utility/
├── file_protection.py   # main encrypt/decrypt CLI
└── README.md
```

## Notes

- AES-GCM was chosen over plain AES-CBC because it provides authenticated
  encryption (confidentiality + integrity) in a single step, satisfying
  the "decryption routine verifying MAC integrity" requirement without a
  separate HMAC implementation.
- PBKDF2 iteration count follows OWASP's current recommendation for
  PBKDF2-HMAC-SHA256 to resist brute-force/dictionary attacks on the
  password.
