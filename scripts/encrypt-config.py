#!/usr/bin/env python3
"""
Admin tool to create encrypted WireGuard config files.
Usage: python3 scripts/encrypt-config.py wg0.conf output.enc

Requires: pip install cryptography argon2-cffi
"""
import sys
import os
from getpass import getpass

MAGIC = b"WGCV1\x00"
SALT_LEN = 32
NONCE_LEN = 12

ARGON2_TIME_COST = 2
ARGON2_MEMORY_COST = 19456
ARGON2_PARALLELISM = 1
ARGON2_HASH_LEN = 32

def encrypt(plaintext: bytes, password: str) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from argon2.low_level import hash_secret_raw, Type

    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)

    key = hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=Type.ID,
    )

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    return MAGIC + salt + nonce + ciphertext


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input.conf> <output.enc>")
        sys.exit(1)

    input_path, output_path = sys.argv[1], sys.argv[2]

    with open(input_path, "rb") as f:
        plaintext = f.read()

    password = getpass("Encryption password: ")
    confirm = getpass("Confirm password: ")

    if password != confirm:
        print("Passwords do not match.")
        sys.exit(1)

    encrypted = encrypt(plaintext, password)

    with open(output_path, "wb") as f:
        f.write(encrypted)

    print(f"Encrypted config written to: {output_path}")
    print(f"Original size: {len(plaintext)} bytes → Encrypted: {len(encrypted)} bytes")
