#!/usr/bin/env python3
"""
Admin tool to create encrypted WireGuard config files.
Usage: python3 encrypt-config.py wg0.conf output.enc

Requires: pip install cryptography argon2-cffi
"""
import sys
import os
import struct
from getpass import getpass

def encrypt(plaintext: bytes, password: str) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from argon2.low_level import hash_secret_raw, Type

    MAGIC = b"WGCV1\x00"
    salt = os.urandom(32)
    nonce = os.urandom(12)

    key = hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=2,
        memory_cost=19456,
        parallelism=1,
        hash_len=32,
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
