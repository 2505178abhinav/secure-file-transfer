#!/usr/bin/env python3
"""
Secure File Transfer - Sender
Encrypts a file using AES-256-GCM and sends it over TCP to the receiver.
"""

import os
import socket
import struct
import json
import base64
import argparse
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import secrets


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from a password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
    return kdf.derive(password.encode())


def encrypt_file(file_path: str, password: str) -> tuple[bytes, dict]:
    """
    Encrypt a file using AES-256-GCM.
    Returns (ciphertext_with_tag, metadata_dict)
    """
    file_path = Path(file_path)
    plaintext = file_path.read_bytes()

    salt = secrets.token_bytes(16)        # 128-bit salt
    nonce = secrets.token_bytes(12)       # 96-bit nonce (GCM standard)
    key = derive_key(password, salt)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)   # includes 16-byte GCM tag

    metadata = {
        "filename": file_path.name,
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "original_size": len(plaintext),
    }
    return ciphertext, metadata


def send_file(host: str, port: int, file_path: str, password: str):
    """Encrypt and send a file to the receiver."""
    print(f"[*] Encrypting: {file_path}")
    ciphertext, metadata = encrypt_file(file_path, password)
    print(f"[+] Encrypted {metadata['original_size']} bytes → {len(ciphertext)} bytes ciphertext")

    meta_bytes = json.dumps(metadata).encode()

    with socket.create_connection((host, port), timeout=30) as sock:
        print(f"[*] Connected to {host}:{port}")

        # Protocol: [4 bytes meta_len][meta][8 bytes cipher_len][ciphertext]
        sock.sendall(struct.pack(">I", len(meta_bytes)))
        sock.sendall(meta_bytes)
        sock.sendall(struct.pack(">Q", len(ciphertext)))
        sock.sendall(ciphertext)

        # Wait for ACK
        ack = sock.recv(3)
        if ack == b"ACK":
            print("[+] Transfer complete — receiver confirmed successful decryption!")
        else:
            print("[-] Transfer complete but no ACK received.")

    print(f"[+] Done. File '{metadata['filename']}' sent securely.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Secure File Sender (AES-256-GCM)")
    parser.add_argument("file", help="Path to the file to encrypt and send")
    parser.add_argument("--host", default="127.0.0.1", help="Receiver IP address")
    parser.add_argument("--port", type=int, default=9000, help="Receiver port")
    parser.add_argument("--password", required=True, help="Encryption password")
    args = parser.parse_args()

    send_file(args.host, args.port, args.file, args.password)
