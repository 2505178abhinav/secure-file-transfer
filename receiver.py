#!/usr/bin/env python3
"""
Secure File Transfer - Receiver
Listens for an incoming encrypted file, decrypts it using AES-256-GCM, and saves it.
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


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from a password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
    return kdf.derive(password.encode())


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Receive exactly n bytes from socket."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly")
        buf.extend(chunk)
    return bytes(buf)


def decrypt_data(ciphertext: bytes, password: str, metadata: dict) -> bytes:
    """Decrypt AES-256-GCM ciphertext using password and metadata."""
    salt = base64.b64decode(metadata["salt"])
    nonce = base64.b64decode(metadata["nonce"])
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)   # raises InvalidTag if tampered
    return plaintext


def start_receiver(host: str, port: int, password: str, output_dir: str):
    """Listen for one incoming encrypted file, decrypt and save it."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(1)
        print(f"[*] Listening on {host}:{port} — waiting for sender...")

        conn, addr = server.accept()
        with conn:
            print(f"[+] Connection from {addr[0]}:{addr[1]}")

            # Read metadata
            meta_len = struct.unpack(">I", recv_exact(conn, 4))[0]
            meta_bytes = recv_exact(conn, meta_len)
            metadata = json.loads(meta_bytes.decode())
            print(f"[*] Incoming file: '{metadata['filename']}' ({metadata['original_size']} bytes original)")

            # Read ciphertext
            cipher_len = struct.unpack(">Q", recv_exact(conn, 8))[0]
            print(f"[*] Receiving {cipher_len} bytes of ciphertext...")
            ciphertext = recv_exact(conn, cipher_len)

            # Decrypt
            print("[*] Decrypting...")
            try:
                plaintext = decrypt_data(ciphertext, password, metadata)
            except Exception as e:
                print(f"[-] DECRYPTION FAILED: {e}")
                conn.sendall(b"NAK")
                return

            # Save
            out_path = output_dir / metadata["filename"]
            out_path.write_bytes(plaintext)
            print(f"[+] Decrypted successfully! Saved to: {out_path}")
            print(f"[+] Size verified: {len(plaintext)} == {metadata['original_size']}: {len(plaintext) == metadata['original_size']}")

            conn.sendall(b"ACK")
            print("[+] ACK sent to sender.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Secure File Receiver (AES-256-GCM)")
    parser.add_argument("--host", default="0.0.0.0", help="IP to bind (0.0.0.0 = all interfaces)")
    parser.add_argument("--port", type=int, default=9000, help="Port to listen on")
    parser.add_argument("--password", required=True, help="Decryption password")
    parser.add_argument("--output", default="./received", help="Directory to save received files")
    args = parser.parse_args()

    start_receiver(args.host, args.port, args.password, args.output)
