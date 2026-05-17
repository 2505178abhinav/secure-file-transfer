# 🔒 Secure File Transfer

**Encryption · Transfer · Decryption**

A Python implementation of end-to-end encrypted file transfer over TCP/IP, featuring both a CLI and a full GUI (bonus).

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        SENDER DEVICE                        │
│                                                             │
│  [File] ──► PBKDF2 Key Derivation ──► AES-256-GCM Encrypt  │
│                                              │               │
│                                        [Ciphertext]          │
│                                              │               │
│                                       TCP Socket ──────────► │
└─────────────────────────────────────────────────────────────┘
                                                │
                                          (IP Network)
                                                │
┌─────────────────────────────────────────────────────────────┐
│                       RECEIVER DEVICE                        │
│                                                             │
│  ◄────── TCP Socket                                         │
│              │                                              │
│        [Ciphertext + Metadata]                              │
│              │                                              │
│  PBKDF2 Key Derivation ──► AES-256-GCM Decrypt ──► [File]  │
└─────────────────────────────────────────────────────────────┘
```

## Security Design

| Layer | Choice | Reason |
|-------|--------|--------|
| Encryption | AES-256-GCM | Industry standard; provides both confidentiality and integrity (authenticated encryption) |
| Key Derivation | PBKDF2-SHA256, 600,000 iterations | Resists brute-force; NIST-recommended iteration count |
| Salt | 128-bit random per transfer | Prevents rainbow-table attacks |
| Nonce | 96-bit random per transfer | GCM standard; prevents nonce reuse |
| Integrity | GCM authentication tag (128-bit) | Detects any tampering of ciphertext in transit |
| Transport | TCP/IP | Reliable byte-stream; works on LAN or internet |

### Transfer Protocol

```
[4 bytes: metadata length]  →  big-endian uint32
[N bytes: JSON metadata   ]  →  filename, salt, nonce, original_size (base64)
[8 bytes: ciphertext len  ]  →  big-endian uint64
[M bytes: ciphertext      ]  →  AES-GCM ciphertext + 16-byte auth tag
[3 bytes: ACK / NAK       ]  →  receiver confirmation
```

---

## Setup

### Requirements
- Python 3.9+
- `pip install -r requirements.txt`

```bash
pip install -r requirements.txt
```

---

## Running — CLI

### Step 1: Start the Receiver (on receiving device)
```bash
python receiver.py --host 0.0.0.0 --port 9000 --password "YourSecretPass" --output ./received
```

### Step 2: Send the File (on sending device)
```bash
python sender.py secret.pdf --host 192.168.1.50 --port 9000 --password "YourSecretPass"
```

Replace `192.168.1.50` with the receiver's actual IP address. Use `ipconfig` (Windows) or `ip a` (Linux/macOS) to find it.

---

## Running — GUI (Bonus)

```bash
python gui.py
```

The GUI has two tabs:
- **SEND** — Browse for a file, enter receiver IP/port/password, click "Encrypt & Send"
- **RECEIVE** — Enter port/password/save directory, click "Start Listening"

No command line needed!

---

## Demo Script (localhost test)

Open two terminals:

**Terminal 1 (Receiver):**
```bash
python receiver.py --password "demo123" --output ./received
```

**Terminal 2 (Sender):**
```bash
echo "Hello, World! This is a secret message." > test.txt
python sender.py test.txt --password "demo123"
```

Check `./received/test.txt` — it should match the original.

---

## File Structure

```
secure-file-transfer/
├── sender.py          # CLI sender: encrypts and sends file over TCP
├── receiver.py        # CLI receiver: accepts and decrypts file over TCP
├── gui.py             # GUI application (bonus) — full graphical interface
├── requirements.txt   # Python dependencies
└── README.md          # This file
```

---

## Notes

- The password is **never transmitted** over the network. Only the encrypted file and metadata (salt, nonce, filename) are sent.
- The GCM authentication tag ensures that any tampering of the file in transit is detected and the decryption fails with an error.
- For transfers over the internet (not LAN), ensure port 9000 is open/forwarded on the receiver's router.
