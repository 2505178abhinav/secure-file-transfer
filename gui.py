#!/usr/bin/env python3
"""
Secure File Transfer — GUI Application (Bonus)
A full graphical interface for encrypting, sending, and receiving files.
Run this script to launch the GUI. No command line needed.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import socket
import struct
import json
import base64
import secrets
import os
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


# ──────────────────────────── Crypto helpers ────────────────────────────

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600_000)
    return kdf.derive(password.encode())


def encrypt_file(file_path: str, password: str):
    data = Path(file_path).read_bytes()
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key = derive_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, data, None)
    meta = {
        "filename": Path(file_path).name,
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "original_size": len(data),
    }
    return ciphertext, meta


def decrypt_data(ciphertext: bytes, password: str, metadata: dict) -> bytes:
    salt = base64.b64decode(metadata["salt"])
    nonce = base64.b64decode(metadata["nonce"])
    key = derive_key(password, salt)
    return AESGCM(key).decrypt(nonce, ciphertext, None)


def recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection dropped")
        buf.extend(chunk)
    return bytes(buf)


# ──────────────────────────── GUI ────────────────────────────

DARK_BG   = "#0d1117"
PANEL_BG  = "#161b22"
ACCENT    = "#00d4aa"
ACCENT2   = "#7c3aed"
TEXT      = "#e6edf3"
MUTED     = "#8b949e"
SUCCESS   = "#3fb950"
ERROR     = "#f85149"
BORDER    = "#30363d"
BTN_BG    = "#21262d"


class LogWidget(scrolledtext.ScrolledText):
    def __init__(self, master, **kw):
        super().__init__(master, bg=PANEL_BG, fg=TEXT, insertbackground=ACCENT,
                         font=("Courier New", 10), relief="flat", bd=0,
                         selectbackground=ACCENT2, state="disabled", **kw)
        self.tag_config("ok",      foreground=SUCCESS)
        self.tag_config("err",     foreground=ERROR)
        self.tag_config("info",    foreground=ACCENT)
        self.tag_config("muted",   foreground=MUTED)

    def log(self, msg, kind="muted"):
        self.config(state="normal")
        self.insert("end", msg + "\n", kind)
        self.see("end")
        self.config(state="disabled")

    def clear(self):
        self.config(state="normal")
        self.delete("1.0", "end")
        self.config(state="disabled")


class StyledButton(tk.Button):
    def __init__(self, master, text, command, accent=False, **kw):
        color = ACCENT if accent else BTN_BG
        fg    = DARK_BG if accent else TEXT
        super().__init__(master, text=text, command=command,
                         bg=color, fg=fg, activebackground=ACCENT2, activeforeground="#fff",
                         font=("Segoe UI", 10, "bold"), relief="flat", cursor="hand2",
                         padx=16, pady=8, bd=0, **kw)
        self.bind("<Enter>", lambda e: self.config(bg=ACCENT2, fg="#fff"))
        self.bind("<Leave>", lambda e: self.config(bg=color, fg=fg))


class LabeledEntry(tk.Frame):
    def __init__(self, master, label, placeholder="", show="", **kw):
        super().__init__(master, bg=PANEL_BG, **kw)
        tk.Label(self, text=label, bg=PANEL_BG, fg=MUTED,
                 font=("Segoe UI", 9)).pack(anchor="w")
        self.var = tk.StringVar()
        e = tk.Entry(self, textvariable=self.var, show=show,
                     bg=BTN_BG, fg=TEXT, insertbackground=ACCENT,
                     relief="flat", bd=0, font=("Segoe UI", 11),
                     highlightthickness=1, highlightbackground=BORDER,
                     highlightcolor=ACCENT)
        e.pack(fill="x", ipady=6)
        if placeholder:
            e.insert(0, placeholder)
            e.config(fg=MUTED)
            e.bind("<FocusIn>",  lambda ev: (e.delete(0,"end"), e.config(fg=TEXT)) if e.get()==placeholder else None)
            e.bind("<FocusOut>", lambda ev: (e.insert(0,placeholder), e.config(fg=MUTED)) if e.get()==""    else None)

    def get(self): return self.var.get()
    def set(self, v): self.var.set(v)


class SenderTab(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=DARK_BG)
        self._build()

    def _build(self):
        pad = dict(padx=20, pady=8)

        # File picker
        frow = tk.Frame(self, bg=DARK_BG)
        frow.pack(fill="x", **pad)
        self.file_var = tk.StringVar(value="No file selected")
        tk.Label(frow, text="FILE TO SEND", bg=DARK_BG, fg=MUTED,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w")
        inner = tk.Frame(frow, bg=BTN_BG, highlightthickness=1,
                         highlightbackground=BORDER, highlightcolor=ACCENT)
        inner.pack(fill="x")
        tk.Label(inner, textvariable=self.file_var, bg=BTN_BG, fg=TEXT,
                 font=("Segoe UI", 10), anchor="w").pack(side="left", padx=10, pady=6, fill="x", expand=True)
        StyledButton(inner, "Browse", self._browse).pack(side="right", padx=4, pady=4)

        # Host / port / password
        row1 = tk.Frame(self, bg=DARK_BG)
        row1.pack(fill="x", **pad)
        self.host = LabeledEntry(row1, "RECEIVER IP", placeholder="127.0.0.1")
        self.host.pack(side="left", fill="x", expand=True, padx=(0,10))
        self.port = LabeledEntry(row1, "PORT", placeholder="9000")
        self.port.pack(side="left", fill="x", expand=True)

        self.pw = LabeledEntry(self, "PASSWORD", show="•")
        self.pw.pack(fill="x", **pad)

        StyledButton(self, "🔒  Encrypt & Send", self._send, accent=True).pack(pady=12)

        # Progress bar
        self.progress = ttk.Progressbar(self, mode="indeterminate", length=400)
        self.progress.pack(fill="x", padx=20)

        # Log
        tk.Label(self, text="LOG", bg=DARK_BG, fg=MUTED,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=20, pady=(12,2))
        self.log = LogWidget(self, height=10)
        self.log.pack(fill="both", expand=True, padx=20, pady=(0,12))

    def _browse(self):
        path = filedialog.askopenfilename(title="Select file to send")
        if path:
            self.file_var.set(path)

    def _send(self):
        filepath = self.file_var.get()
        host     = self.host.get().strip() or "127.0.0.1"
        port     = int(self.port.get().strip() or 9000)
        password = self.pw.get().strip()

        if filepath == "No file selected" or not filepath:
            messagebox.showerror("Error", "Please select a file first.")
            return
        if not password:
            messagebox.showerror("Error", "Password cannot be empty.")
            return

        self.log.clear()
        self.progress.start(10)
        threading.Thread(target=self._send_worker,
                         args=(filepath, host, port, password), daemon=True).start()

    def _send_worker(self, filepath, host, port, password):
        try:
            self.log.log(f"[*] Encrypting: {Path(filepath).name}", "info")
            ciphertext, meta = encrypt_file(filepath, password)
            self.log.log(f"[+] Encrypted! {meta['original_size']} → {len(ciphertext)} bytes", "ok")

            meta_bytes = json.dumps(meta).encode()
            self.log.log(f"[*] Connecting to {host}:{port}...", "info")

            with socket.create_connection((host, port), timeout=30) as sock:
                self.log.log(f"[+] Connected!", "ok")
                sock.sendall(struct.pack(">I", len(meta_bytes)))
                sock.sendall(meta_bytes)
                sock.sendall(struct.pack(">Q", len(ciphertext)))

                # Send in chunks for progress feel
                chunk = 65536
                sent = 0
                while sent < len(ciphertext):
                    end = min(sent + chunk, len(ciphertext))
                    sock.sendall(ciphertext[sent:end])
                    sent = end

                self.log.log(f"[*] Sent {sent} bytes. Waiting for ACK...", "muted")
                ack = sock.recv(3)

            if ack == b"ACK":
                self.log.log("[+] ✅ Receiver confirmed successful decryption!", "ok")
                self.after(0, lambda: messagebox.showinfo("Success",
                    f"File '{meta['filename']}' transferred and verified!"))
            else:
                self.log.log("[-] Transfer done but receiver sent no ACK.", "err")

        except Exception as e:
            self.log.log(f"[-] ERROR: {e}", "err")
            self.after(0, lambda: messagebox.showerror("Error", str(e)))
        finally:
            self.after(0, self.progress.stop)


class ReceiverTab(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=DARK_BG)
        self._server_thread = None
        self._running = False
        self._build()

    def _build(self):
        pad = dict(padx=20, pady=8)

        row1 = tk.Frame(self, bg=DARK_BG)
        row1.pack(fill="x", **pad)
        self.host = LabeledEntry(row1, "BIND IP", placeholder="0.0.0.0")
        self.host.pack(side="left", fill="x", expand=True, padx=(0,10))
        self.port = LabeledEntry(row1, "PORT", placeholder="9000")
        self.port.pack(side="left", fill="x", expand=True)

        self.pw = LabeledEntry(self, "PASSWORD", show="•")
        self.pw.pack(fill="x", **pad)

        # Output dir
        orow = tk.Frame(self, bg=DARK_BG)
        orow.pack(fill="x", **pad)
        self.outdir_var = tk.StringVar(value=str(Path.home() / "Downloads" / "received"))
        tk.Label(orow, text="SAVE DIRECTORY", bg=DARK_BG, fg=MUTED,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w")
        inner = tk.Frame(orow, bg=BTN_BG, highlightthickness=1,
                         highlightbackground=BORDER, highlightcolor=ACCENT)
        inner.pack(fill="x")
        tk.Label(inner, textvariable=self.outdir_var, bg=BTN_BG, fg=TEXT,
                 font=("Segoe UI", 10), anchor="w").pack(side="left", padx=10, pady=6, fill="x", expand=True)
        StyledButton(inner, "Browse", self._browse_dir).pack(side="right", padx=4, pady=4)

        btnrow = tk.Frame(self, bg=DARK_BG)
        btnrow.pack(pady=12)
        self.start_btn = StyledButton(btnrow, "▶  Start Listening", self._start, accent=True)
        self.start_btn.pack(side="left", padx=8)
        self.stop_btn  = StyledButton(btnrow, "■  Stop", self._stop)
        self.stop_btn.pack(side="left", padx=8)

        # Status badge
        self.status_var = tk.StringVar(value="● IDLE")
        self.status_lbl = tk.Label(self, textvariable=self.status_var,
                                   bg=DARK_BG, fg=MUTED, font=("Segoe UI", 10, "bold"))
        self.status_lbl.pack()

        tk.Label(self, text="LOG", bg=DARK_BG, fg=MUTED,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=20, pady=(12,2))
        self.log = LogWidget(self, height=14)
        self.log.pack(fill="both", expand=True, padx=20, pady=(0,12))

    def _browse_dir(self):
        d = filedialog.askdirectory(title="Select save directory")
        if d:
            self.outdir_var.set(d)

    def _set_status(self, text, color):
        self.status_var.set(text)
        self.status_lbl.config(fg=color)

    def _start(self):
        if self._running:
            return
        password = self.pw.get().strip()
        if not password:
            messagebox.showerror("Error", "Password cannot be empty.")
            return
        host    = self.host.get().strip() or "0.0.0.0"
        port    = int(self.port.get().strip() or 9000)
        outdir  = self.outdir_var.get()
        self._running = True
        self.log.clear()
        self._set_status("● LISTENING", ACCENT)
        self._server_thread = threading.Thread(
            target=self._listen_loop, args=(host, port, password, outdir), daemon=True)
        self._server_thread.start()

    def _stop(self):
        self._running = False
        self._set_status("● IDLE", MUTED)
        self.log.log("[*] Stopped.", "muted")

    def _listen_loop(self, host, port, password, outdir):
        Path(outdir).mkdir(parents=True, exist_ok=True)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind((host, port))
                server.listen(5)
                server.settimeout(1.0)
                self.log.log(f"[*] Listening on {host}:{port}", "info")

                while self._running:
                    try:
                        conn, addr = server.accept()
                    except socket.timeout:
                        continue
                    threading.Thread(target=self._handle_client,
                                     args=(conn, addr, password, outdir), daemon=True).start()

        except Exception as e:
            self.log.log(f"[-] Server error: {e}", "err")
        finally:
            self._running = False
            self.after(0, lambda: self._set_status("● IDLE", MUTED))

    def _handle_client(self, conn, addr, password, outdir):
        with conn:
            self.log.log(f"[+] Connection from {addr[0]}:{addr[1]}", "ok")
            try:
                meta_len   = struct.unpack(">I", recv_exact(conn, 4))[0]
                metadata   = json.loads(recv_exact(conn, meta_len).decode())
                self.log.log(f"[*] Incoming: '{metadata['filename']}' ({metadata['original_size']} bytes)", "info")

                cipher_len = struct.unpack(">Q", recv_exact(conn, 8))[0]
                self.log.log(f"[*] Receiving {cipher_len} bytes...", "muted")
                ciphertext = recv_exact(conn, cipher_len)

                plaintext = decrypt_data(ciphertext, password, metadata)
                out = Path(outdir) / metadata["filename"]
                out.write_bytes(plaintext)

                self.log.log(f"[+] ✅ Decrypted & saved: {out}", "ok")
                conn.sendall(b"ACK")
                self.after(0, lambda: messagebox.showinfo("File Received",
                    f"File '{metadata['filename']}' received and decrypted!\nSaved to: {out}"))

            except Exception as e:
                self.log.log(f"[-] Error: {e}", "err")
                try: conn.sendall(b"NAK")
                except: pass


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("🔒 Secure File Transfer")
        self.geometry("700x620")
        self.configure(bg=DARK_BG)
        self.resizable(True, True)
        self._build()

    def _build(self):
        # Header
        hdr = tk.Frame(self, bg=PANEL_BG, pady=16)
        hdr.pack(fill="x")
        tk.Label(hdr, text="🔒  SECURE FILE TRANSFER", bg=PANEL_BG, fg=ACCENT,
                 font=("Courier New", 18, "bold")).pack()
        tk.Label(hdr, text="AES-256-GCM  •  PBKDF2  •  TCP/IP", bg=PANEL_BG, fg=MUTED,
                 font=("Segoe UI", 9)).pack()

        # Tabs
        style = ttk.Style()
        style.theme_use("default")
        style.configure("TNotebook",          background=DARK_BG, borderwidth=0)
        style.configure("TNotebook.Tab",      background=BTN_BG, foreground=MUTED,
                         font=("Segoe UI", 10, "bold"), padding=[20, 8])
        style.map("TNotebook.Tab",
                  background=[("selected", PANEL_BG)],
                  foreground=[("selected", ACCENT)])

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=0, pady=0)

        sender_tab   = SenderTab(nb)
        receiver_tab = ReceiverTab(nb)

        nb.add(sender_tab,   text="  📤  SEND  ")
        nb.add(receiver_tab, text="  📥  RECEIVE  ")

        # Footer
        foot = tk.Frame(self, bg=PANEL_BG, pady=6)
        foot.pack(fill="x", side="bottom")
        tk.Label(foot, text="Encryption: AES-256-GCM  |  KDF: PBKDF2-SHA256 (600,000 iter)  |  Transport: TCP/IP",
                 bg=PANEL_BG, fg=MUTED, font=("Segoe UI", 8)).pack()


if __name__ == "__main__":
    app = App()
    app.mainloop()
