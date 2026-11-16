"""Secure File Transfer - CLIENT (command-line menu).

Run:  python client.py
The SecureClient class is also used by gui_client.py and test_all.py.
"""
import hashlib
import math
import os
import socket
import struct
from getpass import getpass

from cryptography.exceptions import InvalidTag

import config
from crypto_utils import auth_response, decrypt, derive_key, encrypt, sha256_file
from network_utils import recv_json, recv_msg, recv_secure, send_msg, send_secure


class AuthError(Exception):
    pass


class SecureClient:
    def __init__(self, passphrase, host=config.HOST, port=config.PORT):
        self.key = derive_key(passphrase)
        self.host, self.port = host, port
        self.sock = None
        self.username = None
        self.last_preview = None      # (plaintext_hex, encrypted_hex) of the first chunk, for demos

    # ------------------------------------------------------------ connection
    def connect(self):
        self.sock = socket.create_connection((self.host, self.port), timeout=30)
        nonce = recv_msg(self.sock)
        send_msg(self.sock, auth_response(self.key, nonce))
        if not recv_json(self.sock)["ok"]:
            self.close()
            raise AuthError("Authentication failed: wrong shared passphrase")

    def close(self):
        if self.sock:
            try:
                send_secure(self.sock, self.key, {"cmd": "quit"})
            except Exception:
                pass
            self.sock.close()
            self.sock = None

    def _request(self, obj):
        send_secure(self.sock, self.key, obj)
        return recv_secure(self.sock, self.key)

    # ------------------------------------------------------------ accounts
    def register(self, username, password):
        r = self._request({"cmd": "register", "username": username, "password": password})
        if r["ok"]:
            self.username = username
        return r

    def login(self, username, password):
        r = self._request({"cmd": "login", "username": username, "password": password})
        if r["ok"]:
            self.username = username
        return r

    # ------------------------------------------------------------ file operations
    def upload(self, path, progress=None, tamper=False):
        """Encrypt `path` chunk by chunk and send it. `tamper=True` flips one byte (demo)."""
        size = os.path.getsize(path)
        chunks = math.ceil(size / config.CHUNK_SIZE)
        r = self._request({"cmd": "upload", "filename": os.path.basename(path), "size": size,
                           "chunks": chunks, "sha256": sha256_file(path)})
        if not r["ok"]:
            return r
        with open(path, "rb") as f:
            for i in range(chunks):
                plain = f.read(config.CHUNK_SIZE)
                blob = encrypt(self.key, plain, struct.pack(">I", i))
                if i == 0:
                    self.last_preview = (plain[:16].hex(), blob[12:28].hex())
                if tamper and i == 0:
                    blob = blob[:20] + bytes([blob[20] ^ 1]) + blob[21:]
                send_msg(self.sock, blob)
                if progress:
                    progress(i + 1, chunks)
        return recv_secure(self.sock, self.key)

    def download(self, filename, dest_dir=".", progress=None):
        r = self._request({"cmd": "download", "filename": filename})
        if not r["ok"]:
            return r
        out_path = os.path.join(dest_dir, "downloaded_" + os.path.basename(filename))
        sha = hashlib.sha256()
        try:
            with open(out_path + ".part", "wb") as f:
                for i in range(r["chunks"]):
                    data = decrypt(self.key, recv_msg(self.sock), struct.pack(">I", i))
                    f.write(data)
                    sha.update(data)
                    if progress:
                        progress(i + 1, r["chunks"])
        except InvalidTag:
            os.remove(out_path + ".part")
            self.close()
            return {"ok": False, "msg": "Decryption failed: data corrupted or wrong key"}
        if sha.hexdigest() != r["sha256"]:
            os.remove(out_path + ".part")
            return {"ok": False, "msg": "Integrity check failed (SHA-256 mismatch)"}
        os.replace(out_path + ".part", out_path)
        return {"ok": True, "msg": "Downloaded and integrity verified", "path": out_path}

    def list_files(self):
        return self._request({"cmd": "list"})

    def delete(self, filename):
        return self._request({"cmd": "delete", "filename": filename})

    def history(self):
        return self._request({"cmd": "history"})


# ====================================================================== command-line menu
def show_progress(done, total):
    pct = int(done * 100 / total) if total else 100
    print(f"\r  [{'#' * (pct // 5):<20}] {pct}%", end="", flush=True)
    if done == total:
        print()


def human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def menu(c):
    while True:
        print(f"\n--- Secure File Transfer (user: {c.username}) ---")
        print("1. Upload file\n2. Download file\n3. List my files\n4. Delete file")
        print("5. Transfer history\n6. Upload with corrupted data (demo)\n0. Exit")
        choice = input("Choose: ").strip()
        if choice in ("1", "6"):
            path = input("Path of file to upload: ").strip().strip('"')
            if not os.path.isfile(path):
                print("File not found.")
                continue
            r = c.upload(path, show_progress, tamper=(choice == "6"))
            if c.last_preview:
                print(f"  Original  first 16 bytes: {c.last_preview[0]}")
                print(f"  Encrypted first 16 bytes: {c.last_preview[1]}")
            print(("OK: " if r["ok"] else "ERROR: ") + r["msg"])
        elif choice == "2":
            r = c.download(input("File name to download: ").strip(), ".", show_progress)
            print(("OK: " if r["ok"] else "ERROR: ") + r["msg"] + (f" -> {r['path']}" if r["ok"] else ""))
            if c.sock is None:
                return
        elif choice == "3":
            files = c.list_files()["files"]
            print("\n".join(f"  {f['name']}  ({human(f['size'])})" for f in files) or "  (no files)")
        elif choice == "4":
            print(c.delete(input("File name to delete: ").strip())["msg"])
        elif choice == "5":
            for h in c.history()["history"]:
                print(f"  {h['time']}  {h['action']:<8} {h['filename']}  {h['status']}")
        elif choice == "0":
            return


def main():
    host = input(f"Server IP [{config.HOST}]: ").strip() or config.HOST
    c = SecureClient(getpass("Shared passphrase: "), host)
    try:
        c.connect()
    except AuthError as e:
        print(e)
        return
    except OSError as e:
        print("Could not connect to server:", e)
        return
    print("Connected. Key authentication successful.")
    while not c.username:
        mode = input("1. Login  2. Register : ").strip()
        user = input("Username: ").strip()
        pw = getpass("Password: ")
        r = c.login(user, pw) if mode == "1" else c.register(user, pw)
        print(r["msg"])
    try:
        menu(c)
    finally:
        c.close()


if __name__ == "__main__":
    main()
