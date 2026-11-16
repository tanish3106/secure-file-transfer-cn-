"""Automated tests.  Run: python test_all.py   (starts its own temporary server)"""
import os
import shutil
import tempfile
import threading

import config

TMP = tempfile.mkdtemp()
config.STORAGE_DIR = os.path.join(TMP, "storage")
config.DB_PATH = os.path.join(TMP, "test.db")
config.LOG_FILE = os.path.join(TMP, "test.log")

import server
from client import AuthError, SecureClient
from crypto_utils import derive_key, decrypt, encrypt, sha256_file
from cryptography.exceptions import InvalidTag

PORT, PASS = 5055, "test-passphrase"
passed = 0


def check(name, condition):
    global passed
    assert condition, "FAILED: " + name
    passed += 1
    print("PASS:", name)


def new_client(passphrase=PASS):
    c = SecureClient(passphrase, "127.0.0.1", PORT)
    c.connect()
    return c


stop, ready = threading.Event(), threading.Event()
threading.Thread(target=server.serve, args=(derive_key(PASS), PORT, ready, stop), daemon=True).start()
ready.wait(5)

# --- crypto unit tests
key = derive_key(PASS)
check("AES round trip", decrypt(key, encrypt(key, b"hello")) == b"hello")
check("same plaintext gives different ciphertext", encrypt(key, b"x") != encrypt(key, b"x"))
try:
    decrypt(derive_key("other"), encrypt(key, b"hello"))
    check("wrong key detected", False)
except InvalidTag:
    check("wrong key detected", True)

# --- network tests
try:
    new_client("wrong-passphrase")
    check("wrong passphrase rejected", False)
except AuthError:
    check("wrong passphrase rejected", True)

c = new_client()
check("command before login refused", c.list_files()["ok"] is False)
check("register works", c.register("alice", "secret1")["ok"])
check("duplicate username refused", not c.register("alice", "secret1")["ok"])
c.close()

c = new_client()
check("wrong password refused", not c.login("alice", "badpass")["ok"])
check("correct login works", c.login("alice", "secret1")["ok"])

big = os.path.join(TMP, "big.bin")                      # ~300 KB = 5 chunks
with open(big, "wb") as f:
    f.write(os.urandom(300_000))
check("multi-chunk upload accepted", c.upload(big)["ok"])
check("file appears in list", any(x["name"] == "big.bin" for x in c.list_files()["files"]))
r = c.download("big.bin", TMP)
check("download succeeds", r["ok"])
check("downloaded file identical (SHA-256)", sha256_file(r["path"]) == sha256_file(big))

check("tampered upload rejected", not c.upload(big, tamper=True)["ok"])
empty = os.path.join(TMP, "empty.txt")
open(empty, "wb").close()
check("empty file works", c.upload(empty)["ok"])
check("history recorded", len(c.history()["history"]) >= 4)
check("path traversal blocked", not c.download("../../etc/passwd", TMP)["ok"])
check("delete works", c.delete("big.bin")["ok"])
check("deleted file gone", not any(x["name"] == "big.bin" for x in c.list_files()["files"]))
c.close()

stop.set()
shutil.rmtree(TMP, ignore_errors=True)
print(f"\nAll {passed} tests passed.")
