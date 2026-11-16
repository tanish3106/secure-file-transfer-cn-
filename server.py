"""Secure File Transfer - SERVER.

Run:  python server.py <passphrase> [--port 5001]

Connection steps for every client:
  1. HMAC challenge-response with the shared key   (is this a trusted client?)
  2. register / login with username + password     (who is this user?)
  3. commands: upload, download, list, delete, history, quit
Everything after step 1 is AES-256-GCM encrypted.
"""
import argparse
import logging
import math
import os
import socket
import struct
import threading

from cryptography.exceptions import InvalidTag

import config
import database
from crypto_utils import (auth_response, decrypt, derive_key, encrypt, sha256_file)
import hashlib
import hmac
from network_utils import (recv_json, recv_msg, recv_secure, send_json, send_msg, send_secure)

log = logging.getLogger("server")


def setup_logging():
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s",
                        handlers=[logging.FileHandler(config.LOG_FILE), logging.StreamHandler()])


def safe_name(name: str) -> str:
    """Strip any folder part so '../../x' cannot escape the user's folder."""
    return os.path.basename(str(name).replace("\\", "/"))


def user_dir(username: str) -> str:
    path = os.path.join(config.STORAGE_DIR, username)
    os.makedirs(path, exist_ok=True)
    return path


# ---------------------------------------------------------------- step 1: authentication
def authenticate_channel(conn, key) -> bool:
    nonce = os.urandom(16)                       # new random challenge for every connection
    send_msg(conn, nonce)
    reply = recv_msg(conn)
    ok = hmac.compare_digest(reply, auth_response(key, nonce))
    send_json(conn, {"ok": ok})
    return ok


# ---------------------------------------------------------------- step 2: accounts
def handle_account(conn, key, req, ip):
    username = str(req.get("username", "")).strip()
    password = str(req.get("password", ""))
    if req["cmd"] == "register":
        ok, msg = database.create_user(username, password)
    else:
        ok = database.check_user(username, password)
        msg = "Login successful" if ok else "Invalid username or password"
    log.info("%s %s from %s: %s", req["cmd"], username, ip, "OK" if ok else "FAILED")
    send_secure(conn, key, {"ok": ok, "msg": msg})
    return username if ok else None


# ---------------------------------------------------------------- step 3: commands
def handle_upload(conn, key, req, user, ip):
    name = safe_name(req.get("filename", ""))
    size = int(req.get("size", -1))
    chunks = int(req.get("chunks", -1))
    expected_hash = str(req.get("sha256", ""))
    if not name or size < 0 or size > config.MAX_FILE_SIZE or chunks != math.ceil(size / config.CHUNK_SIZE):
        send_secure(conn, key, {"ok": False, "msg": "Invalid upload request"})
        return
    send_secure(conn, key, {"ok": True, "msg": "ready"})

    final_path = os.path.join(user_dir(user), name)
    temp_path = final_path + ".part"
    sha, received, corrupted = hashlib.sha256(), 0, False
    with open(temp_path, "wb") as f:
        for i in range(chunks):                      # always read every chunk so the stream stays in sync
            blob = recv_msg(conn)
            if corrupted:
                continue
            try:
                data = decrypt(key, blob, struct.pack(">I", i))   # chunk number is authenticated
            except InvalidTag:
                corrupted = True
                continue
            f.write(data)
            sha.update(data)
            received += len(data)

    if corrupted:
        os.remove(temp_path)
        log.warning("REJECTED %s from %s: corrupted data or wrong key", name, user)
        database.log_transfer(user, "upload", name, size, "REJECTED (corrupted)", ip)
        send_secure(conn, key, {"ok": False, "msg": "Decryption failed: data corrupted or wrong key"})
    elif received != size or sha.hexdigest() != expected_hash:
        os.remove(temp_path)
        log.warning("REJECTED %s from %s: SHA-256 mismatch", name, user)
        database.log_transfer(user, "upload", name, size, "REJECTED (hash mismatch)", ip)
        send_secure(conn, key, {"ok": False, "msg": "Integrity check failed (SHA-256 mismatch)"})
    else:
        os.replace(temp_path, final_path)
        log.info("STORED %s (%d bytes) for %s", name, size, user)
        database.log_transfer(user, "upload", name, size, "OK", ip)
        send_secure(conn, key, {"ok": True, "msg": f"Saved '{name}' ({size} bytes). Integrity verified."})


def handle_download(conn, key, req, user, ip):
    name = safe_name(req.get("filename", ""))
    path = os.path.join(user_dir(user), name)
    if not name or not os.path.isfile(path):
        send_secure(conn, key, {"ok": False, "msg": "File not found"})
        return
    size = os.path.getsize(path)
    chunks = math.ceil(size / config.CHUNK_SIZE)
    send_secure(conn, key, {"ok": True, "size": size, "chunks": chunks, "sha256": sha256_file(path)})
    with open(path, "rb") as f:
        for i in range(chunks):
            send_msg(conn, encrypt(key, f.read(config.CHUNK_SIZE), struct.pack(">I", i)))
    log.info("SENT %s (%d bytes) to %s", name, size, user)
    database.log_transfer(user, "download", name, size, "OK", ip)


def handle_list(conn, key, user):
    folder = user_dir(user)
    files = [{"name": n, "size": os.path.getsize(os.path.join(folder, n))}
             for n in sorted(os.listdir(folder)) if not n.endswith(".part")]
    send_secure(conn, key, {"ok": True, "files": files})


def handle_delete(conn, key, req, user, ip):
    name = safe_name(req.get("filename", ""))
    path = os.path.join(user_dir(user), name)
    if name and os.path.isfile(path):
        os.remove(path)
        database.log_transfer(user, "delete", name, 0, "OK", ip)
        send_secure(conn, key, {"ok": True, "msg": f"Deleted '{name}'"})
    else:
        send_secure(conn, key, {"ok": False, "msg": "File not found"})


# ---------------------------------------------------------------- one thread per client
def handle_client(conn, addr, key):
    ip, user = addr[0], None
    log.info("Connection from %s", ip)
    try:
        conn.settimeout(120)
        if not authenticate_channel(conn, key):
            log.warning("Authentication FAILED for %s (wrong shared key)", ip)
            return
        log.info("%s passed key authentication", ip)
        while True:
            try:
                req = recv_secure(conn, key)
            except InvalidTag:
                log.warning("Bad encrypted message from %s, closing", ip)
                break
            cmd = req.get("cmd")
            if cmd == "quit":
                break
            if cmd in ("register", "login"):
                user = handle_account(conn, key, req, ip) or user
            elif user is None:
                send_secure(conn, key, {"ok": False, "msg": "Please login first"})
            elif cmd == "upload":
                handle_upload(conn, key, req, user, ip)
            elif cmd == "download":
                handle_download(conn, key, req, user, ip)
            elif cmd == "list":
                handle_list(conn, key, user)
            elif cmd == "delete":
                handle_delete(conn, key, req, user, ip)
            elif cmd == "history":
                send_secure(conn, key, {"ok": True, "history": database.get_history(user)})
            else:
                send_secure(conn, key, {"ok": False, "msg": "Unknown command"})
    except (ConnectionError, socket.timeout):
        log.info("Client %s disconnected", ip)
    except Exception:
        log.exception("Error while handling %s", ip)
    finally:
        conn.close()


def serve(key, port=None, ready=None, stop=None):
    """Accept clients forever (or until `stop` event is set; used by the tests)."""
    database.init_db()
    os.makedirs(config.STORAGE_DIR, exist_ok=True)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port or config.PORT))
    srv.listen(10)
    srv.settimeout(0.5)
    log.info("Server listening on port %d", port or config.PORT)
    if ready:
        ready.set()
    while not (stop and stop.is_set()):
        try:
            conn, addr = srv.accept()
        except socket.timeout:
            continue
        threading.Thread(target=handle_client, args=(conn, addr, key), daemon=True).start()
    srv.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Secure file transfer server")
    parser.add_argument("passphrase", help="shared secret used to derive the AES-256 key")
    parser.add_argument("--port", type=int, default=config.PORT)
    args = parser.parse_args()
    setup_logging()
    try:
        serve(derive_key(args.passphrase), args.port)
    except KeyboardInterrupt:
        log.info("Server stopped")
