"""Socket helpers. TCP is a byte stream, so every message is sent as: 4-byte length + payload."""
import json
import struct

from crypto_utils import encrypt, decrypt


def recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed by peer")
        buf += chunk
    return buf


def send_msg(sock, data: bytes):
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_msg(sock) -> bytes:
    (length,) = struct.unpack(">I", recv_exact(sock, 4))
    return recv_exact(sock, length)


# plain JSON (only used for the very first authentication result)
def send_json(sock, obj):
    send_msg(sock, json.dumps(obj).encode())


def recv_json(sock):
    return json.loads(recv_msg(sock).decode())


# encrypted JSON: every command and reply after authentication goes through these
def send_secure(sock, key, obj):
    send_msg(sock, encrypt(key, json.dumps(obj).encode()))


def recv_secure(sock, key):
    return json.loads(decrypt(key, recv_msg(sock)).decode())
