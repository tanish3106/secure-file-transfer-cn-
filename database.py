"""SQLite storage for user accounts and the transfer history."""
import re
import sqlite3
from contextlib import closing
from datetime import datetime

import config
from crypto_utils import hash_password, verify_password


def _run(sql, params=(), fetch=False):
    with closing(sqlite3.connect(config.DB_PATH)) as conn:
        cur = conn.execute(sql, params)
        rows = cur.fetchall() if fetch else None
        conn.commit()
        return rows


def init_db():
    _run("""CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                salt TEXT NOT NULL,
                pw_hash TEXT NOT NULL,
                created_at TEXT NOT NULL)""")
    _run("""CREATE TABLE IF NOT EXISTS transfers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                action TEXT NOT NULL,
                filename TEXT,
                size INTEGER,
                status TEXT NOT NULL,
                client_ip TEXT,
                timestamp TEXT NOT NULL)""")


def create_user(username: str, password: str):
    if not re.fullmatch(r"[A-Za-z0-9_]{3,20}", username or ""):
        return False, "Username must be 3-20 characters: letters, digits or underscore"
    if len(password or "") < 6:
        return False, "Password must be at least 6 characters"
    salt, pw_hash = hash_password(password)
    try:
        _run("INSERT INTO users (username, salt, pw_hash, created_at) VALUES (?,?,?,?)",
             (username, salt, pw_hash, datetime.now().isoformat(timespec="seconds")))
    except sqlite3.IntegrityError:
        return False, "Username already exists"
    return True, "Account created"


def check_user(username: str, password: str) -> bool:
    rows = _run("SELECT salt, pw_hash FROM users WHERE username=?", (username,), fetch=True)
    if not rows:
        return False
    return verify_password(password or "", rows[0][0], rows[0][1])


def log_transfer(username, action, filename, size, status, client_ip):
    _run("INSERT INTO transfers (username, action, filename, size, status, client_ip, timestamp)"
         " VALUES (?,?,?,?,?,?,?)",
         (username, action, filename, size, status, client_ip,
          datetime.now().isoformat(timespec="seconds")))


def get_history(username: str, limit: int = 10):
    rows = _run("SELECT timestamp, action, filename, size, status FROM transfers "
                "WHERE username=? ORDER BY id DESC LIMIT ?", (username, limit), fetch=True)
    return [{"time": r[0], "action": r[1], "filename": r[2], "size": r[3], "status": r[4]}
            for r in rows]
