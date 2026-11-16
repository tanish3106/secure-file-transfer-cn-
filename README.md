# Secure File Transfer using AES-256 Encryption

Computer Networks project - Python, TCP sockets, AES-256-GCM, SHA-256, HMAC, SQLite, Tkinter.

## Features
- TCP client-server with a thread per client
- AES-256-GCM encryption of every file, in 64 KB chunks (chunk number is authenticated)
- Key authentication: HMAC-SHA256 challenge-response (the key is never sent)
- User accounts: register / login, passwords stored as salted PBKDF2 hashes in SQLite
- Integrity: GCM tag per chunk + SHA-256 of the whole file
- Upload, download, list, delete, transfer history (per-user folders)
- Command-line menu and Tkinter GUI, server log file, automated tests

## Files
| File | Purpose |
|---|---|
| config.py | host, port, chunk size, paths |
| crypto_utils.py | AES-GCM, PBKDF2 key derivation, SHA-256, HMAC, password hashing |
| network_utils.py | message framing and encrypted JSON helpers |
| database.py | SQLite: users and transfers tables |
| server.py | multi-threaded server |
| client.py | SecureClient class + command-line menu |
| gui_client.py | Tkinter GUI |
| test_all.py | 19 automated tests |

## Run
    pip install cryptography
    python server.py mysecret          # terminal 1
    python client.py                   # terminal 2 (or: python gui_client.py)
    python test_all.py                 # run tests

Two computers: put both on the same network, set the server's IP in the client prompt/GUI,
and allow port 5001 in the firewall.
