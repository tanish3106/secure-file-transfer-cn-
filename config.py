"""Central settings for the project. Change values here, not in the other files."""

HOST = "127.0.0.1"                 # set to the server PC's IP for the two-computer demo
PORT = 5001
CHUNK_SIZE = 64 * 1024             # files are encrypted and sent in 64 KB chunks
MAX_FILE_SIZE = 200 * 1024 * 1024  # server refuses uploads larger than 200 MB

STORAGE_DIR = "server_storage"     # each user gets a sub-folder here
DB_PATH = "secure_transfer.db"     # SQLite database (users + transfer history)
LOG_FILE = "server.log"

KDF_SALT = b"cn-project-fixed-salt"  # same on client and server so both derive the same AES key
KDF_ITERATIONS = 200_000
