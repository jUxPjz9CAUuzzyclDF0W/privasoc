"""Local, encrypted mapping between pseudonyms and original values (D15, D41).

- Lookup by HMAC digest of the original: the original never appears in clear on disk.
- Originals are encrypted with Fernet (AES-128-CBC + HMAC-SHA256).
- The file is created with mode 600 and lives outside git (data/).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import sqlite3
import threading
from pathlib import Path

from cryptography.fernet import Fernet

from privasoc.pseudo.tokens import GENERATORS

SCHEMA = """
CREATE TABLE IF NOT EXISTS mapping (
    kind   TEXT NOT NULL,
    digest TEXT NOT NULL,
    token  TEXT NOT NULL UNIQUE,
    enc    BLOB NOT NULL,
    PRIMARY KEY (kind, digest)
);
"""
MAX_SALT = 64


class Vault:
    def __init__(self, path: Path | str, hmac_key: bytes, fernet_key: bytes):
        if not hmac_key or not fernet_key:
            raise ValueError("Vault needs both an HMAC key and a Fernet key")
        self._key = hmac_key
        self._fernet = Fernet(fernet_key)
        self._lock = threading.Lock()
        path = str(path)
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            if not Path(path).exists():
                Path(path).touch(mode=0o600)
            os.chmod(path, 0o600)
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.executescript(SCHEMA)

    def _digest(self, kind: str, value: str) -> str:
        norm = value if kind in {"sid"} else value.lower()
        return hmac.new(self._key, f"{kind}\x00{norm}".encode(), hashlib.sha256).hexdigest()

    def token_for(self, kind: str, value: str) -> str:
        """Deterministic pseudonym for (kind, value); stored on first sight."""
        digest = self._digest(kind, value)
        with self._lock:
            row = self._conn.execute(
                "SELECT token FROM mapping WHERE kind=? AND digest=?", (kind, digest)
            ).fetchone()
            if row:
                return row[0]
            gen = GENERATORS[kind]
            for salt in range(MAX_SALT):
                token = gen(self._key, value, salt)
                taken = self._conn.execute(
                    "SELECT 1 FROM mapping WHERE token=?", (token,)
                ).fetchone()
                if not taken:
                    with self._conn:
                        self._conn.execute(
                            "INSERT INTO mapping(kind, digest, token, enc) VALUES (?,?,?,?)",
                            (kind, digest, token, self._fernet.encrypt(value.encode())),
                        )
                    return token
        raise RuntimeError(f"Could not allocate a unique {kind} pseudonym")

    def original(self, token: str) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT enc FROM mapping WHERE token=? COLLATE NOCASE", (token,)
            ).fetchone()
        return self._fernet.decrypt(row[0]).decode() if row else None

    def __len__(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM mapping").fetchone()[0]

    def close(self) -> None:
        self._conn.close()
