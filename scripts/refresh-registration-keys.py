#!/usr/bin/env python3
"""Refresh an externally managed registration after a DB header changes.

Requires sqlcipher3. Never writes WeChat databases or prints secrets. The server
only reloads the resulting registration; it does not receive the passphrase.
"""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import tempfile
import time

import sqlcipher3


def refresh(registration, passphrase_file, headers):
    original = registration.read_bytes()
    config = json.loads(original)
    root = Path(config["db_path"]).resolve(strict=True)
    if (root / "db_storage").is_dir():
        root = (root / "db_storage").resolve(strict=True)
    passphrase = bytes.fromhex(passphrase_file.read_text().strip())
    changed = []
    pending = {}
    candidates = dict(config["keys"])
    # WeChat creates new numbered message shards; they must not stay permanently keyless.
    for database in (root / "message").glob("message_*.db"):
        if re.fullmatch(r"message_\d+\.db", database.name):
            candidates.setdefault(str(database.relative_to(root)), None)
    for relative, old_key in candidates.items():
        database = (root / relative).resolve(strict=True)
        if not database.is_relative_to(root):
            raise ValueError("registered database escapes storage root")
        with database.open("rb") as source:
            salt = source.read(16)
        if len(salt) != 16:
            raise ValueError("database header incomplete")
        if old_key is not None and headers.get(relative) == salt:
            continue
        candidate = hashlib.pbkdf2_hmac("sha512", passphrase, salt, 256000, 32).hex()
        connection = sqlcipher3.connect(database.as_uri() + "?mode=ro", uri=True)
        try:
            connection.execute("PRAGMA key = \"x'%s'\"" % candidate)
            connection.execute("PRAGMA query_only=ON")
            connection.execute("SELECT count(*) FROM sqlite_master").fetchone()
        finally:
            connection.close()
        # A moving database must be retried rather than recording a key for an old header.
        with database.open("rb") as source:
            if source.read(16) != salt:
                raise RuntimeError("database header changed during validation")
        pending[relative] = salt
        if old_key is None or candidate != old_key.lower():
            config["keys"][relative] = candidate
            changed.append(relative)
    if changed:
        # Refuse a stale overwrite if another owner updates registration while deriving keys.
        if registration.read_bytes() != original:
            raise RuntimeError("registration changed during key validation; retry")
        fd, temporary = tempfile.mkstemp(prefix=registration.name + ".", dir=registration.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as output:
                json.dump(config, output, ensure_ascii=False, indent=2)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, registration)
        finally:
            # Only remove the exact tempfile returned by mkstemp in the registration directory.
            path = Path(temporary)
            if path.parent.resolve() != registration.parent.resolve():
                raise RuntimeError("unexpected temporary registration path")
            if path.exists():
                path.unlink()
    headers.update(pending)
    return len(changed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registration", type=Path, required=True)
    parser.add_argument("--passphrase-file", type=Path, required=True)
    parser.add_argument("--watch-seconds", type=float, default=0,
                        help="0: one pass; otherwise poll headers at this interval (minimum 1s)")
    args = parser.parse_args()
    if args.watch_seconds < 0 or 0 < args.watch_seconds < 1:
        parser.error("watch interval must be 0 or at least 1 second")
    registration = args.registration.resolve(strict=True)
    headers = {}
    last_error = None
    while True:
        try:
            count = refresh(registration, args.passphrase_file, headers)
            if count:
                print("validated and refreshed %d database keys" % count, flush=True)
            if last_error:
                print("registration key refresh recovered", flush=True)
            last_error = None
        except Exception as error:
            # Exception strings from third-party DB libraries can contain paths or SQL.
            kind = type(error).__name__
            if kind != last_error:
                print("registration key refresh blocked: " + kind, flush=True)
            last_error = kind
            if not args.watch_seconds:
                raise SystemExit(1)
        if not args.watch_seconds:
            return
        time.sleep(args.watch_seconds)


if __name__ == "__main__":
    main()
