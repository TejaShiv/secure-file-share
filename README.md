# Secure File Sharing with Audit Ledger

A Flask application for storing and sharing files. Files are encrypted at rest,
access is authorization-checked on every read, and every transfer is recorded in
an append-only, hash-chained ledger whose integrity can be verified on demand.

## Features

- User registration with a password strength policy and hashed passwords.
- Login with account lockout after repeated failed attempts.
- File upload with per-file encryption at rest (Fernet / AES).
- File sharing to a specific recipient, with authorization enforced on preview,
  download, and delete.
- A tamper-evident transfer ledger: each entry is hash-chained to the previous
  one, so any retroactive change to history is detectable.
- Live "online users" presence via Socket.IO.

## Architecture

The app uses the application-factory pattern with blueprints:

```
filestore/
  __init__.py      create_app() factory: config, extensions, encryptor, blueprints
  config.py        environment-driven config (development / production / testing)
  extensions.py    single db / migrate / socketio instances
  security.py      encryption, traversal-safe storage names, ledger hashing
  models.py        User, File, TransferLedger
  ledger.py        append entries + verify_chain()
  sockets.py       online-user presence handlers
  auth/            register, login (with lockout), logout, login_required
  files/           upload, download, preview, shared/uploaded listings, delete
  main/            home, dashboard, ledger view
run.py             entrypoint (dev server + WSGI target)
tests/             pytest suite
```

## Security model

Several deliberate choices protect the app; each maps to a concrete threat:

- **Session secret from the environment.** `SECRET_KEY` signs session cookies and
  is never hardcoded. A guessable key would let anyone forge a logged-in session
  for any user. Production refuses to start without it.
- **Encryption at rest.** File contents are encrypted with Fernet before being
  written to disk. The key comes from `ENCRYPTION_KEY` in production.
- **Path-traversal-safe storage.** Uploaded files are stored under a random
  UUID-prefixed, sanitized name (see `safe_storage_name`), never the raw
  client-supplied filename. This blocks `../` traversal and prevents one user's
  upload from overwriting or being reachable via another's filename.
- **Authorization on every file read.** Preview and download verify that the
  session user is the owner or the designated recipient before returning bytes.
- **Validated input before side effects.** The upload route validates the
  recipient (integer, exists, not self) *before* writing anything, and wraps the
  disk write plus database records in a single transaction that rolls back and
  cleans up the orphaned file on failure.
- **Specific exception handling.** Decryption catches `InvalidToken` only, rather
  than a bare `except` that would hide unrelated errors.
- **Tamper-evident ledger.** Each `TransferLedger` row stores the hash of the
  previous row. `verify_chain()` re-walks the ledger and reports the first entry
  whose hash no longer matches — so edits to past records are detectable. This is
  a hash-chained audit log, not a distributed blockchain.

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt

cp .env.example .env
# Fill in SECRET_KEY and ENCRYPTION_KEY (generation commands are in the file).

flask --app run db upgrade      # or: python -c "from filestore import create_app; from filestore.extensions import db; app=create_app(); app.app_context().push(); db.create_all()"
python run.py                   # http://localhost:5000
```

## Running tests

```bash
pytest
```

The suite covers the security helpers (traversal safety, encryption round-trip,
ledger hashing) and integration flows (registration policy, login lockout, upload
authorization, and ledger tamper-detection).

## Notes

This project encrypts files with a single application-managed key and is intended
as a demonstration of secure application patterns rather than a production secrets
platform. Per-user key management and at-rest key rotation would be the next step
for a real deployment.
