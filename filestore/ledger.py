"""Service functions for the tamper-evident transfer ledger."""
from datetime import datetime, timezone

from .extensions import db
from .models import TransferLedger
from .security import GENESIS_PREV_HASH, compute_ledger_hash


def _canonical_ts(dt):
    """Format a datetime for hashing in a way that is stable across a
    write (timezone-aware) and a later read from SQLite (naive). Both are
    treated as UTC and rendered identically."""
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt.replace(microsecond=dt.microsecond).isoformat()


def latest_entry():
    return TransferLedger.query.order_by(TransferLedger.id.desc()).first()


def append_entry(*, sent_by, sent_to, stored_name, file_extension, content_hash):
    """Create and persist a new ledger entry linked to the previous one.

    Returns the unsaved entry added to the session; the caller commits so
    the ledger write and the File write share one transaction.
    """
    prev = latest_entry()
    prev_hash = prev.entry_hash if prev else GENESIS_PREV_HASH

    # Set the timestamp explicitly so the value we hash is guaranteed to match
    # the value we persist, independent of when column defaults are applied.
    ts = datetime.now(timezone.utc)

    entry = TransferLedger(
        sent_by=sent_by,
        sent_to=sent_to,
        stored_name=stored_name,
        file_extension=file_extension,
        content_hash=content_hash,
        prev_hash=prev_hash,
        timestamp=ts,
    )
    db.session.add(entry)
    entry.entry_hash = compute_ledger_hash(
        prev_hash=prev_hash,
        sent_by=sent_by,
        sent_to=sent_to,
        stored_name=stored_name,
        content_hash=content_hash,
        timestamp_iso=_canonical_ts(ts),
    )
    return entry


def verify_chain():
    """Walk the ledger oldest-to-newest and confirm the hash chain is intact.

    Returns (ok, broken_id). ``ok`` is True when every entry's stored hash
    matches a recomputation and links correctly to its predecessor. If a
    break is found, ``broken_id`` is the id of the first bad entry.
    """
    entries = TransferLedger.query.order_by(TransferLedger.id.asc()).all()
    expected_prev = GENESIS_PREV_HASH
    for entry in entries:
        if entry.prev_hash != expected_prev:
            return False, entry.id
        recomputed = compute_ledger_hash(
            prev_hash=entry.prev_hash,
            sent_by=entry.sent_by,
            sent_to=entry.sent_to,
            stored_name=entry.stored_name,
            content_hash=entry.content_hash,
            timestamp_iso=_canonical_ts(entry.timestamp),
        )
        if recomputed != entry.entry_hash:
            return False, entry.id
        expected_prev = entry.entry_hash
    return True, None
