from filestore.security import (compute_ledger_hash, file_extension,
                                safe_storage_name)


def test_safe_storage_name_strips_traversal():
    name = safe_storage_name("../../etc/passwd")
    assert "/" not in name and "\\" not in name
    assert ".." not in name
    # secure_filename keeps the trailing readable component.
    assert name.endswith("passwd")


def test_safe_storage_name_is_unique_per_call():
    a = safe_storage_name("report.pdf")
    b = safe_storage_name("report.pdf")
    assert a != b  # UUID prefix prevents collisions/overwrites


def test_file_extension():
    assert file_extension("photo.JPG") == "jpg"
    assert file_extension("archive.tar.gz") == "gz"
    assert file_extension("noext") == ""


def test_ledger_hash_changes_with_prev_hash():
    common = dict(sent_by="a", sent_to="b", stored_name="x",
                  content_hash="c", timestamp_iso="2026-01-01T00:00:00")
    h1 = compute_ledger_hash(prev_hash="0" * 64, **common)
    h2 = compute_ledger_hash(prev_hash="1" * 64, **common)
    assert h1 != h2  # linkage means the same entry hashes differently in a different chain
