"""SHA-256 hashing and artifact-identity tests."""
from __future__ import annotations

from core.hashing.sha256 import artifact_id, sha256_bytes, sha256_file

DIGEST_OF_EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_sha256_of_empty_bytes():
    assert sha256_bytes(b"") == DIGEST_OF_EMPTY


def test_sha256_changes_for_different_content():
    assert sha256_bytes(b"hello") != sha256_bytes(b"hello!")


def test_artifact_id_format():
    aid = artifact_id("abc123")
    assert aid == "airlock:sha256:abc123"


def test_file_digest_matches_bytes(tmp_path):
    f = tmp_path / "a.txt"
    f.write_bytes(b"payload")
    assert sha256_file(f) == sha256_bytes(b"payload")


def test_changed_artifact_changes_digest(tmp_path):
    a = tmp_path / "a.tgz"
    b = tmp_path / "b.tgz"
    a.write_bytes(b"0123456789abcdef")
    b.write_bytes(b"0123456789Abcdef")  # one byte changed
    assert sha256_file(a) != sha256_file(b)