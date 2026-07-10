import pytest

from src.core.crypto.envelope import (
    EnvelopeCipher,
    generate_kek,
    unwrap_kek,
    wrap_kek,
)


def test_wrap_unwrap_roundtrip():
    cipher = EnvelopeCipher(generate_kek())
    wrapped = cipher.wrap(b"db-password")
    assert cipher.unwrap(wrapped) == b"db-password"


def test_plaintext_not_in_wrapped():
    cipher = EnvelopeCipher(generate_kek())
    wrapped = cipher.wrap(b"db-password")
    assert b"db-password" not in wrapped.ciphertext
    assert b"db-password" not in wrapped.encrypted_dek


def test_fresh_dek_per_wrap():
    cipher = EnvelopeCipher(generate_kek())
    a = cipher.wrap(b"same")
    b = cipher.wrap(b"same")
    assert a.encrypted_dek != b.encrypted_dek
    assert a.ciphertext != b.ciphertext


def test_wrong_kek_cannot_unwrap():
    wrapped = EnvelopeCipher(generate_kek()).wrap(b"db-password")
    with pytest.raises(Exception):
        EnvelopeCipher(generate_kek()).unwrap(wrapped)


def test_kek_wrap_roundtrip_under_root():
    root = generate_kek()
    kek = generate_kek()
    assert unwrap_kek(root, wrap_kek(root, kek)) == kek


def test_wrong_root_cannot_unwrap_kek():
    kek = generate_kek()
    blob = wrap_kek(generate_kek(), kek)
    with pytest.raises(Exception):
        unwrap_kek(generate_kek(), blob)
