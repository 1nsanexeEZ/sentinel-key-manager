import pytest

from src.core.crypto.aes import decrypt, encrypt, generate_key


def test_roundtrip():
    key = generate_key()
    blob = encrypt(key, b"top secret")
    assert decrypt(key, blob) == b"top secret"


def test_ciphertext_is_not_plaintext():
    key = generate_key()
    blob = encrypt(key, b"top secret")
    assert b"top secret" not in blob


def test_nonce_is_random_per_call():
    key = generate_key()
    assert encrypt(key, b"same") != encrypt(key, b"same")


def test_wrong_key_fails():
    blob = encrypt(generate_key(), b"top secret")
    with pytest.raises(Exception):
        decrypt(generate_key(), blob)


def test_tampered_ciphertext_fails():
    key = generate_key()
    blob = bytearray(encrypt(key, b"top secret"))
    blob[-1] ^= 0x01
    with pytest.raises(Exception):
        decrypt(key, bytes(blob))


def test_aad_mismatch_fails():
    key = generate_key()
    blob = encrypt(key, b"top secret", aad=b"ctx-a")
    with pytest.raises(Exception):
        decrypt(key, blob, aad=b"ctx-b")
