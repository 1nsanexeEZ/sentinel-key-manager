import os

import pytest

from src.core.crypto.shamir import combine, split


def test_split_produces_n_shares():
    shares = split(b"secret", n=5, k=3)
    assert len(shares) == 5


def test_any_k_shares_reconstruct():
    secret = os.urandom(32)
    shares = split(secret, n=5, k=3)
    # several different 3-subsets must all recover the secret
    assert combine(shares[:3]) == secret
    assert combine(shares[2:5]) == secret
    assert combine([shares[0], shares[2], shares[4]]) == secret


def test_all_shares_reconstruct():
    secret = os.urandom(16)
    shares = split(secret, n=4, k=2)
    assert combine(shares) == secret


def test_fewer_than_k_does_not_reveal_secret():
    secret = os.urandom(32)
    shares = split(secret, n=5, k=3)
    # with only 2 of 3 required shares, reconstruction should not equal secret
    assert combine(shares[:2]) != secret


def test_threshold_two():
    secret = b"\x00\xff\x10\x2a"
    shares = split(secret, n=3, k=2)
    assert combine([shares[0], shares[2]]) == secret


def test_invalid_params():
    with pytest.raises(ValueError):
        split(b"x", n=2, k=3)
    with pytest.raises(ValueError):
        split(b"", n=3, k=2)


def test_duplicate_indices_rejected():
    shares = split(b"secret", n=3, k=2)
    with pytest.raises(ValueError):
        combine([shares[0], shares[0]])
