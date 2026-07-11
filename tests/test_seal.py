import pytest

from src.infrastructure.crypto.seal import SealState, SealedError


def test_starts_sealed():
    state = SealState()
    assert state.sealed is True


def test_root_key_raises_when_sealed():
    state = SealState()
    with pytest.raises(SealedError):
        state.root_key()


def test_unseal_exposes_root_key():
    state = SealState()
    state.unseal(b"0" * 32)
    assert state.sealed is False
    assert state.root_key() == b"0" * 32


def test_seal_clears_root_key():
    state = SealState()
    state.unseal(b"0" * 32)
    state.seal()
    assert state.sealed is True
    with pytest.raises(SealedError):
        state.root_key()
