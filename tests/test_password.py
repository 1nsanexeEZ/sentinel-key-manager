from src.core.security.password import hash_password, verify_password


def test_hash_is_not_plaintext():
    h = hash_password("s3cret")
    assert h != "s3cret"
    assert h.startswith("$argon2id$")


def test_verify_correct_password():
    h = hash_password("s3cret")
    assert verify_password(h, "s3cret") is True


def test_verify_wrong_password():
    h = hash_password("s3cret")
    assert verify_password(h, "wrong") is False


def test_hashes_are_salted():
    assert hash_password("same") != hash_password("same")
