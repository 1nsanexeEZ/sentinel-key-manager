from dataclasses import dataclass

from src.domain.rbac import Capability, is_allowed, path_matches


@dataclass
class FakePolicy:
    path_glob: str
    can_read: bool = False
    can_write: bool = False
    can_delete: bool = False


def test_exact_path_matches():
    assert path_matches("app/db/password", "app/db/password")


def test_wildcard_matches_prefix():
    assert path_matches("app/*", "app/db/password")


def test_wildcard_does_not_match_other_prefix():
    assert not path_matches("app/*", "other/db/password")


def test_read_allowed_when_policy_grants_read():
    policies = [FakePolicy("app/*", can_read=True)]
    assert is_allowed(policies, "app/db/password", Capability.READ)


def test_write_denied_when_only_read_granted():
    policies = [FakePolicy("app/*", can_read=True)]
    assert not is_allowed(policies, "app/db/password", Capability.WRITE)


def test_denied_when_no_policy_matches():
    policies = [FakePolicy("app/*", can_read=True, can_write=True)]
    assert not is_allowed(policies, "other/secret", Capability.READ)
