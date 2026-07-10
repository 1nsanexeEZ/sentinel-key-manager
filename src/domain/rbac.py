from enum import Enum
from fnmatch import fnmatchcase
from typing import Protocol


class Capability(str, Enum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"


class PolicyLike(Protocol):
    path_glob: str
    can_read: bool
    can_write: bool
    can_delete: bool


def path_matches(glob: str, path: str) -> bool:
    """Glob match where '*' spans any characters, including '/'."""
    return fnmatchcase(path, glob)


def _grants(policy: PolicyLike, capability: Capability) -> bool:
    return {
        Capability.READ: policy.can_read,
        Capability.WRITE: policy.can_write,
        Capability.DELETE: policy.can_delete,
    }[capability]


def is_allowed(
    policies: list[PolicyLike],
    path: str,
    capability: Capability,
) -> bool:
    """Allowed if any policy matches the path and grants the capability."""
    return any(
        path_matches(p.path_glob, path) and _grants(p, capability)
        for p in policies
    )
