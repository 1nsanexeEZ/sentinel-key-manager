"""Shamir's Secret Sharing over GF(2^8).

Each byte of the secret is split independently using a random polynomial of
degree k-1; any k of the n shares reconstruct the secret via Lagrange
interpolation at x=0, while k-1 shares reveal nothing.
"""

import os

_EXP = [0] * 512
_LOG = [0] * 256


def _init_tables() -> None:
    x = 1
    for i in range(255):
        _EXP[i] = x
        _LOG[x] = i
        # advance by the primitive element 3 (2 is not a generator of this field)
        doubled = x << 1
        if doubled & 0x100:
            doubled ^= 0x11B  # AES field polynomial
        x = doubled ^ x  # 3*x == (2*x) ^ x
    for i in range(255, 512):
        _EXP[i] = _EXP[i - 255]


_init_tables()


def _mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def _div(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError("division by zero in GF(256)")
    if a == 0:
        return 0
    return _EXP[(_LOG[a] - _LOG[b]) % 255]


def _eval(coeffs: list[int], x: int) -> int:
    y = 0
    for c in reversed(coeffs):
        y = _mul(y, x) ^ c
    return y


def _interpolate_at_zero(points: list[tuple[int, int]]) -> int:
    result = 0
    for i, (xi, yi) in enumerate(points):
        num = 1
        den = 1
        for j, (xj, _yj) in enumerate(points):
            if i == j:
                continue
            num = _mul(num, xj)  # (0 - xj) == xj in GF(2^8)
            den = _mul(den, xi ^ xj)  # (xi - xj) == xi ^ xj
        result ^= _mul(yi, _div(num, den))
    return result


def split(secret: bytes, n: int, k: int) -> list[bytes]:
    if not 1 <= k <= n <= 255:
        raise ValueError("require 1 <= k <= n <= 255")
    if not secret:
        raise ValueError("secret must be non-empty")

    shares: list[bytearray] = [bytearray([x]) for x in range(1, n + 1)]
    for byte in secret:
        coeffs = [byte] + list(os.urandom(k - 1))
        for share in shares:
            x = share[0]
            share.append(_eval(coeffs, x))
    return [bytes(share) for share in shares]


def combine(shares: list[bytes]) -> bytes:
    if len(shares) < 1:
        raise ValueError("need at least one share")
    length = len(shares[0])
    if any(len(s) != length for s in shares):
        raise ValueError("shares have inconsistent length")

    xs = [s[0] for s in shares]
    if len(set(xs)) != len(xs):
        raise ValueError("duplicate share indices")

    secret = bytearray()
    for pos in range(1, length):
        points = [(s[0], s[pos]) for s in shares]
        secret.append(_interpolate_at_zero(points))
    return bytes(secret)
