"""Arithmetic in GF(2^8) with the AES irreducible polynomial.

The modulus is m(x) = x^8 + x^4 + x^3 + x + 1, written 0x11B.
A byte shifted past bit 7 is reduced with 0x1B, because the x^8 coefficient
is implicit in an 8-bit register. See FIPS-197 section 4.2.
"""

from __future__ import annotations


def _require_byte(value: int, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 0xFF:
        raise ValueError(f"{name} must be a byte (0..255)")
    return value


def xtime(value: int) -> int:
    """Multiply a byte by x (0x02) in GF(2^8).

    FIPS-197 section 4.2.1: ``{57} * {02} = {ae}`` and ``{ae} * {02} = {47}``.
    """
    value = _require_byte(value, "value")
    shifted = (value << 1) & 0xFF
    if value & 0x80:
        shifted ^= 0x1B
    return shifted


def gf_mul(left: int, right: int) -> int:
    """Multiply two bytes in GF(2^8).

    Repeatedly doubles ``left`` with ``xtime`` and adds it when the matching
    bit of ``right`` is set. FIPS-197 section 4.2.1: ``{57} * {13} = {fe}``.
    """
    left = _require_byte(left, "left")
    right = _require_byte(right, "right")
    result = 0
    while right:
        if right & 1:
            result ^= left
        left = xtime(left)
        right >>= 1
    return result


def gf_inv(value: int) -> int:
    """Return the multiplicative inverse of a byte in GF(2^8).

    Zero maps to zero, matching the AES S-box. Every other byte ``a`` satisfies
    ``a^254 = a^{-1}`` because the multiplicative group has order 255.
    """
    value = _require_byte(value, "value")
    if value == 0:
        return 0
    result = 1
    base = value
    exponent = 254
    while exponent:
        if exponent & 1:
            result = gf_mul(result, base)
        base = gf_mul(base, base)
        exponent >>= 1
    return result
