"""Integer arithmetic used by RSA.

Implemented for Week 5: the extended Euclidean algorithm, modular inverses,
and square-and-multiply modular exponentiation. Prime generation and the RSA
encryption scheme live in ``cryptosystem.rsa.rsa`` and are still stubs.

These routines are iterative so a 1024-bit modulus does not hit Python's
recursion limit when a teammate builds key generation on top of them.
"""

from __future__ import annotations


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Return ``(g, x, y)`` such that ``a * x + b * y = g`` and ``g = gcd(a, b) >= 0``.

    The classic check is ``extended_gcd(240, 46) == (2, -9, 47)``.
    """
    if not isinstance(a, int) or isinstance(a, bool):
        raise TypeError("a must be an int")
    if not isinstance(b, int) or isinstance(b, bool):
        raise TypeError("b must be an int")

    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    if old_r < 0:
        old_r, old_s, old_t = -old_r, -old_s, -old_t
    return old_r, old_s, old_t


def modinv(value: int, modulus: int) -> int:
    """Return the inverse of ``value`` modulo ``modulus``.

    The result ``x`` satisfies ``0 <= x < modulus`` and
    ``value * x ≡ 1 (mod modulus)``. Raise ``ValueError`` when ``modulus``
    is not positive or when ``gcd(value, modulus)`` is not 1.

    Textbook RSA: ``modinv(17, 3120) == 2753`` for ``p = 61``, ``q = 53``.
    """
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError("value must be an int")
    if not isinstance(modulus, int) or isinstance(modulus, bool):
        raise TypeError("modulus must be an int")
    if modulus <= 0:
        raise ValueError("modulus must be positive")

    gcd, coefficient, _ = extended_gcd(value, modulus)
    if gcd != 1:
        raise ValueError(f"inverse of {value} mod {modulus} does not exist")
    return coefficient % modulus


def modexp(base: int, exponent: int, modulus: int) -> int:
    """Compute ``base ** exponent mod modulus`` by square-and-multiply.

    ``exponent`` must be non-negative and ``modulus`` must be positive.
    ``modexp(65, 17, 3233) == 2790`` is the textbook RSA encryption of 65
    under ``n = 61 * 53`` and ``e = 17``.
    """
    if not isinstance(base, int) or isinstance(base, bool):
        raise TypeError("base must be an int")
    if not isinstance(exponent, int) or isinstance(exponent, bool):
        raise TypeError("exponent must be an int")
    if not isinstance(modulus, int) or isinstance(modulus, bool):
        raise TypeError("modulus must be an int")
    if modulus <= 0:
        raise ValueError("modulus must be positive")
    if exponent < 0:
        raise ValueError("exponent must be non-negative")

    result = 1 % modulus
    base %= modulus
    while exponent:
        if exponent & 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        exponent >>= 1
    return result
