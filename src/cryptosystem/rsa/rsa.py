"""RSA key generation and encryption.

Week 11 work, except ``RSAKey``, which is the shared record the rest of the
program already imports. Implement the functions against
``tests/unit/test_rsa.py`` and use ``modexp`` / ``modinv`` from
``cryptosystem.rsa.number_theory``. Do not call an external crypto library.

The integer API is textbook RSA. The byte API wraps a message in PKCS#1 v1.5
(block type 2) before that exponentiation, which is what the hybrid scheme
needs in order to hide a 16-byte AES key.

Author: Pichponleur Pen (Week 11: Miller-Rabin, prime and key generation,
textbook RSA, PKCS#1 v1.5, byte encrypt/decrypt with CRT decryption).
``RSAKey`` is by Adarsha Shrestha.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Callable

from cryptosystem.rsa.number_theory import extended_gcd, modexp, modinv


Rng = Callable[[int], bytes]

# Odd primes below 200. Trial division by these rejects most random
# candidates before the more expensive Miller-Rabin rounds.
_SMALL_PRIMES = (
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
    157, 163, 167, 173, 179, 181, 191, 193, 197, 199,
)

# Minimum PKCS#1 v1.5 overhead: 0x00, 0x02, eight padding bytes, 0x00.
_PKCS1_OVERHEAD = 11


@dataclass(frozen=True)
class RSAKey:
    """An RSA modulus and exponent, plus the private factors when they are known.

    ``byte_length`` is the size of the modulus in bytes, which is also the
    length of a PKCS#1 block and of an encrypted byte string.
    """

    n: int
    e: int
    d: int | None = None
    p: int | None = None
    q: int | None = None

    @property
    def byte_length(self) -> int:
        """Return the modulus length in bytes, rounding up."""
        if self.n <= 0:
            raise ValueError("modulus must be positive")
        return (self.n.bit_length() + 7) // 8


# Author: Pichponleur Pen
def _require_int(value: int, name: str) -> int:
    """Reject anything that is not a plain ``int`` (``bool`` included)."""
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{name} must be an int")
    return value


# Author: Pichponleur Pen
def _random_below(bound: int, rng: Rng) -> int:
    """Return a random integer in ``0 .. bound - 1`` from ``rng`` bytes.

    Eight extra bytes are drawn before the reduction, so the bias of the
    modulo step is below 2^-64 and no rejection loop is needed.
    """
    byte_count = (bound.bit_length() + 7) // 8 + 8
    return int.from_bytes(rng(byte_count), "big") % bound


# Author: Pichponleur Pen
def is_probable_prime(n: int, rounds: int = 40, rng: Rng | None = None) -> bool:
    """Miller-Rabin primality test.

    Return ``False`` for ``n < 2`` and for every even ``n`` other than 2.
    Write ``n - 1 = 2^s * d`` with ``d`` odd. For each of ``rounds`` random
    bases ``a`` in ``2..n-2`` (use ``rng`` when given; otherwise
    ``secrets.token_bytes``), compute ``x = modexp(a, d, n)``. The base passes
    when ``x`` is 1 or ``n - 1``, or when squaring ``x`` reaches ``n - 1``
    within ``s - 1`` squarings. Otherwise ``n`` is composite.

    ``rounds`` defaults to 40. A deterministic witness set is not required.
    Small primes are checked by trial division first, which settles every
    ``n`` below 200 and removes most composites cheaply.
    """
    _require_int(n, "n")
    _require_int(rounds, "rounds")
    if rounds < 1:
        raise ValueError("rounds must be at least 1")
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    for small in _SMALL_PRIMES:
        if n == small:
            return True
        if n % small == 0:
            return False

    rng = rng or secrets.token_bytes

    # n - 1 = 2^s * d with d odd.
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        a = 2 + _random_below(n - 3, rng)  # a in 2 .. n-2
        x = modexp(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False  # a is a witness that n is composite
    return True


# Author: Pichponleur Pen
def generate_prime(bits: int, rng: Rng | None = None) -> int:
    """Return a probable prime whose bit length is exactly ``bits``.

    Set the top bit so the integer has ``bits`` bits, and set the bottom bit
    so it is odd. Draw candidates with ``rng`` (default ``secrets.token_bytes``)
    and accept the first one for which ``is_probable_prime`` returns true.
    ``bits`` must be at least 2.
    """
    _require_int(bits, "bits")
    if bits < 2:
        raise ValueError("bits must be at least 2")
    rng = rng or secrets.token_bytes

    byte_count = (bits + 7) // 8
    mask = (1 << bits) - 1
    top_and_bottom = (1 << (bits - 1)) | 1
    while True:
        candidate = (int.from_bytes(rng(byte_count), "big") & mask) | top_and_bottom
        if is_probable_prime(candidate, rng=rng):
            return candidate


# Author: Pichponleur Pen
def generate_keypair(bits: int = 1024, e: int = 65537, rng: Rng | None = None) -> RSAKey:
    """Build a key pair whose modulus has about ``bits`` bits.

    ``bits`` must be even and at least 32. Draw distinct primes ``p`` and ``q``
    of ``bits // 2`` bits each, retrying while ``gcd(e, (p - 1) * (q - 1))``
    is not 1 or ``p == q``. The private exponent is the Euler-totient inverse

        d = modinv(e, (p - 1) * (q - 1))

    not the Carmichael-lambda inverse. Return ``RSAKey(n=p*q, e=e, d=d, p=p, q=q)``.
    The demo GUI asks for 1024 bits. Unit tests may use a smaller even size.
    """
    _require_int(bits, "bits")
    _require_int(e, "e")
    if bits < 32 or bits % 2 != 0:
        raise ValueError("bits must be even and at least 32")
    if e < 3 or e % 2 == 0:
        raise ValueError("e must be an odd integer of at least 3")

    half = bits // 2
    while True:
        p = generate_prime(half, rng)
        q = generate_prime(half, rng)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if extended_gcd(e, phi)[0] != 1:
            continue
        d = modinv(e, phi)
        return RSAKey(n=p * q, e=e, d=d, p=p, q=q)


# Author: Pichponleur Pen
def encrypt_int(message: int, n: int, e: int) -> int:
    """Textbook RSA: ``modexp(message, e, n)``.

    Require ``0 <= message < n``. The Week 11 test vector is ``p = 61``,
    ``q = 53``, ``n = 3233``, ``e = 17``, message ``65``, ciphertext ``2790``.
    """
    _require_int(message, "message")
    _require_int(n, "n")
    _require_int(e, "e")
    if n <= 0:
        raise ValueError("modulus must be positive")
    if not 0 <= message < n:
        raise ValueError("message must satisfy 0 <= message < n")
    return modexp(message, e, n)


# Author: Pichponleur Pen
def decrypt_int(ciphertext: int, n: int, d: int) -> int:
    """Textbook RSA: ``modexp(ciphertext, d, n)``. Require ``0 <= ciphertext < n``."""
    _require_int(ciphertext, "ciphertext")
    _require_int(n, "n")
    _require_int(d, "d")
    if n <= 0:
        raise ValueError("modulus must be positive")
    if not 0 <= ciphertext < n:
        raise ValueError("ciphertext must satisfy 0 <= ciphertext < n")
    return modexp(ciphertext, d, n)


# Author: Pichponleur Pen
def decrypt_int_crt(ciphertext: int, key: RSAKey) -> int:
    """Decrypt with the Chinese Remainder Theorem (Paar and Pelzl, Section 7.5.2).

    Needs ``key.p``, ``key.q`` and ``key.d``. The two exponentiations work
    modulo ``p`` and ``q`` with exponents ``d mod (p - 1)`` and
    ``d mod (q - 1)``, which is about four times faster than one
    exponentiation modulo ``n``. The result equals ``decrypt_int``.
    """
    if key.d is None or key.p is None or key.q is None:
        raise ValueError("CRT decryption needs d, p and q")
    _require_int(ciphertext, "ciphertext")
    if not 0 <= ciphertext < key.n:
        raise ValueError("ciphertext must satisfy 0 <= ciphertext < n")
    p, q = key.p, key.q
    m_p = modexp(ciphertext % p, key.d % (p - 1), p)
    m_q = modexp(ciphertext % q, key.d % (q - 1), q)
    # Recombine: m = m_q + q * ((m_p - m_q) * q^-1 mod p).
    h = ((m_p - m_q) * modinv(q, p)) % p
    return m_q + q * h


# Author: Pichponleur Pen
def pkcs1_v15_pad(message: bytes, k: int, rng: Rng | None = None) -> bytes:
    """PKCS#1 v1.5 block type 2, RFC 8017 section 7.2.1.

    ``EM = 0x00 || 0x02 || PS || 0x00 || M`` with ``len(EM) == k`` and
    ``len(PS) = k - len(message) - 3 >= 8``. Every byte of ``PS`` is nonzero.
    ``rng(n)`` returns ``n`` random bytes and defaults to ``secrets.token_bytes``.
    Replace any zero drawn for ``PS``. Raise ``ValueError`` when the message
    is longer than ``k - 11`` bytes.
    """
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("message must be bytes")
    _require_int(k, "k")
    if len(message) > k - _PKCS1_OVERHEAD:
        raise ValueError(
            f"message too long: at most {max(k - _PKCS1_OVERHEAD, 0)} bytes for k = {k}"
        )
    rng = rng or secrets.token_bytes

    padding = bytearray(rng(k - len(message) - 3))
    for index, byte in enumerate(padding):
        while byte == 0:
            byte = rng(1)[0]
        padding[index] = byte
    return b"\x00\x02" + bytes(padding) + b"\x00" + bytes(message)


# Author: Pichponleur Pen
def pkcs1_v15_unpad(encoded: bytes) -> bytes:
    """Strip PKCS#1 v1.5 block type 2 padding.

    Require a leading ``0x00 0x02``, at least eight nonzero padding bytes, and
    a ``0x00`` separator. Raise ``ValueError`` when the block is malformed.
    """
    if not isinstance(encoded, (bytes, bytearray)):
        raise TypeError("encoded must be bytes")
    # One message for every failure, so the error does not reveal which check failed.
    error = ValueError("decryption error: malformed PKCS#1 v1.5 block")
    if len(encoded) < _PKCS1_OVERHEAD or encoded[0] != 0x00 or encoded[1] != 0x02:
        raise error
    separator = encoded.find(b"\x00", 2)
    if separator < 2 + 8:  # not found (-1) or fewer than eight padding bytes
        raise error
    return bytes(encoded[separator + 1:])


# Author: Pichponleur Pen
def encrypt(message: bytes, key: RSAKey, rng: Rng | None = None) -> bytes:
    """Pad ``message`` to ``key.byte_length`` bytes, then textbook-encrypt it.

    Return the ciphertext as a big-endian byte string of that same length.
    """
    k = key.byte_length
    encoded = pkcs1_v15_pad(message, k, rng)
    # encoded starts with 0x00, so as an integer it is below 256^(k-1) <= n.
    cipher_int = encrypt_int(int.from_bytes(encoded, "big"), key.n, key.e)
    return cipher_int.to_bytes(k, "big")


# Author: Pichponleur Pen
def decrypt(ciphertext: bytes, key: RSAKey) -> bytes:
    """Invert ``encrypt``. ``key.d`` is required, and the ciphertext length is ``key.byte_length``.

    Uses CRT decryption when the key holds ``p`` and ``q``, and plain
    ``decrypt_int`` otherwise.
    """
    if key.d is None:
        raise ValueError("decryption needs the private exponent d")
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("ciphertext must be bytes")
    k = key.byte_length
    if len(ciphertext) != k:
        raise ValueError(f"ciphertext must be {k} bytes long")
    cipher_int = int.from_bytes(ciphertext, "big")
    if key.p is not None and key.q is not None:
        plain_int = decrypt_int_crt(cipher_int, key)
    else:
        plain_int = decrypt_int(cipher_int, key.n, key.d)
    return pkcs1_v15_unpad(plain_int.to_bytes(k, "big"))
