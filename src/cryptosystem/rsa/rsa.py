"""RSA key generation and encryption.

Week 11 work, except ``RSAKey``, which is the shared record the rest of the
program already imports. Implement the functions against
``tests/unit/test_rsa.py`` and use ``modexp`` / ``modinv`` from
``cryptosystem.rsa.number_theory``. Do not call an external crypto library.

The integer API is textbook RSA. The byte API wraps a message in PKCS#1 v1.5
(block type 2) before that exponentiation, which is what the hybrid scheme
needs in order to hide a 16-byte AES key.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


Rng = Callable[[int], bytes]


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


def is_probable_prime(n: int, rounds: int = 40, rng: Rng | None = None) -> bool:
    """Miller-Rabin primality test.

    Return ``False`` for ``n < 2`` and for every even ``n`` other than 2.
    Write ``n - 1 = 2^s * d`` with ``d`` odd. For each of ``rounds`` random
    bases ``a`` in ``2..n-2`` (use ``rng`` when given; otherwise
    ``secrets.token_bytes``), compute ``x = modexp(a, d, n)``. The base passes
    when ``x`` is 1 or ``n - 1``, or when squaring ``x`` reaches ``n - 1``
    within ``s - 1`` squarings. Otherwise ``n`` is composite.

    ``rounds`` defaults to 40. A deterministic witness set is not required.
    """
    raise NotImplementedError("Week 11: Miller-Rabin is not implemented yet")


def generate_prime(bits: int, rng: Rng | None = None) -> int:
    """Return a probable prime whose bit length is exactly ``bits``.

    Set the top bit so the integer has ``bits`` bits, and set the bottom bit
    so it is odd. Draw candidates with ``rng`` (default ``secrets.token_bytes``)
    and accept the first one for which ``is_probable_prime`` returns true.
    ``bits`` must be at least 2.
    """
    raise NotImplementedError("Week 11: prime generation is not implemented yet")


def generate_keypair(bits: int = 1024, e: int = 65537, rng: Rng | None = None) -> RSAKey:
    """Build a key pair whose modulus has about ``bits`` bits.

    ``bits`` must be even and at least 32. Draw distinct primes ``p`` and ``q``
    of ``bits // 2`` bits each, retrying while ``gcd(e, (p - 1) * (q - 1))``
    is not 1 or ``p == q``. The private exponent is the Euler-totient inverse

        d = modinv(e, (p - 1) * (q - 1))

    not the Carmichael-lambda inverse. Return ``RSAKey(n=p*q, e=e, d=d, p=p, q=q)``.
    The demo GUI asks for 1024 bits. Unit tests may use a smaller even size.
    """
    raise NotImplementedError("Week 11: RSA key generation is not implemented yet")


def encrypt_int(message: int, n: int, e: int) -> int:
    """Textbook RSA: ``modexp(message, e, n)``.

    Require ``0 <= message < n``. The Week 11 test vector is ``p = 61``,
    ``q = 53``, ``n = 3233``, ``e = 17``, message ``65``, ciphertext ``2790``.
    """
    raise NotImplementedError("Week 11: RSA integer encryption is not implemented yet")


def decrypt_int(ciphertext: int, n: int, d: int) -> int:
    """Textbook RSA: ``modexp(ciphertext, d, n)``. Require ``0 <= ciphertext < n``."""
    raise NotImplementedError("Week 11: RSA integer decryption is not implemented yet")


def pkcs1_v15_pad(message: bytes, k: int, rng: Rng | None = None) -> bytes:
    """PKCS#1 v1.5 block type 2, RFC 8017 section 7.2.1.

    ``EM = 0x00 || 0x02 || PS || 0x00 || M`` with ``len(EM) == k`` and
    ``len(PS) = k - len(message) - 3 >= 8``. Every byte of ``PS`` is nonzero.
    ``rng(n)`` returns ``n`` random bytes and defaults to ``secrets.token_bytes``.
    Replace any zero drawn for ``PS``. Raise ``ValueError`` when the message
    is longer than ``k - 11`` bytes.
    """
    raise NotImplementedError("Week 11: PKCS#1 v1.5 padding is not implemented yet")


def pkcs1_v15_unpad(encoded: bytes) -> bytes:
    """Strip PKCS#1 v1.5 block type 2 padding.

    Require a leading ``0x00 0x02``, at least eight nonzero padding bytes, and
    a ``0x00`` separator. Raise ``ValueError`` when the block is malformed.
    """
    raise NotImplementedError("Week 11: PKCS#1 v1.5 unpadding is not implemented yet")


def encrypt(message: bytes, key: RSAKey, rng: Rng | None = None) -> bytes:
    """Pad ``message`` to ``key.byte_length`` bytes, then textbook-encrypt it.

    Return the ciphertext as a big-endian byte string of that same length.
    """
    raise NotImplementedError("Week 11: RSA byte encryption is not implemented yet")


def decrypt(ciphertext: bytes, key: RSAKey) -> bytes:
    """Invert ``encrypt``. ``key.d`` is required, and the ciphertext length is ``key.byte_length``."""
    raise NotImplementedError("Week 11: RSA byte decryption is not implemented yet")
