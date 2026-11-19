"""Hybrid encryption: RSA wraps an AES-128 session key, AES-CBC carries the message.

Author: Adarsha Shrestha (Week 13).

``encrypt`` draws a fresh 16-byte AES key and IV, encrypts the message with
``encrypt_file`` (PKCS#7 then AES-CBC), and wraps the AES key with
``cryptosystem.rsa.encrypt`` (PKCS#1 v1.5). ``decrypt`` reverses those steps.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Callable

from cryptosystem.aes.modes import decrypt_file, encrypt_file
from cryptosystem.rsa.rsa import RSAKey
from cryptosystem.rsa.rsa import decrypt as rsa_decrypt
from cryptosystem.rsa.rsa import encrypt as rsa_encrypt

Rng = Callable[[int], bytes]

# PKCS#1 v1.5 needs 11 bytes of overhead around the 16-byte AES key.
_MIN_MODULUS_BYTES = 27


@dataclass(frozen=True)
class HybridPackage:
    """One hybrid ciphertext, with every field encoded as lowercase hex.

    ``wrapped_key`` is the RSA-encrypted 16-byte AES key (PKCS#1 v1.5).
    ``iv`` is 16 bytes, so its hex form is 32 characters.
    ``ciphertext`` is the PKCS#7-padded AES-CBC encryption of the plaintext.
    """

    wrapped_key: str
    iv: str
    ciphertext: str

    def to_dict(self) -> dict[str, str]:
        """Return the three hex fields for display or JSON."""
        return {
            "wrapped_key": self.wrapped_key,
            "iv": self.iv,
            "ciphertext": self.ciphertext,
        }


def _draw(rng: Rng, size: int) -> bytes:
    """Read exactly ``size`` bytes from ``rng``."""
    material = rng(size)
    if not isinstance(material, (bytes, bytearray)) or len(material) != size:
        raise ValueError(f"rng must return exactly {size} bytes")
    return bytes(material)


def _parse_hex(value: str, name: str) -> bytes:
    """Decode one hex field. Raise ``ValueError`` when the length is odd or the text is not hex."""
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a hex string")
    cleaned = "".join(value.split())
    if len(cleaned) % 2 != 0:
        raise ValueError(f"{name} hex length must be even")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError(f"{name} must be hexadecimal") from exc


def encrypt(plaintext: bytes, public_key: RSAKey, rng: Rng | None = None) -> HybridPackage:
    """Encrypt ``plaintext`` for the holder of ``public_key``.

    Draw a fresh 16-byte AES key and a fresh 16-byte IV with ``rng``
    (default ``secrets.token_bytes``). The same ``rng`` is then used for the
    PKCS#1 padding around the session key. Encrypt the plaintext with
    ``encrypt_file`` (PKCS#7 then AES-CBC). Store all three values as
    lowercase hex.

    The modulus must be at least 27 bytes so PKCS#1 v1.5 can wrap a 16-byte
    AES key. A 512-bit or larger key is the right size for the demo.
    """
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext must be bytes")
    if not isinstance(public_key, RSAKey):
        raise TypeError("public_key must be an RSAKey")
    if public_key.byte_length < _MIN_MODULUS_BYTES:
        raise ValueError(
            "RSA modulus is too small to wrap a 16-byte AES key "
            f"(need at least {_MIN_MODULUS_BYTES} bytes)"
        )

    source = rng or secrets.token_bytes
    aes_key = _draw(source, 16)
    iv = _draw(source, 16)
    ciphertext = encrypt_file(bytes(plaintext), aes_key, iv)
    wrapped = rsa_encrypt(aes_key, public_key, source)
    return HybridPackage(
        wrapped_key=wrapped.hex(),
        iv=iv.hex(),
        ciphertext=ciphertext.hex(),
    )


def decrypt(package: HybridPackage, private_key: RSAKey) -> bytes:
    """Recover the plaintext from ``package`` using ``private_key``.

    Parse the hex fields, RSA-decrypt the session key, then AES-CBC decrypt
    and strip PKCS#7 padding. Raise ``ValueError`` for odd-length hex or a
    session key that is not 16 bytes.
    """
    if not isinstance(package, HybridPackage):
        raise TypeError("package must be a HybridPackage")
    if not isinstance(private_key, RSAKey):
        raise TypeError("private_key must be an RSAKey")

    wrapped = _parse_hex(package.wrapped_key, "wrapped_key")
    iv = _parse_hex(package.iv, "iv")
    ciphertext = _parse_hex(package.ciphertext, "ciphertext")
    if len(iv) != 16:
        raise ValueError("iv must be 16 bytes")

    aes_key = rsa_decrypt(wrapped, private_key)
    if len(aes_key) != 16:
        raise ValueError("session key must be 16 bytes")
    return decrypt_file(ciphertext, aes_key, iv)
