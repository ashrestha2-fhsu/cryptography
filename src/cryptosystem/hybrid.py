"""Hybrid encryption: RSA wraps an AES-128 session key, AES-CBC carries the message.

Week 13 work. ``HybridPackage`` is the record the GUI and the system test
already share. ``encrypt`` and ``decrypt`` still raise ``NotImplementedError``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from cryptosystem.rsa.rsa import RSAKey

Rng = Callable[[int], bytes]


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


def encrypt(plaintext: bytes, public_key: RSAKey, rng: Rng | None = None) -> HybridPackage:
    """Encrypt ``plaintext`` for the holder of ``public_key``.

    Draw a fresh 16-byte AES key and a fresh 16-byte IV with ``rng``
    (default ``secrets.token_bytes``). Encrypt the plaintext with
    ``encrypt_file`` (PKCS#7 then AES-CBC). Encrypt the AES key with
    ``cryptosystem.rsa.encrypt``. Store all three values as lowercase hex.
    """
    raise NotImplementedError("Week 13: hybrid encryption is not implemented yet")


def decrypt(package: HybridPackage, private_key: RSAKey) -> bytes:
    """Recover the plaintext from ``package`` using ``private_key``.

    Parse the hex fields, RSA-decrypt the session key, then AES-CBC decrypt
    and strip PKCS#7 padding. Raise ``ValueError`` for odd-length hex or a
    session key that is not 16 bytes.
    """
    raise NotImplementedError("Week 13: hybrid decryption is not implemented yet")
