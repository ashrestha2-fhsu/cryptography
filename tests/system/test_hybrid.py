"""Whole-system tests for the hybrid cryptosystem.

The course demo:

1. Generate an RSA key pair.
2. Hybrid-encrypt a short message. RSA (PKCS#1 v1.5) wraps a random
   AES-128 session key, and AES-CBC with PKCS#7 encrypts the message.
3. The package exposes lowercase hex fields ``wrapped_key``, ``iv``, and
   ``ciphertext``.
4. Hybrid-decrypt with the same private key and recover the original bytes.
"""

import pytest

from cryptosystem.hybrid import HybridPackage, decrypt, encrypt
from cryptosystem.rsa.rsa import RSAKey, encrypt as rsa_encrypt
from cryptosystem.rsa.rsa import generate_keypair


def test_hybrid_roundtrip_and_package_shape():
    key = generate_keypair(bits=1024)
    package = encrypt(b"hybrid encryption demo", key)
    assert package.wrapped_key == package.wrapped_key.lower()
    assert package.iv == package.iv.lower()
    assert package.ciphertext == package.ciphertext.lower()
    assert len(bytes.fromhex(package.iv)) == 16
    assert len(bytes.fromhex(package.ciphertext)) % 16 == 0
    assert len(package.wrapped_key) == key.byte_length * 2
    assert decrypt(package, key) == b"hybrid encryption demo"
    assert set(package.to_dict()) == {"wrapped_key", "iv", "ciphertext"}


def test_hybrid_rng_is_deterministic_and_empty_plaintext_roundtrips():
    key = generate_keypair(bits=256)

    def rng(size: int) -> bytes:
        return b"\x11" * size

    first = encrypt(b"", key, rng)
    second = encrypt(b"", key, rng)
    assert first == second
    assert decrypt(first, key) == b""


def test_encrypt_rejects_a_modulus_too_small_to_wrap_the_session_key():
    textbook = RSAKey(n=3233, e=17, d=2753, p=61, q=53)
    with pytest.raises(ValueError):
        encrypt(b"hi", textbook)


def test_decrypt_rejects_odd_length_hex_and_a_short_session_key():
    key = generate_keypair(bits=256)
    odd = HybridPackage(wrapped_key="abc", iv="00" * 16, ciphertext="00" * 16)
    with pytest.raises(ValueError):
        decrypt(odd, key)

    wrapped = rsa_encrypt(b"short", key)
    package = HybridPackage(
        wrapped_key=wrapped.hex(),
        iv="00" * 16,
        ciphertext="00" * 16,
    )
    with pytest.raises(ValueError, match="16 bytes"):
        decrypt(package, key)
