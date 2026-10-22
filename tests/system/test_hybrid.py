"""Whole-system test structure for the hybrid cryptosystem.

Week 3 requires this file before the hybrid functions exist, so the test is
skipped. Week 13 removes the skip. The scenario is the course demo:

1. Generate a 1024-bit RSA key pair.
2. Hybrid-encrypt a short UTF-8 message. RSA (PKCS#1 v1.5) wraps a random
   AES-128 session key, and AES-CBC with PKCS#7 encrypts the message.
3. The package exposes lowercase hex fields ``wrapped_key``, ``iv``, and
   ``ciphertext``.
4. Hybrid-decrypt with the same private key and recover the original bytes.
"""

import pytest

from cryptosystem.hybrid import decrypt, encrypt
from cryptosystem.rsa.rsa import generate_keypair


@pytest.mark.skip(reason="Week 13: hybrid encrypt and decrypt are not implemented yet")
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
