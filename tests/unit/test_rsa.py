"""Week 11 contract for RSA key generation and encryption.

Skipped until ``cryptosystem.rsa.rsa`` is implemented. The integer vector is
the usual textbook example and does not depend on prime generation:

    p = 61, q = 53, n = 3233, e = 17, d = 2753, message = 65, cipher = 2790
"""

import pytest

from cryptosystem.rsa.number_theory import modinv
from cryptosystem.rsa.rsa import (
    RSAKey,
    decrypt,
    decrypt_int,
    encrypt,
    encrypt_int,
    generate_keypair,
    generate_prime,
    is_probable_prime,
    pkcs1_v15_pad,
    pkcs1_v15_unpad,
)

_P = 61
_Q = 53
_N = _P * _Q
_E = 17
_D = 2753
_MESSAGE = 65
_CIPHER = 2790


@pytest.mark.skip(reason="Week 11: Miller-Rabin and prime generation are not implemented yet")
def test_primality_and_prime_generation():
    assert is_probable_prime(2) is True
    assert is_probable_prime(_P) is True
    assert is_probable_prime(1) is False
    assert is_probable_prime(_N) is False
    prime = generate_prime(32)
    assert prime.bit_length() == 32
    assert is_probable_prime(prime) is True


@pytest.mark.skip(reason="Week 11: RSA integer encrypt and decrypt are not implemented yet")
def test_textbook_integer_roundtrip():
    assert encrypt_int(_MESSAGE, _N, _E) == _CIPHER
    assert decrypt_int(_CIPHER, _N, _D) == _MESSAGE
    with pytest.raises(ValueError):
        encrypt_int(_N, _N, _E)


@pytest.mark.skip(reason="Week 11: PKCS#1 v1.5 padding is not implemented yet")
def test_pkcs1_v15_pad_format():
    message = bytes(range(16))
    encoded = pkcs1_v15_pad(message, k=128, rng=lambda n: b"\x01" * n)
    assert len(encoded) == 128
    assert encoded[0:2] == b"\x00\x02"
    assert encoded.endswith(b"\x00" + message)
    assert pkcs1_v15_unpad(encoded) == message


@pytest.mark.skip(reason="Week 11: RSA key generation is not implemented yet")
def test_generate_keypair_uses_euler_totient_and_roundtrips():
    key = generate_keypair(bits=256)
    assert key.e == 65537
    assert key.p is not None and key.q is not None and key.d is not None
    assert key.p.bit_length() == 128
    assert key.q.bit_length() == 128
    assert key.n == key.p * key.q
    assert 255 <= key.n.bit_length() <= 256
    phi = (key.p - 1) * (key.q - 1)
    assert modinv(key.e, phi) == key.d
    message = b"aes-key-16bytes!"
    assert decrypt(encrypt(message, key), key) == message


def test_rsakey_byte_length_for_the_textbook_modulus():
    key = RSAKey(n=_N, e=_E, d=_D, p=_P, q=_Q)
    assert key.byte_length == 2
