"""Week 11 contract for RSA key generation and encryption.

Active since Week 11 (RSA scheme by Pichponleur Pen). The integer vector is
the usual textbook example and does not depend on prime generation:

    p = 61, q = 53, n = 3233, e = 17, d = 2753, message = 65, cipher = 2790
"""

import pytest

from cryptosystem.rsa.number_theory import modinv
from cryptosystem.rsa.rsa import (
    RSAKey,
    decrypt,
    decrypt_int,
    decrypt_int_crt,
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


def test_primality_and_prime_generation():
    assert is_probable_prime(2) is True
    assert is_probable_prime(_P) is True
    assert is_probable_prime(1) is False
    assert is_probable_prime(_N) is False
    prime = generate_prime(32)
    assert prime.bit_length() == 32
    assert is_probable_prime(prime) is True


def test_textbook_integer_roundtrip():
    assert encrypt_int(_MESSAGE, _N, _E) == _CIPHER
    assert decrypt_int(_CIPHER, _N, _D) == _MESSAGE
    with pytest.raises(ValueError):
        encrypt_int(_N, _N, _E)


def test_pkcs1_v15_pad_format():
    message = bytes(range(16))
    encoded = pkcs1_v15_pad(message, k=128, rng=lambda n: b"\x01" * n)
    assert len(encoded) == 128
    assert encoded[0:2] == b"\x00\x02"
    assert encoded.endswith(b"\x00" + message)
    assert pkcs1_v15_unpad(encoded) == message


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


# Additional Week 11 checks. Author: Pichponleur Pen


def test_miller_rabin_on_known_primes_and_composites():
    assert is_probable_prime(3) is True
    assert is_probable_prime(4) is False
    assert is_probable_prime(7919) is True  # the 1000th prime
    assert is_probable_prime(2**127 - 1) is True  # Mersenne prime
    assert is_probable_prime(561) is False  # Carmichael number, fools Fermat
    assert is_probable_prime(41041) is False  # Carmichael number
    assert is_probable_prime((2**61 - 1) * (2**31 - 1)) is False


def test_crt_decryption_matches_textbook_decryption():
    key = RSAKey(n=_N, e=_E, d=_D, p=_P, q=_Q)
    assert decrypt_int_crt(_CIPHER, key) == _MESSAGE
    for message in (0, 1, 2, 1000, _N - 1):
        cipher = encrypt_int(message, _N, _E)
        assert decrypt_int_crt(cipher, key) == decrypt_int(cipher, _N, _D) == message


def test_pkcs1_v15_rejects_long_messages_and_malformed_blocks():
    with pytest.raises(ValueError):
        pkcs1_v15_pad(bytes(118), k=128)  # k - 11 = 117 is the limit
    assert len(pkcs1_v15_pad(bytes(117), k=128)) == 128
    good = pkcs1_v15_pad(b"key", k=32, rng=lambda n: b"\x07" * n)
    with pytest.raises(ValueError):
        pkcs1_v15_unpad(b"\x00\x01" + good[2:])  # wrong block type
    with pytest.raises(ValueError):
        pkcs1_v15_unpad(good.replace(b"\x00key", b"\x07key"))  # no separator
    with pytest.raises(ValueError):
        pkcs1_v15_unpad(b"\x00\x02" + b"\x07" * 7 + b"\x00" + b"key" + bytes(19))


def test_padding_bytes_are_nonzero_even_when_rng_returns_zeros():
    draws = iter([bytes(20), b"\x00", b"\x09"] + [b"\x05"] * 40)
    encoded = pkcs1_v15_pad(b"m", k=24, rng=lambda n: next(draws)[:n].ljust(n, b"\x05"))
    padding = encoded[2:-2]
    assert len(padding) == 20
    assert 0 not in padding
    assert pkcs1_v15_unpad(encoded) == b"m"


def test_byte_encryption_is_randomized_and_checks_lengths():
    key = generate_keypair(bits=512)
    message = b"sixteen byte key"
    first = encrypt(message, key)
    second = encrypt(message, key)
    assert len(first) == len(second) == key.byte_length
    assert first != second  # fresh random padding each time
    assert decrypt(first, key) == decrypt(second, key) == message
    public_only = RSAKey(n=key.n, e=key.e)
    with pytest.raises(ValueError):
        decrypt(first, public_only)
    with pytest.raises(ValueError):
        decrypt(first[1:], key)
    without_factors = RSAKey(n=key.n, e=key.e, d=key.d)
    assert decrypt(first, without_factors) == message  # non-CRT path


def test_generate_keypair_rejects_bad_sizes():
    with pytest.raises(ValueError):
        generate_keypair(bits=31)
    with pytest.raises(ValueError):
        generate_keypair(bits=16)
    with pytest.raises(ValueError):
        generate_keypair(bits=64, e=4)
