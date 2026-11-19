"""Contract and edge-case tests for CBC, PKCS#7, and the text/file helpers.

Expected CBC bytes are NIST SP 800-38A appendix F.2.1.
"""

import pytest

from cryptosystem.aes.modes import (
    decrypt_cbc,
    decrypt_file,
    decrypt_text,
    encrypt_cbc,
    encrypt_file,
    encrypt_text,
    pkcs7_pad,
    pkcs7_unpad,
)

_CBC_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
_CBC_IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
_CBC_PLAINTEXT = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
)
_CBC_CIPHERTEXT = bytes.fromhex(
    "7649abac8119b246cee98e9b12e9197d"
    "5086cb9b507219ee95db113a917678b2"
    "73bed6b8e3c1743b7116e69e22229516"
    "3ff1caa1681fac09120eca307586e1a7"
)


def test_pkcs7_pad_and_unpad():
    assert pkcs7_pad(b"hello", 16) == b"hello" + bytes([11] * 11)
    assert pkcs7_unpad(b"hello" + bytes([11] * 11), 16) == b"hello"
    assert pkcs7_pad(b"", 16) == bytes([16] * 16)
    full_block = bytes(range(16))
    assert pkcs7_pad(full_block, 16) == full_block + bytes([16] * 16)
    with pytest.raises(ValueError):
        pkcs7_unpad(b"hello", 16)


def test_pkcs7_invalid_padding_rejected():
    with pytest.raises(ValueError):
        pkcs7_unpad(b"", 16)
    with pytest.raises(ValueError):
        pkcs7_unpad(b"\x00" * 16, 16)
    with pytest.raises(ValueError):
        pkcs7_unpad(b"a" * 15 + b"\x11", 16)
    with pytest.raises(ValueError):
        pkcs7_unpad(b"a" * 14 + b"\x01\x02", 16)
    with pytest.raises(ValueError):
        pkcs7_pad(b"abc", 0)
    with pytest.raises(ValueError):
        pkcs7_pad(b"abc", 256)


def test_cbc_nist_sp800_38a_f21():
    assert encrypt_cbc(_CBC_PLAINTEXT, _CBC_KEY, _CBC_IV) == _CBC_CIPHERTEXT
    assert decrypt_cbc(_CBC_CIPHERTEXT, _CBC_KEY, _CBC_IV) == _CBC_PLAINTEXT


def test_cbc_rejects_a_partial_block_and_bad_iv():
    with pytest.raises(ValueError):
        encrypt_cbc(b"short", _CBC_KEY, _CBC_IV)
    with pytest.raises(ValueError):
        decrypt_cbc(b"short", _CBC_KEY, _CBC_IV)
    with pytest.raises(ValueError):
        encrypt_cbc(_CBC_PLAINTEXT, _CBC_KEY, b"bad_iv")


def test_text_and_file_roundtrip():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    iv = bytes.fromhex("00112233445566778899aabbccddeeff")
    assert decrypt_text(encrypt_text("hi", key, iv), key, iv) == "hi"
    assert decrypt_text(encrypt_text("", key, iv), key, iv) == ""
    assert decrypt_text(encrypt_text("សួស្តី 🔐", key, iv), key, iv) == "សួស្តី 🔐"
    payload = b"\x00\xff binary"
    assert decrypt_file(encrypt_file(payload, key, iv), key, iv) == payload
    assert decrypt_file(encrypt_file(b"", key, iv), key, iv) == b""


def test_aes_192_and_256_cbc_roundtrip():
    iv = bytes(range(16))
    for key_len in (24, 32):
        key = bytes(range(key_len))
        assert decrypt_text(encrypt_text("AES-192/256 test", key, iv), key, iv) == "AES-192/256 test"
        data = b"block" * 7
        assert decrypt_file(encrypt_file(data, key, iv), key, iv) == data
