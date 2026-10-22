"""Week 7–9 contract for CBC, PKCS#7, and the text/file helpers.

Every test is skipped until those functions exist. Delete the ``skip`` marker
on a test when you implement the function it calls. Expected CBC bytes are
NIST SP 800-38A appendix F.2.1 and are not produced by our code.
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


@pytest.mark.skip(reason="Week 7: PKCS#7 padding is not implemented yet")
def test_pkcs7_pad_and_unpad():
    assert pkcs7_pad(b"hello", 16) == b"hello" + bytes([11] * 11)
    assert pkcs7_unpad(b"hello" + bytes([11] * 11), 16) == b"hello"
    assert pkcs7_pad(b"", 16) == bytes([16] * 16)
    full_block = bytes(range(16))
    assert pkcs7_pad(full_block, 16) == full_block + bytes([16] * 16)
    with pytest.raises(ValueError):
        pkcs7_unpad(b"hello", 16)


@pytest.mark.skip(reason="Week 7: AES-CBC is not implemented yet")
def test_cbc_nist_sp800_38a_f21():
    assert encrypt_cbc(_CBC_PLAINTEXT, _CBC_KEY, _CBC_IV) == _CBC_CIPHERTEXT
    assert decrypt_cbc(_CBC_CIPHERTEXT, _CBC_KEY, _CBC_IV) == _CBC_PLAINTEXT


@pytest.mark.skip(reason="Week 7: AES-CBC is not implemented yet")
def test_cbc_rejects_a_partial_block():
    with pytest.raises(ValueError):
        encrypt_cbc(b"short", _CBC_KEY, _CBC_IV)


@pytest.mark.skip(reason="Week 9: text and file helpers are not implemented yet")
def test_text_and_file_roundtrip():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    iv = bytes.fromhex("00112233445566778899aabbccddeeff")
    assert decrypt_text(encrypt_text("hi", key, iv), key, iv) == "hi"
    payload = b"\x00\xff binary"
    assert decrypt_file(encrypt_file(payload, key, iv), key, iv) == payload
