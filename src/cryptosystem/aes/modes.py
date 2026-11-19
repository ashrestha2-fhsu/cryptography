"""AES-CBC, PKCS#7 padding, and text or file helpers.

``encrypt_cbc`` and ``decrypt_cbc`` do not pad. They operate on whole blocks
so the NIST SP 800-38A vector can be checked directly. ``encrypt_text`` and
``encrypt_file`` apply PKCS#7, then CBC.
"""

from __future__ import annotations

from cryptosystem.aes.cipher import decrypt_block, encrypt_block


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two equal-length byte strings."""
    return bytes(x ^ y for x, y in zip(a, b))


def _validate_block_size(block_size: int) -> None:
    if not isinstance(block_size, int) or not (1 <= block_size <= 255):
        raise ValueError("block_size must be an integer in 1..255")


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """Append PKCS#7 padding so ``len(result)`` is a multiple of ``block_size``.

    The padding length ``n`` is in ``1..block_size``, and each padding byte
    equals ``n``. A block that is already a multiple of ``block_size`` still
    gains a full extra block. ``block_size`` must be in ``1..255``.
    """
    _validate_block_size(block_size)
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes")
    pad_len = block_size - (len(data) % block_size)
    return bytes(data) + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    """Remove PKCS#7 padding. Raise ``ValueError`` when the padding is invalid."""
    _validate_block_size(block_size)
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes")
    if len(data) == 0 or len(data) % block_size != 0:
        raise ValueError("data length must be a non-zero multiple of block_size")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("invalid PKCS#7 padding length")
    if bytes(data[-pad_len:]) != bytes([pad_len] * pad_len):
        raise ValueError("invalid PKCS#7 padding bytes")
    return bytes(data[:-pad_len])


def encrypt_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """Encrypt with AES-CBC. ``plaintext`` must be a multiple of 16 bytes, and ``iv`` must be 16 bytes.

    ``C_0`` is not emitted. ``C_1 = AES(P_1 XOR iv)`` and
    ``C_i = AES(P_i XOR C_{i-1})``. Raise ``ValueError`` when the lengths are wrong.
    The known-answer test is NIST SP 800-38A appendix F.2.1.
    """
    if not isinstance(iv, (bytes, bytearray)) or len(iv) != 16:
        raise ValueError("iv must be 16 bytes")
    if not isinstance(plaintext, (bytes, bytearray)) or len(plaintext) % 16 != 0:
        raise ValueError("plaintext length must be a multiple of 16 bytes")

    prev = bytes(iv)
    out = bytearray()
    for offset in range(0, len(plaintext), 16):
        block = bytes(plaintext[offset : offset + 16])
        cipher_block = encrypt_block(_xor_bytes(block, prev), key)
        out.extend(cipher_block)
        prev = cipher_block
    return bytes(out)


def decrypt_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Decrypt AES-CBC. Inverse of ``encrypt_cbc``, with no padding removal."""
    if not isinstance(iv, (bytes, bytearray)) or len(iv) != 16:
        raise ValueError("iv must be 16 bytes")
    if not isinstance(ciphertext, (bytes, bytearray)) or len(ciphertext) % 16 != 0:
        raise ValueError("ciphertext length must be a multiple of 16 bytes")

    prev = bytes(iv)
    out = bytearray()
    for offset in range(0, len(ciphertext), 16):
        block = bytes(ciphertext[offset : offset + 16])
        plain_block = _xor_bytes(decrypt_block(block, key), prev)
        out.extend(plain_block)
        prev = block
    return bytes(out)


def encrypt_text(text: str, key: bytes, iv: bytes) -> bytes:
    """UTF-8 encode ``text``, PKCS#7 pad, then AES-CBC encrypt."""
    if not isinstance(text, str):
        raise TypeError("text must be a str")
    return encrypt_cbc(pkcs7_pad(text.encode("utf-8"), 16), key, iv)


def decrypt_text(ciphertext: bytes, key: bytes, iv: bytes) -> str:
    """AES-CBC decrypt, strip PKCS#7 padding, and UTF-8 decode."""
    return pkcs7_unpad(decrypt_cbc(ciphertext, key, iv), 16).decode("utf-8")


def encrypt_file(data: bytes, key: bytes, iv: bytes) -> bytes:
    """PKCS#7 pad ``data`` and AES-CBC encrypt it. This is the byte-oriented helper."""
    return encrypt_cbc(pkcs7_pad(data, 16), key, iv)


def decrypt_file(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-CBC decrypt and strip PKCS#7 padding."""
    return pkcs7_unpad(decrypt_cbc(ciphertext, key, iv), 16)
