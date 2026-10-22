"""AES-CBC, PKCS#7 padding, and text or file helpers.

Week 7–9 work. Every function below raises ``NotImplementedError`` until a
teammate fills it in. The contract is the docstring plus the skipped tests in
``tests/unit/test_modes.py``. Remove the skip marker on a test once the
function it calls is implemented.

``encrypt_cbc`` and ``decrypt_cbc`` do not pad. They operate on whole blocks
so the NIST SP 800-38A vector can be checked directly. ``encrypt_text`` and
``encrypt_file`` apply PKCS#7, then CBC.
"""

from __future__ import annotations


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """Append PKCS#7 padding so ``len(result)`` is a multiple of ``block_size``.

    The padding length ``n`` is in ``1..block_size``, and each padding byte
    equals ``n``. A block that is already a multiple of ``block_size`` still
    gains a full extra block. ``block_size`` must be in ``1..255``.
    """
    raise NotImplementedError("Week 7: PKCS#7 padding is not implemented yet")


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    """Remove PKCS#7 padding. Raise ``ValueError`` when the padding is invalid."""
    raise NotImplementedError("Week 7: PKCS#7 unpadding is not implemented yet")


def encrypt_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """Encrypt with AES-CBC. ``plaintext`` must be a multiple of 16 bytes, and ``iv`` must be 16 bytes.

    ``C_0`` is not emitted. ``C_1 = AES(P_1 XOR iv)`` and
    ``C_i = AES(P_i XOR C_{i-1})``. Raise ``ValueError`` when the lengths are wrong.
    The known-answer test is NIST SP 800-38A appendix F.2.1.
    """
    raise NotImplementedError("Week 7: AES-CBC encryption is not implemented yet")


def decrypt_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Decrypt AES-CBC. Inverse of ``encrypt_cbc``, with no padding removal."""
    raise NotImplementedError("Week 7: AES-CBC decryption is not implemented yet")


def encrypt_text(text: str, key: bytes, iv: bytes) -> bytes:
    """UTF-8 encode ``text``, PKCS#7 pad, then AES-CBC encrypt."""
    raise NotImplementedError("Week 9: text encryption is not implemented yet")


def decrypt_text(ciphertext: bytes, key: bytes, iv: bytes) -> str:
    """AES-CBC decrypt, strip PKCS#7 padding, and UTF-8 decode."""
    raise NotImplementedError("Week 9: text decryption is not implemented yet")


def encrypt_file(data: bytes, key: bytes, iv: bytes) -> bytes:
    """PKCS#7 pad ``data`` and AES-CBC encrypt it. This is the byte-oriented helper."""
    raise NotImplementedError("Week 9: file encryption is not implemented yet")


def decrypt_file(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-CBC decrypt and strip PKCS#7 padding."""
    raise NotImplementedError("Week 9: file decryption is not implemented yet")
