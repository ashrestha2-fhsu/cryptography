"""AES S-box, derived from the field inverse and the FIPS-197 affine map.

FIPS-197 section 5.1.1 defines SubBytes as an affine transformation of the
multiplicative inverse in GF(2^8), not as a table that has to be copied in.
The derived table is cached. ``tests/unit/test_sbox.py`` checks it against
the first row of Figure 7.
"""

from __future__ import annotations

from cryptosystem.aes.field import gf_inv

# Constant vector c in the affine map. Bit 0 is the least significant bit.
_AFFINE_CONSTANT = 0x63


def _affine(value: int) -> int:
    """Map one byte through b'_i = b_i + b_{i+4} + b_{i+5} + b_{i+6} + b_{i+7} + c_i."""
    result = 0
    for index in range(8):
        bit = (
            (value >> index)
            ^ (value >> ((index + 4) % 8))
            ^ (value >> ((index + 5) % 8))
            ^ (value >> ((index + 6) % 8))
            ^ (value >> ((index + 7) % 8))
            ^ (_AFFINE_CONSTANT >> index)
        ) & 1
        result |= bit << index
    return result


def _build_tables() -> tuple[bytes, bytes]:
    sbox = bytearray(_affine(gf_inv(value)) for value in range(256))
    inverse = bytearray(256)
    for value, mapped in enumerate(sbox):
        inverse[mapped] = value
    return bytes(sbox), bytes(inverse)


SBOX, INV_SBOX = _build_tables()


def sbox_lookup(byte: int) -> int:
    """Return the AES S-box image of one byte."""
    if not isinstance(byte, int) or isinstance(byte, bool) or not 0 <= byte <= 0xFF:
        raise ValueError("sbox_lookup expects a byte (0..255)")
    return SBOX[byte]


def inv_sbox_lookup(byte: int) -> int:
    """Return the inverse AES S-box image of one byte."""
    if not isinstance(byte, int) or isinstance(byte, bool) or not 0 <= byte <= 0xFF:
        raise ValueError("inv_sbox_lookup expects a byte (0..255)")
    return INV_SBOX[byte]
