"""AES round transformations on a 16-byte state.

Bytes are stored in FIPS-197 input order: the byte at row ``r`` and column
``c`` lives at index ``r + 4 * c``. A 16-byte block from a caller is already
in that order, so no transpose is required at the cipher boundary.
"""

from __future__ import annotations

from cryptosystem.aes.field import gf_mul
from cryptosystem.aes.sbox import inv_sbox_lookup, sbox_lookup


def _as_state(state: bytes | bytearray) -> bytes:
    if not isinstance(state, (bytes, bytearray)) or len(state) != 16:
        raise ValueError("AES state must be 16 bytes")
    return bytes(state)


def sub_bytes(state: bytes | bytearray) -> bytes:
    """Apply the S-box to every byte. FIPS-197 section 5.1.1."""
    return bytes(sbox_lookup(byte) for byte in _as_state(state))


def inv_sub_bytes(state: bytes | bytearray) -> bytes:
    """Apply the inverse S-box to every byte. FIPS-197 section 5.3.2."""
    return bytes(inv_sbox_lookup(byte) for byte in _as_state(state))


def shift_rows(state: bytes | bytearray) -> bytes:
    """Rotate row ``r`` left by ``r`` bytes. FIPS-197 section 5.1.2."""
    state = _as_state(state)
    out = bytearray(16)
    for row in range(4):
        for col in range(4):
            out[row + 4 * col] = state[row + 4 * ((col + row) % 4)]
    return bytes(out)


def inv_shift_rows(state: bytes | bytearray) -> bytes:
    """Rotate row ``r`` right by ``r`` bytes. FIPS-197 section 5.3.1."""
    state = _as_state(state)
    out = bytearray(16)
    for row in range(4):
        for col in range(4):
            out[row + 4 * col] = state[row + 4 * ((col - row) % 4)]
    return bytes(out)


def mix_columns(state: bytes | bytearray) -> bytes:
    """Mix each column by the fixed AES polynomial. FIPS-197 section 5.1.3.

    The column polynomial is multiplied by ``{03}x^3 + {01}x^2 + {01}x + {02}``
    modulo ``x^4 + 1``.
    """
    state = _as_state(state)
    out = bytearray(16)
    for col in range(4):
        a = state[4 * col]
        b = state[4 * col + 1]
        c = state[4 * col + 2]
        d = state[4 * col + 3]
        out[4 * col] = gf_mul(a, 2) ^ gf_mul(b, 3) ^ c ^ d
        out[4 * col + 1] = a ^ gf_mul(b, 2) ^ gf_mul(c, 3) ^ d
        out[4 * col + 2] = a ^ b ^ gf_mul(c, 2) ^ gf_mul(d, 3)
        out[4 * col + 3] = gf_mul(a, 3) ^ b ^ c ^ gf_mul(d, 2)
    return bytes(out)


def inv_mix_columns(state: bytes | bytearray) -> bytes:
    """Invert MixColumns. FIPS-197 section 5.3.3.

    The inverse polynomial is ``{0b}x^3 + {0d}x^2 + {09}x + {0e}``.
    """
    state = _as_state(state)
    out = bytearray(16)
    for col in range(4):
        a = state[4 * col]
        b = state[4 * col + 1]
        c = state[4 * col + 2]
        d = state[4 * col + 3]
        out[4 * col] = (
            gf_mul(a, 0x0E) ^ gf_mul(b, 0x0B) ^ gf_mul(c, 0x0D) ^ gf_mul(d, 0x09)
        )
        out[4 * col + 1] = (
            gf_mul(a, 0x09) ^ gf_mul(b, 0x0E) ^ gf_mul(c, 0x0B) ^ gf_mul(d, 0x0D)
        )
        out[4 * col + 2] = (
            gf_mul(a, 0x0D) ^ gf_mul(b, 0x09) ^ gf_mul(c, 0x0E) ^ gf_mul(d, 0x0B)
        )
        out[4 * col + 3] = (
            gf_mul(a, 0x0B) ^ gf_mul(b, 0x0D) ^ gf_mul(c, 0x09) ^ gf_mul(d, 0x0E)
        )
    return bytes(out)


def add_round_key(state: bytes | bytearray, round_key: bytes | bytearray) -> bytes:
    """XOR the state with a 16-byte round key. FIPS-197 section 5.1.4."""
    state = _as_state(state)
    if not isinstance(round_key, (bytes, bytearray)) or len(round_key) != 16:
        raise ValueError("round key must be 16 bytes")
    return bytes(left ^ right for left, right in zip(state, round_key))
