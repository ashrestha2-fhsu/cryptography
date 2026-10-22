"""Single-block AES encryption and decryption.

FIPS-197 sections 5.1 and 5.3. CBC, PKCS#7 padding, and string helpers are
Week 7 work in ``cryptosystem.aes.modes``.
"""

from __future__ import annotations

from cryptosystem.aes.key_schedule import expand_key, rounds_for_nk
from cryptosystem.aes.rounds import (
    add_round_key,
    inv_mix_columns,
    inv_shift_rows,
    inv_sub_bytes,
    mix_columns,
    shift_rows,
    sub_bytes,
)


def _as_block(block: bytes | bytearray, name: str) -> bytes:
    if not isinstance(block, (bytes, bytearray)) or len(block) != 16:
        raise ValueError(f"{name} must be 16 bytes")
    return bytes(block)


def _prepare_key(key: bytes | bytearray) -> tuple[bytes, int, int]:
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("AES key must be bytes")
    key_bytes = bytes(key)
    if len(key_bytes) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes")
    nk = len(key_bytes) // 4
    return key_bytes, nk, rounds_for_nk(nk)


def encrypt_block(plaintext: bytes | bytearray, key: bytes | bytearray) -> bytes:
    """Encrypt one 16-byte block.

    ``key`` is 16 bytes for AES-128, the size this course tests. 24-byte and
    32-byte keys are accepted by the same schedule. The last round omits
    MixColumns.
    """
    plaintext = _as_block(plaintext, "plaintext")
    key_bytes, nk, nr = _prepare_key(key)
    round_keys = expand_key(key_bytes, nk)

    state = add_round_key(plaintext, round_keys[0])
    for round_index in range(1, nr):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[round_index])
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[nr])
    return state


def decrypt_block(ciphertext: bytes | bytearray, key: bytes | bytearray) -> bytes:
    """Decrypt one 16-byte block. Inverse of ``encrypt_block``.

    This is the equivalent inverse cipher from FIPS-197 section 5.3: the round
    keys are the encryption round keys, and InvMixColumns is applied to the
    state rather than to those keys.
    """
    ciphertext = _as_block(ciphertext, "ciphertext")
    key_bytes, nk, nr = _prepare_key(key)
    round_keys = expand_key(key_bytes, nk)

    state = add_round_key(ciphertext, round_keys[nr])
    for round_index in range(nr - 1, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_keys[round_index])
        state = inv_mix_columns(state)
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])
    return state
