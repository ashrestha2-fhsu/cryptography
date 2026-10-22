"""AES key expansion. FIPS-197 section 5.2.

``Nk`` is the key length in 32-bit words: 4, 6, or 8 for AES-128, AES-192,
and AES-256. This course tests AES-128. The extra ``Nk`` values share this
routine so a later size does not need a second expansion.
"""

from __future__ import annotations

from cryptosystem.aes.sbox import sbox_lookup

# Rcon[i] for i = 1..10. Index 0 is unused so the index matches FIPS numbering.
# Only the first byte of each Rcon word is nonzero: it is x^{i-1} in GF(2^8).
_RCON = (0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)

_NR_FOR_NK = {4: 10, 6: 12, 8: 14}


def rounds_for_nk(nk: int) -> int:
    """Return ``Nr``, the number of rounds, for a key of ``nk`` words."""
    try:
        return _NR_FOR_NK[nk]
    except KeyError as exc:
        raise ValueError("Nk must be 4, 6, or 8") from exc


def _rot_word(word: list[int]) -> list[int]:
    return [word[1], word[2], word[3], word[0]]


def _sub_word(word: list[int]) -> list[int]:
    return [sbox_lookup(byte) for byte in word]


def expand_key(key: bytes | bytearray, nk: int | None = None) -> list[bytes]:
    """Expand ``key`` into ``Nr + 1`` round keys of 16 bytes each.

    ``nk`` defaults to ``len(key) // 4``. A caller who passes ``nk`` must
    match the key length. An AES-128 key is 16 bytes, so ``nk`` is 4 and the
    result has 11 round keys.
    """
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("AES key must be bytes")
    key_bytes = bytes(key)
    if nk is None:
        if len(key_bytes) not in (16, 24, 32):
            raise ValueError("AES key must be 16, 24, or 32 bytes")
        nk = len(key_bytes) // 4
    elif nk not in _NR_FOR_NK or len(key_bytes) != 4 * nk:
        raise ValueError("nk must be 4, 6, or 8 and must match the key length")

    nr = _NR_FOR_NK[nk]
    total_words = 4 * (nr + 1)
    words: list[list[int]] = [list(key_bytes[4 * i : 4 * i + 4]) for i in range(nk)]
    for index in range(nk, total_words):
        temp = words[index - 1][:]
        if index % nk == 0:
            temp = _sub_word(_rot_word(temp))
            temp[0] ^= _RCON[index // nk]
        elif nk > 6 and index % nk == 4:
            temp = _sub_word(temp)
        words.append([left ^ right for left, right in zip(words[index - nk], temp)])

    round_keys: list[bytes] = []
    for round_index in range(nr + 1):
        block = bytearray()
        for col in range(4):
            block.extend(words[round_index * 4 + col])
        round_keys.append(bytes(block))
    return round_keys
