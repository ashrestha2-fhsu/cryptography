"""S-box against FIPS-197 Figure 7, plus the inverse table."""

import pytest

from cryptosystem.aes.sbox import INV_SBOX, SBOX, inv_sbox_lookup, sbox_lookup

# First row of FIPS-197 Figure 7.
_FIGURE_7_ROW_0 = bytes.fromhex("637c777bf26b6fc53001672bfed7ab76")


def test_sbox_matches_figure_7_first_row():
    assert SBOX[:16] == _FIGURE_7_ROW_0
    assert sbox_lookup(0x00) == 0x63
    assert sbox_lookup(0x01) == 0x7C


def test_sbox_and_inverse_are_permutations_of_each_other():
    assert len(set(SBOX)) == 256
    assert len(set(INV_SBOX)) == 256
    for value in range(256):
        assert inv_sbox_lookup(sbox_lookup(value)) == value
        assert sbox_lookup(inv_sbox_lookup(value)) == value


def test_lookup_rejects_non_bytes():
    with pytest.raises(ValueError):
        sbox_lookup(256)
    with pytest.raises(ValueError):
        inv_sbox_lookup(-1)
