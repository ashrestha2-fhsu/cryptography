"""FIPS-197 section 4.2 field arithmetic."""

import pytest

from cryptosystem.aes.field import gf_inv, gf_mul, xtime


def test_xtime_matches_fips_doubling_chain():
    # {57} * {02} = {ae}, then * {02} = {47}, * {02} = {8e}, * {02} = {07}.
    assert xtime(0x57) == 0xAE
    assert xtime(0xAE) == 0x47
    assert xtime(0x47) == 0x8E
    assert xtime(0x8E) == 0x07


def test_gf_mul_matches_fips_worked_example():
    assert gf_mul(0x57, 0x13) == 0xFE
    assert gf_mul(0x57, 0x01) == 0x57
    assert gf_mul(0x57, 0x00) == 0x00
    assert gf_mul(0x00, 0x13) == 0x00


def test_gf_mul_is_commutative():
    assert gf_mul(0x53, 0xCA) == gf_mul(0xCA, 0x53)


def test_gf_inv_is_the_multiplicative_inverse():
    assert gf_inv(0x00) == 0x00
    assert gf_inv(0x01) == 0x01
    for value in range(1, 256):
        assert gf_mul(value, gf_inv(value)) == 0x01


def test_field_helpers_reject_non_bytes():
    with pytest.raises(ValueError):
        xtime(256)
    with pytest.raises(ValueError):
        gf_mul(-1, 1)
    with pytest.raises(ValueError):
        gf_inv(0x100)
