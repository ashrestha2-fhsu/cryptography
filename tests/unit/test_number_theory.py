"""Week 5 RSA arithmetic on small integers."""

import pytest

from cryptosystem.rsa.number_theory import extended_gcd, modexp, modinv


def test_extended_gcd_classic_pair():
    assert extended_gcd(240, 46) == (2, -9, 47)


def test_extended_gcd_identity_holds_for_the_textbook_exponent():
    gcd, x_coef, y_coef = extended_gcd(17, 3120)
    assert gcd == 1
    assert 17 * x_coef + 3120 * y_coef == 1


def test_extended_gcd_is_non_negative_for_negative_inputs():
    gcd, x_coef, y_coef = extended_gcd(-240, 46)
    assert gcd == 2
    assert (-240) * x_coef + 46 * y_coef == gcd


def test_modinv_textbook_rsa_exponent():
    # phi(61 * 53) = 3120, and 17 * 2753 ≡ 1 (mod 3120).
    assert modinv(17, 3120) == 2753
    assert modinv(3, 7) == 5


def test_modinv_rejects_a_non_coprime_pair_and_a_bad_modulus():
    with pytest.raises(ValueError):
        modinv(2, 4)
    with pytest.raises(ValueError):
        modinv(5, 0)


def test_modexp_textbook_rsa_encryption():
    # 65^17 mod 3233, with n = 61 * 53 and e = 17.
    assert modexp(65, 17, 3233) == 2790


def test_modexp_small_exponents():
    assert modexp(7, 0, 13) == 1
    assert modexp(5, 1, 13) == 5
    assert modexp(2, 10, 1000) == 24
    assert modexp(2, 10, 1) == 0


def test_modexp_rejects_a_negative_exponent():
    with pytest.raises(ValueError):
        modexp(2, -1, 13)
