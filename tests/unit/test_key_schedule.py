"""AES-128 key expansion against FIPS-197 Appendix A.1."""

import pytest

from cryptosystem.aes.key_schedule import expand_key, rounds_for_nk
from tests.fips197 import APPENDIX_B_KEY, APPENDIX_B_ROUND_KEYS


def test_rounds_for_aes_128():
    assert rounds_for_nk(4) == 10


def test_expand_appendix_b_key():
    round_keys = expand_key(APPENDIX_B_KEY)
    assert round_keys == APPENDIX_B_ROUND_KEYS
    assert expand_key(APPENDIX_B_KEY, nk=4) == APPENDIX_B_ROUND_KEYS


def test_expand_key_rejects_a_bad_length_or_nk():
    with pytest.raises(ValueError):
        expand_key(b"\x00" * 15)
    with pytest.raises(ValueError):
        expand_key(APPENDIX_B_KEY, nk=6)
    with pytest.raises(TypeError):
        expand_key("not-bytes")  # type: ignore[arg-type]
