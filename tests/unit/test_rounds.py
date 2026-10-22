"""Round functions against the FIPS-197 Appendix B trace."""

import pytest

from cryptosystem.aes.rounds import (
    add_round_key,
    inv_mix_columns,
    inv_shift_rows,
    inv_sub_bytes,
    mix_columns,
    shift_rows,
    sub_bytes,
)
from tests.fips197 import (
    APPENDIX_B_AFTER_MIX_COLUMNS,
    APPENDIX_B_AFTER_ROUND_KEY_0,
    APPENDIX_B_AFTER_ROUND_KEY_1,
    APPENDIX_B_AFTER_SHIFT_ROWS,
    APPENDIX_B_AFTER_SUB_BYTES,
    APPENDIX_B_KEY,
    APPENDIX_B_PLAINTEXT,
    APPENDIX_B_ROUND_KEY_1,
)


def test_initial_add_round_key_matches_appendix_b():
    assert add_round_key(APPENDIX_B_PLAINTEXT, APPENDIX_B_KEY) == APPENDIX_B_AFTER_ROUND_KEY_0


def test_round_1_forward_trace():
    assert sub_bytes(APPENDIX_B_AFTER_ROUND_KEY_0) == APPENDIX_B_AFTER_SUB_BYTES
    assert shift_rows(APPENDIX_B_AFTER_SUB_BYTES) == APPENDIX_B_AFTER_SHIFT_ROWS
    assert mix_columns(APPENDIX_B_AFTER_SHIFT_ROWS) == APPENDIX_B_AFTER_MIX_COLUMNS
    assert (
        add_round_key(APPENDIX_B_AFTER_MIX_COLUMNS, APPENDIX_B_ROUND_KEY_1)
        == APPENDIX_B_AFTER_ROUND_KEY_1
    )


def test_inverses_undo_the_appendix_b_round():
    assert inv_sub_bytes(APPENDIX_B_AFTER_SUB_BYTES) == APPENDIX_B_AFTER_ROUND_KEY_0
    assert inv_shift_rows(APPENDIX_B_AFTER_SHIFT_ROWS) == APPENDIX_B_AFTER_SUB_BYTES
    assert inv_mix_columns(APPENDIX_B_AFTER_MIX_COLUMNS) == APPENDIX_B_AFTER_SHIFT_ROWS


def test_round_functions_reject_bad_lengths():
    with pytest.raises(ValueError):
        sub_bytes(b"short")
    with pytest.raises(ValueError):
        shift_rows(b"")
    with pytest.raises(ValueError):
        mix_columns(b"\x00" * 15)
    with pytest.raises(ValueError):
        add_round_key(APPENDIX_B_PLAINTEXT, b"\x00" * 15)
