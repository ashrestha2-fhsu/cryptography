"""One-block AES against FIPS-197 Appendix B and Appendix C.1."""

import pytest

from cryptosystem.aes.cipher import decrypt_block, encrypt_block
from tests.fips197 import (
    APPENDIX_B_CIPHERTEXT,
    APPENDIX_B_KEY,
    APPENDIX_B_PLAINTEXT,
    C1_CIPHERTEXT,
    C1_KEY,
    C1_PLAINTEXT,
)


def test_appendix_b_encrypt_and_decrypt():
    assert encrypt_block(APPENDIX_B_PLAINTEXT, APPENDIX_B_KEY) == APPENDIX_B_CIPHERTEXT
    assert decrypt_block(APPENDIX_B_CIPHERTEXT, APPENDIX_B_KEY) == APPENDIX_B_PLAINTEXT


def test_appendix_c1_encrypt_and_decrypt():
    assert encrypt_block(C1_PLAINTEXT, C1_KEY) == C1_CIPHERTEXT
    assert decrypt_block(C1_CIPHERTEXT, C1_KEY) == C1_PLAINTEXT


def test_block_api_rejects_bad_lengths():
    with pytest.raises(ValueError):
        encrypt_block(b"\x00" * 15, C1_KEY)
    with pytest.raises(ValueError):
        decrypt_block(C1_CIPHERTEXT, b"\x00" * 15)
    with pytest.raises(ValueError):
        encrypt_block(C1_PLAINTEXT, b"\x00" * 8)
