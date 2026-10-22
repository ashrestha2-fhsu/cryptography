"""From-scratch AES and RSA for the CSCI 663 group project.

Week 5 exports the AES block cipher and the RSA number-theory helpers.
Modes, key generation, hybrid encryption, and the Streamlit demo are stubbed
until later milestones. See docs/design.md.
"""

from cryptosystem.aes.cipher import decrypt_block, encrypt_block
from cryptosystem.rsa.number_theory import extended_gcd, modexp, modinv

__all__ = [
    "decrypt_block",
    "encrypt_block",
    "extended_gcd",
    "modexp",
    "modinv",
]
