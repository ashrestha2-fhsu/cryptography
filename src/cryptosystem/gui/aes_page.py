"""Streamlit page for AES-CBC encryption and decryption.

Author: Oudom Thach (AES-CBC, PKCS#7 padding, text & file interface).

``render()`` draws the whole page and can be called from ``app.py`` when the
three-page app is put together. The page keeps the current key and IV in
``st.session_state["aes_key"]`` and ``st.session_state["aes_iv"]``.
"""

from __future__ import annotations

import os

import streamlit as st

from cryptosystem.aes.modes import (
    decrypt_file,
    decrypt_text,
    encrypt_file,
    encrypt_text,
    pkcs7_pad,
)

KEY_STATE = "aes_key"
IV_STATE = "aes_iv"
KEY_SIZES = {128: 16, 192: 24, 256: 32}

_NIST_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
_NIST_IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")


def _parse_hex(text: str, name: str) -> bytes | None:
    """Read a hex string typed by the user, or show an error and return None."""
    cleaned = "".join(text.split()).lower()
    if not cleaned:
        st.error(f"Enter a value for {name}.")
        return None
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        st.error(f"{name} must be hexadecimal (0-9, a-f).")
        return None


def _ensure_defaults() -> None:
    if KEY_STATE not in st.session_state:
        st.session_state[KEY_STATE] = _NIST_KEY
    if IV_STATE not in st.session_state:
        st.session_state[IV_STATE] = _NIST_IV


def _key_section() -> tuple[bytes | None, bytes | None]:
    st.subheader("1. Key & IV setup")
    left, right = st.columns([2, 1])
    with left:
        bits = st.selectbox("AES key size (bits)", list(KEY_SIZES.keys()), index=0)
    with right:
        st.write("")
        if st.button("Generate random key & IV", type="primary"):
            st.session_state[KEY_STATE] = os.urandom(KEY_SIZES[bits])
            st.session_state[IV_STATE] = os.urandom(16)
        if st.button("Load NIST F.2.1 key & IV"):
            st.session_state[KEY_STATE] = _NIST_KEY
            st.session_state[IV_STATE] = _NIST_IV

    key_hex = st.text_input(
        "AES Key (hex, 16 / 24 / 32 bytes)",
        value=st.session_state[KEY_STATE].hex(),
    )
    iv_hex = st.text_input(
        "Initialization Vector IV (hex, 16 bytes)",
        value=st.session_state[IV_STATE].hex(),
    )

    key = _parse_hex(key_hex, "AES Key")
    iv = _parse_hex(iv_hex, "IV")
    if key is not None and len(key) not in (16, 24, 32):
        st.error("AES Key must be 16, 24, or 32 bytes (32, 48, or 64 hex chars).")
        key = None
    if iv is not None and len(iv) != 16:
        st.error("IV must be 16 bytes (32 hex chars).")
        iv = None

    if key is not None:
        st.session_state[KEY_STATE] = key
    if iv is not None:
        st.session_state[IV_STATE] = iv

    return key, iv


def _text_section(key: bytes | None, iv: bytes | None) -> None:
    st.subheader("2. Text encryption & decryption (AES-CBC + PKCS#7)")
    enc_col, dec_col = st.columns(2)

    with enc_col:
        plaintext = st.text_area("Plaintext (UTF-8)", value="Hello, Cryptography!")
        if st.button("Encrypt text", key="aes_encrypt_text"):
            if key is None or iv is None:
                st.error("Provide a valid AES key and IV above.")
            else:
                try:
                    padded = pkcs7_pad(plaintext.encode("utf-8"), 16)
                    ct = encrypt_text(plaintext, key, iv)
                    st.session_state["aes_last_ct"] = ct.hex()
                    st.caption(f"PKCS#7 padded ({len(padded)} bytes, {len(padded) // 16} block(s)):")
                    st.code(padded.hex(), language="text")
                    st.caption(f"Ciphertext ({len(ct)} bytes, {len(ct) // 16} block(s)):")
                    st.code(ct.hex(), language="text")
                except (ValueError, TypeError) as exc:
                    st.error(str(exc))

    with dec_col:
        ct_hex = st.text_area(
            "Ciphertext (hex)",
            value=st.session_state.get("aes_last_ct", ""),
        )
        if st.button("Decrypt text", key="aes_decrypt_text"):
            if key is None or iv is None:
                st.error("Provide a valid AES key and IV above.")
            else:
                ct_bytes = _parse_hex(ct_hex, "Ciphertext")
                if ct_bytes is not None:
                    try:
                        pt = decrypt_text(ct_bytes, key, iv)
                        st.success(pt)
                    except (ValueError, UnicodeDecodeError) as exc:
                        st.error(f"Decryption failed: {exc}")


def _file_section(key: bytes | None, iv: bytes | None) -> None:
    st.subheader("3. File encryption & decryption (AES-CBC + PKCS#7)")
    enc_col, dec_col = st.columns(2)

    with enc_col:
        up_plain = st.file_uploader("Upload file to encrypt", key="aes_up_plain")
        if up_plain is not None and st.button("Encrypt file", key="aes_btn_enc_file"):
            if key is None or iv is None:
                st.error("Provide a valid AES key and IV above.")
            else:
                try:
                    encrypted = encrypt_file(up_plain.getvalue(), key, iv)
                    st.download_button(
                        label="Download encrypted file",
                        data=encrypted,
                        file_name=f"{up_plain.name}.enc",
                        mime="application/octet-stream",
                    )
                except ValueError as exc:
                    st.error(str(exc))

    with dec_col:
        up_enc = st.file_uploader("Upload .enc file to decrypt", key="aes_up_enc")
        if up_enc is not None and st.button("Decrypt file", key="aes_btn_dec_file"):
            if key is None or iv is None:
                st.error("Provide a valid AES key and IV above.")
            else:
                try:
                    decrypted = decrypt_file(up_enc.getvalue(), key, iv)
                    out_name = (
                        up_enc.name[:-4] if up_enc.name.endswith(".enc") else f"decrypted_{up_enc.name}"
                    )
                    st.download_button(
                        label="Download decrypted file",
                        data=decrypted,
                        file_name=out_name,
                        mime="application/octet-stream",
                    )
                except ValueError as exc:
                    st.error(f"Decryption failed: {exc}")


def render() -> None:
    """Draw the AES-CBC page."""
    st.header("AES-CBC Encryption & Decryption")
    st.caption("FIPS-197 block cipher with PKCS#7 padding and CBC mode.")
    _ensure_defaults()
    key, iv = _key_section()
    st.divider()
    _text_section(key, iv)
    st.divider()
    _file_section(key, iv)
