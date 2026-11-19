"""Streamlit page for hybrid encryption.

Author: Adarsha Shrestha (Week 13).

``render()`` draws the page. It reuses the RSA key in
``st.session_state["rsa_key"]`` from the RSA page, and can generate one
itself into that same slot. The session key and IV are random per message;
they are not the AES page's key.
"""

from __future__ import annotations

import time

import streamlit as st

from cryptosystem.gui.rsa_page import KEY_STATE
from cryptosystem.hybrid import HybridPackage, decrypt, encrypt
from cryptosystem.rsa.rsa import generate_keypair


def _key_section():
    """Show the shared RSA key, or generate one large enough to wrap an AES key."""
    st.subheader("1. RSA key")
    st.caption(
        "Generate a key here, or reuse the key from the RSA page. "
        "The textbook key (n = 3233) is too small to wrap a 16-byte AES key."
    )
    key = st.session_state.get(KEY_STATE)
    left, right = st.columns([2, 1])
    with left:
        bits = st.selectbox("Modulus size (bits)", (512, 1024), index=1, key="hybrid_bits")
    with right:
        st.write("")
        generate = st.button("Generate RSA key", type="primary", key="hybrid_generate")

    if generate:
        try:
            start = time.perf_counter()
            key = generate_keypair(bits=bits)
            st.session_state[KEY_STATE] = key
            elapsed = (time.perf_counter() - start) * 1000
            st.success(f"Generated a {key.n.bit_length()}-bit key in {elapsed:.0f} ms.")
        except ValueError as exc:
            st.error(str(exc))
            key = st.session_state.get(KEY_STATE)

    if key is None:
        st.info("No RSA key yet. Generate one above, or create one on the RSA page.")
        return None
    if key.byte_length < 27:
        st.error(
            f"This modulus is {key.byte_length} bytes. "
            "Hybrid encryption needs at least 27 bytes (a 512-bit key or larger)."
        )
        return None
    if key.d is None:
        st.error("This key has no private exponent, so the message cannot be decrypted.")
        return None

    st.write(
        f"Modulus: **{key.n.bit_length()} bits** ({key.byte_length} bytes), "
        f"public exponent **{key.e}**."
    )
    return key


def _message_section(key) -> None:
    st.subheader("2. Encrypt and decrypt a message")
    plaintext = st.text_area("Message", value="hybrid encryption demo", key="hybrid_message")
    if st.button("Encrypt", key="hybrid_encrypt"):
        try:
            package = encrypt(plaintext.encode("utf-8"), key)
        except (ValueError, TypeError) as exc:
            st.error(str(exc))
        else:
            st.session_state["hybrid_wrapped"] = package.wrapped_key
            st.session_state["hybrid_iv"] = package.iv
            st.session_state["hybrid_ct"] = package.ciphertext
            st.success("Encrypted. The AES session key is inside the RSA field below.")

    st.text_area("RSA-wrapped AES key (hex)", key="hybrid_wrapped")
    st.text_input("IV (hex)", key="hybrid_iv")
    st.text_area("AES-CBC ciphertext (hex)", key="hybrid_ct")

    if st.button("Decrypt", key="hybrid_decrypt"):
        wrapped = st.session_state.get("hybrid_wrapped", "")
        iv = st.session_state.get("hybrid_iv", "")
        ciphertext = st.session_state.get("hybrid_ct", "")
        try:
            recovered = decrypt(
                HybridPackage(wrapped_key=wrapped, iv=iv, ciphertext=ciphertext),
                key,
            )
            st.success(recovered.decode("utf-8"))
        except UnicodeDecodeError:
            st.error("Decryption succeeded, but the bytes are not UTF-8 text.")
        except (ValueError, TypeError) as exc:
            st.error(str(exc))


def render() -> None:
    """Draw the hybrid page."""
    st.header("Hybrid encryption")
    st.caption("RSA (PKCS#1 v1.5) wraps a random AES-128 key. AES-CBC with PKCS#7 encrypts the message.")
    key = _key_section()
    if key is None:
        return
    st.divider()
    _message_section(key)
