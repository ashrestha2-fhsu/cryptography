"""Streamlit page for the RSA scheme.

Author: Pichponleur Pen (Week 11, RSA test interface).

``render()`` draws the whole page and can be called from ``app.py`` when the
three-page app is put together. The page keeps the current key in
``st.session_state["rsa_key"]`` so the other pages (for example the hybrid
page) can reuse it.

Sections:

1. Key generation: choose a modulus size, or load the textbook key
   ``p = 61``, ``q = 53``, ``e = 17``; show ``n``, ``e``, ``d``, ``p``, ``q``.
2. Textbook RSA on integers: ``c = m^e mod n`` and ``m = c^d mod n``.
3. PKCS#1 v1.5 on text: encrypt a short UTF-8 message to hex, decrypt hex back.
4. Miller-Rabin: test any integer for primality.
"""

from __future__ import annotations

import time

import streamlit as st

from cryptosystem.rsa.rsa import (
    RSAKey,
    decrypt,
    decrypt_int,
    decrypt_int_crt,
    encrypt,
    encrypt_int,
    generate_keypair,
    is_probable_prime,
)

KEY_STATE = "rsa_key"
TEXTBOOK_KEY = RSAKey(n=3233, e=17, d=2753, p=61, q=53)
KEY_SIZES = (512, 1024, 2048)


def _parse_int(text: str, name: str) -> int | None:
    """Read a decimal integer typed by the user, or show an error and return None."""
    cleaned = text.strip().replace(",", "").replace(" ", "")
    if not cleaned:
        st.error(f"Enter a value for {name}.")
        return None
    try:
        return int(cleaned, 10)
    except ValueError:
        st.error(f"{name} must be a whole number in decimal.")
        return None


def _parse_hex(text: str, name: str) -> bytes | None:
    """Read a hex string typed by the user, or show an error and return None."""
    cleaned = "".join(text.split()).lower()
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        st.error(f"{name} must be hexadecimal (0-9, a-f).")
        return None


def _key_section() -> None:
    st.subheader("1. Key generation")
    left, right = st.columns([2, 1])
    with left:
        bits = st.selectbox("Modulus size (bits)", KEY_SIZES, index=1)
        e_text = st.text_input("Public exponent e", value="65537")
    with right:
        st.write("")
        generate = st.button("Generate key pair", type="primary")
        load_textbook = st.button("Load textbook key (p = 61, q = 53)")

    if generate:
        e_value = _parse_int(e_text, "e")
        if e_value is not None:
            try:
                start = time.perf_counter()
                st.session_state[KEY_STATE] = generate_keypair(bits=bits, e=e_value)
                elapsed = time.perf_counter() - start
                st.success(f"Generated a {bits}-bit key pair in {elapsed:.2f} s.")
            except ValueError as error:
                st.error(str(error))
    if load_textbook:
        st.session_state[KEY_STATE] = TEXTBOOK_KEY
        st.success("Loaded the textbook key: n = 3233, e = 17, d = 2753.")

    key = st.session_state.get(KEY_STATE)
    if key is None:
        st.info("Generate a key pair or load the textbook key to use the sections below.")
        return

    st.markdown(
        f"Modulus: **{key.n.bit_length()} bits** ({key.byte_length} bytes). "
        f"Largest PKCS#1 v1.5 message: **{max(key.byte_length - 11, 0)} bytes**."
    )
    st.text_area("Public key n", str(key.n), height=90, disabled=True)
    st.text_input("Public key e", str(key.e), disabled=True)
    st.text_area("Private key d", str(key.d), height=90, disabled=True)
    with st.expander("Private primes p and q, and the totient"):
        st.code(f"p = {key.p}\nq = {key.q}\nphi(n) = (p - 1)(q - 1) = {(key.p - 1) * (key.q - 1)}")
        st.caption("d is the inverse of e modulo phi(n), computed with the extended Euclidean algorithm.")


def _integer_section(key: RSAKey) -> None:
    st.subheader("2. Textbook RSA on integers")
    st.caption("Encryption c = m^e mod n, decryption m = c^d mod n (square-and-multiply). Requires 0 <= m < n.")
    enc_col, dec_col = st.columns(2)
    with enc_col:
        m_text = st.text_input("Message m", value="65", key="rsa_int_m")
        if st.button("Encrypt integer"):
            message = _parse_int(m_text, "m")
            if message is not None:
                try:
                    cipher_text = str(encrypt_int(message, key.n, key.e))
                    st.session_state["rsa_int_c"] = cipher_text
                    st.session_state["rsa_int_c_in"] = cipher_text  # fill the decrypt box
                except ValueError as error:
                    st.error(str(error))
        if "rsa_int_c" in st.session_state:
            st.code(f"c = {st.session_state['rsa_int_c']}")
    with dec_col:
        c_text = st.text_input("Ciphertext c", key="rsa_int_c_in")
        if st.button("Decrypt integer"):
            cipher = _parse_int(c_text, "c")
            if cipher is not None:
                try:
                    plain = decrypt_int(cipher, key.n, key.d)
                    st.code(f"m = {plain}")
                    if key.p is not None and key.q is not None:
                        st.caption(f"CRT decryption gives the same value: {decrypt_int_crt(cipher, key)}")
                except ValueError as error:
                    st.error(str(error))


def _text_section(key: RSAKey) -> None:
    st.subheader("3. PKCS#1 v1.5 encryption of text")
    limit = key.byte_length - 11
    if limit < 1:
        st.warning("This modulus is too small for PKCS#1 v1.5. Generate a 512-bit or larger key.")
        return
    st.caption(
        "The message is padded as 00 || 02 || random nonzero bytes || 00 || message, "
        "so encrypting the same text twice gives different ciphertexts."
    )
    text = st.text_input(f"Plaintext (UTF-8, at most {limit} bytes)", value="Hello from CSCI 663", key="rsa_text_m")
    if st.button("Encrypt text"):
        data = text.encode("utf-8")
        try:
            st.session_state["rsa_text_c_in"] = encrypt(data, key).hex()  # fill the decrypt box
        except ValueError as error:
            st.error(str(error))
    cipher_hex = st.text_area("Ciphertext (hex)", height=110, key="rsa_text_c_in")
    if st.button("Decrypt text"):
        cipher = _parse_hex(cipher_hex, "Ciphertext")
        if cipher is not None:
            try:
                start = time.perf_counter()
                plain = decrypt(cipher, key)
                elapsed = (time.perf_counter() - start) * 1000
                st.success(f"Recovered plaintext ({elapsed:.1f} ms, CRT): {plain.decode('utf-8', errors='replace')}")
            except ValueError as error:
                st.error(str(error))


def _primality_section() -> None:
    st.subheader("4. Miller-Rabin primality test")
    n_text = st.text_input("Integer to test", value="561", key="rsa_mr_n")
    rounds = st.slider("Rounds", min_value=1, max_value=64, value=40)
    if st.button("Test primality"):
        number = _parse_int(n_text, "the integer")
        if number is not None:
            if is_probable_prime(number, rounds=rounds):
                st.success(f"{number} is probably prime (error chance at most 4^-{rounds}).")
            else:
                st.error(f"{number} is not prime.")


def render() -> None:
    """Draw the RSA page."""
    st.header("RSA")
    st.caption("From-scratch RSA: Miller-Rabin key generation, textbook RSA, PKCS#1 v1.5 and CRT decryption.")
    _key_section()
    key = st.session_state.get(KEY_STATE)
    if key is not None:
        st.divider()
        _integer_section(key)
        st.divider()
        _text_section(key)
    st.divider()
    _primality_section()
