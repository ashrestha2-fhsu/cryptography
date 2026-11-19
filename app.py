"""Streamlit demo for AES, RSA, and hybrid encryption.

Author: Adarsha Shrestha (Week 13), wiring pages by Oudom Thach and Pichponleur Pen.

Run with ``streamlit run app.py``.
"""

from __future__ import annotations

import sys
from pathlib import Path

# pytest finds the package through pytest.ini. The demo process needs the same path.
_SRC = Path(__file__).resolve().parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import streamlit as st

from cryptosystem.gui import aes_page, hybrid_page, rsa_page


def main() -> None:
    """Open the three-page demo."""
    st.set_page_config(page_title="AES and RSA", layout="wide")
    st.sidebar.title("CSCI 663")
    st.sidebar.caption("From-scratch AES and RSA")
    page = st.sidebar.radio("Scheme", ["AES", "RSA", "Hybrid"])
    if page == "AES":
        aes_page.render()
    elif page == "RSA":
        rsa_page.render()
    else:
        hybrid_page.render()


if __name__ == "__main__":
    main()
