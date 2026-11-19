# CSCI 663 group project: AES and RSA

From-scratch AES and RSA in Python. The demo is one Streamlit app: AES-CBC, RSA, and a hybrid scheme where RSA wraps an AES-128 session key and AES-CBC encrypts the message.

The design and test plan are in [docs/design.md](docs/design.md).

## Run the tests

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest
```

Do not satisfy a test by calling PyCryptodome or another crypto library.

## Run the demo

```bash
streamlit run app.py
```

The sidebar opens the AES page, the RSA page, or the hybrid page. The hybrid page reuses the RSA key stored by the RSA page.

## What is implemented

- AES block cipher, including FIPS-197 Appendix C.1 (Adarsha, Week 5)
- AES-CBC, PKCS#7, text/file helpers, and the AES page (Oudom, Weeks 7–9)
- RSA key generation, textbook RSA, PKCS#1 v1.5, CRT decryption, and the RSA page (Pichponleur, Week 11)
- Hybrid encrypt/decrypt and the combined app (Adarsha, Week 13)

Week 15 is the recorded group presentation.
