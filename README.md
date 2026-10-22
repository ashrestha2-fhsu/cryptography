# CSCI 663 group project: AES and RSA

From-scratch AES-128 and RSA in Python. The finished demo is a hybrid scheme (RSA wraps an AES session key, AES-CBC encrypts the message) behind one Streamlit app. Week 5 is done: the AES block cipher and the RSA number-theory functions pass their unit tests. Modes, key generation, the hybrid wiring, and the GUI are stubbed for the next milestones.

The design, function list, and test plan are in [docs/design.md](docs/design.md).

## Run the tests

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest
```

`pip install pytest` is enough for the current suite. Streamlit is listed for the Week 9–13 GUI and is not imported yet.

A green run looks like `27 passed, 9 skipped`. The skipped tests are the contract for later weeks. Remove a test's `@pytest.mark.skip` line after implementing the function it calls. Do not satisfy a test by calling PyCryptodome or another crypto library.

## What already passes

- GF(2^8) `xtime`, `gf_mul`, and `gf_inv`
- S-box and inverse S-box
- `sub_bytes`, `shift_rows`, `mix_columns`, `add_round_key`, and the three inverses
- AES-128 key expansion
- `encrypt_block` and `decrypt_block`, including FIPS-197 Appendix C.1
- `extended_gcd`, `modinv`, and square-and-multiply `modexp`

## Where to continue

One person, Weeks 7–9, first scheme:

- [src/cryptosystem/aes/modes.py](src/cryptosystem/aes/modes.py): PKCS#7, AES-CBC, `encrypt_text` / `decrypt_text`, `encrypt_file` / `decrypt_file`
- [tests/unit/test_modes.py](tests/unit/test_modes.py): NIST SP 800-38A F.2.1 is the CBC vector
- [app.py](app.py): the AES page only. Key entry is 32 hex characters. No password KDF.

The other person, Week 11, second scheme:

- [src/cryptosystem/rsa/rsa.py](src/cryptosystem/rsa/rsa.py): Miller-Rabin, prime generation, `generate_keypair`, textbook `encrypt_int` / `decrypt_int`, PKCS#1 v1.5, byte `encrypt` / `decrypt`
- Build those on `modexp` and `modinv`. The private exponent uses Euler's totient, `(p - 1) * (q - 1)`, not Carmichael's lambda.
- [tests/unit/test_rsa.py](tests/unit/test_rsa.py): `65^17 mod 3233 = 2790` with `p = 61`, `q = 53`, `e = 17`, `d = 2753`

After both of those exist, the remaining piece is the hybrid package and a single GUI:

- [src/cryptosystem/hybrid.py](src/cryptosystem/hybrid.py) and [tests/system/test_hybrid.py](tests/system/test_hybrid.py)
- AES, RSA, and hybrid pages in `app.py`
