"""Published FIPS-197 vectors. These constants are independent of our code."""

APPENDIX_B_PLAINTEXT = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
APPENDIX_B_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
APPENDIX_B_CIPHERTEXT = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")

# Appendix B round-1 trace, in the same byte order as the cipher input.
APPENDIX_B_AFTER_ROUND_KEY_0 = bytes.fromhex("193de3bea0f4e22b9ac68d2ae9f84808")
APPENDIX_B_AFTER_SUB_BYTES = bytes.fromhex("d42711aee0bf98f1b8b45de51e415230")
APPENDIX_B_AFTER_SHIFT_ROWS = bytes.fromhex("d4bf5d30e0b452aeb84111f11e2798e5")
APPENDIX_B_AFTER_MIX_COLUMNS = bytes.fromhex("046681e5e0cb199a48f8d37a2806264c")
APPENDIX_B_AFTER_ROUND_KEY_1 = bytes.fromhex("a49c7ff2689f352b6b5bea43026a5049")
APPENDIX_B_ROUND_KEY_1 = bytes.fromhex("a0fafe1788542cb123a339392a6c7605")

# Appendix A.1 expansion of APPENDIX_B_KEY, eleven round keys.
APPENDIX_B_ROUND_KEYS = [
    bytes.fromhex(value)
    for value in (
        "2b7e151628aed2a6abf7158809cf4f3c",
        "a0fafe1788542cb123a339392a6c7605",
        "f2c295f27a96b9435935807a7359f67f",
        "3d80477d4716fe3e1e237e446d7a883b",
        "ef44a541a8525b7fb671253bdb0bad00",
        "d4d1c6f87c839d87caf2b8bc11f915bc",
        "6d88a37a110b3efddbf98641ca0093fd",
        "4e54f70e5f5fc9f384a64fb24ea6dc4f",
        "ead27321b58dbad2312bf5607f8d292f",
        "ac7766f319fadc2128d12941575c006e",
        "d014f9a8c9ee2589e13f0cc8b6630ca6",
    )
]

# Appendix C.1, AES-128.
C1_PLAINTEXT = bytes.fromhex("00112233445566778899aabbccddeeff")
C1_KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
C1_CIPHERTEXT = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
