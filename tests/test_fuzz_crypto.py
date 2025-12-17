"""
Fuzz tests for crypto module (encrypt/decrypt).

Inspired by https://fuzzing.readthedocs.io/en/latest/tutorial.html,
but implemented only with Python stdlib (no external fuzzing lib),
to avoid fragile build deps.
"""

import os
import random
import string

import pytest

from app.crypto import encrypt_note_content, decrypt_note_content, generate_master_key


@pytest.fixture(scope="module", autouse=True)
def _set_test_master_key():
    """Ensure a valid master key exists for these tests."""
    os.environ["ENCRYPTION_MASTER_KEY"] = generate_master_key()
    yield


def _mutate_string(seed: str, fuzz_factor: int) -> str:
    """
    Rough equivalent of fuzzing.fuzz_string for a single variant:
    - pick N random positions (len(seed) / fuzz_factor)
    - flip chars to random printable chars.
    """
    buf = list(seed)
    if not buf:
        return seed

    num_writes = random.randrange(max(1, len(buf) // fuzz_factor)) + 1

    alphabet = string.printable  # covers ASCII, symbols, etc.

    for _ in range(num_writes):
        pos = random.randrange(len(buf))
        buf[pos] = random.choice(alphabet)

    return "".join(buf)


def test_encrypt_decrypt_roundtrip_fuzz():
    """
    Fuzz encrypt/decrypt with many mutated strings (randomized input).
    """
    seed = "This is a typical note content used as fuzz seed."
    num_variants = 200
    fuzz_factor = 7

    for _ in range(num_variants):
        variant = _mutate_string(seed, fuzz_factor)

        # Make sure we don't blow up on weird characters.
        try:
            plaintext = variant
            ciphertext_b64, nonce_b64 = encrypt_note_content(plaintext)
            decrypted = decrypt_note_content(ciphertext_b64, nonce_b64)
        except Exception as e:  # noqa: BLE001
            pytest.fail(f"Crypto fuzzing raised exception for input {repr(variant)}: {e}")

        assert decrypted == plaintext
