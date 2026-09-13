"""
tests/test_crypto.py
----------------------
Tests for crypto/key_derivation.py and crypto/encryption.py.

Run with:
    python -m pytest tests/test_crypto.py -v
or:
    python -m unittest tests.test_crypto -v
"""

import unittest

from crypto.encryption import (
    encrypt_message,
    decrypt_message,
    AuthenticationError,
    InvalidPayloadError,
    get_header_size,
)
from crypto.key_derivation import generate_salt, derive_key


class TestKeyDerivation(unittest.TestCase):

    def test_key_length_is_32_bytes(self):
        salt = generate_salt()
        key = derive_key("correct horse battery staple", salt)
        self.assertEqual(len(key), 32)

    def test_same_password_and_salt_give_same_key(self):
        salt = generate_salt()
        key1 = derive_key("hunter2", salt)
        key2 = derive_key("hunter2", salt)
        self.assertEqual(key1, key2)

    def test_different_salt_gives_different_key(self):
        key1 = derive_key("hunter2", generate_salt())
        key2 = derive_key("hunter2", generate_salt())
        self.assertNotEqual(key1, key2)

    def test_empty_password_rejected(self):
        with self.assertRaises(ValueError):
            derive_key("", generate_salt())


class TestEncryptDecryptRoundTrip(unittest.TestCase):

    def test_small_message_round_trip(self):
        payload = encrypt_message("Hi", "password123")
        result = decrypt_message(payload, "password123")
        self.assertEqual(result, "Hi")

    def test_large_message_round_trip(self):
        big_message = "A" * 50_000  # 50 KB
        payload = encrypt_message(big_message, "another-password")
        result = decrypt_message(payload, "another-password")
        self.assertEqual(result, big_message)

    def test_unicode_message_round_trip(self):
        message = "Confidential: naïve café 安全 🔐"
        payload = encrypt_message(message, "unicode-pw")
        result = decrypt_message(payload, "unicode-pw")
        self.assertEqual(result, message)

    def test_empty_message_rejected(self):
        with self.assertRaises(ValueError):
            encrypt_message("", "password123")

    def test_two_encryptions_of_same_message_differ(self):
        # Random salt + nonce should make ciphertext different every time,
        # even for identical plaintext and password.
        payload1 = encrypt_message("same message", "pw")
        payload2 = encrypt_message("same message", "pw")
        self.assertNotEqual(payload1, payload2)


class TestWrongPasswordAndTamperDetection(unittest.TestCase):

    def test_wrong_password_raises_authentication_error(self):
        payload = encrypt_message("top secret", "correct-password")
        with self.assertRaises(AuthenticationError):
            decrypt_message(payload, "wrong-password")

    def test_tampered_ciphertext_raises_authentication_error(self):
        payload = bytearray(encrypt_message("top secret", "pw"))
        # Flip a bit somewhere inside the ciphertext (after the header)
        header_size = get_header_size()
        flip_index = header_size + 2
        payload[flip_index] ^= 0xFF
        with self.assertRaises(AuthenticationError):
            decrypt_message(bytes(payload), "pw")

    def test_tampered_tag_raises_authentication_error(self):
        payload = bytearray(encrypt_message("top secret", "pw"))
        # Tag lives right before the ciphertext-length field in the header;
        # flip a byte inside it.
        payload[20] ^= 0xFF
        with self.assertRaises(AuthenticationError):
            decrypt_message(bytes(payload), "pw")


class TestInvalidPayloads(unittest.TestCase):

    def test_garbage_bytes_raise_invalid_payload_error(self):
        with self.assertRaises(InvalidPayloadError):
            decrypt_message(b"not a real payload at all", "pw")

    def test_truncated_payload_raises_invalid_payload_error(self):
        payload = encrypt_message("some message", "pw")
        truncated = payload[:get_header_size() - 5]  # cut into the header
        with self.assertRaises(InvalidPayloadError):
            decrypt_message(truncated, "pw")

    def test_ciphertext_length_mismatch_raises_invalid_payload_error(self):
        payload = encrypt_message("some message", "pw")
        # Drop the last few bytes of ciphertext -> declared length no
        # longer matches actual remaining bytes.
        short_payload = payload[:-3]
        with self.assertRaises(InvalidPayloadError):
            decrypt_message(short_payload, "pw")


if __name__ == "__main__":
    unittest.main()