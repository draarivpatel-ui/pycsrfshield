"""BREACH-safe masking tests."""

from __future__ import annotations

import base64
import unittest

from pycsrfshield import MaskError, TokenError
from pycsrfshield.token import MASK_BYTES

from _support import manager, now, unb64

SESSION = "session-42"


class MaskingTests(unittest.TestCase):
    def setUp(self):
        self.m = manager()
        self.token = self.m.issue(SESSION, now=now())

    def test_roundtrip(self):
        masked = self.m.mask(self.token)
        self.assertEqual(self.m.unmask(masked), self.token)

    def test_mint_roundtrip(self):
        masked = self.m.mint(SESSION, now=now())
        self.assertTrue(self.m.verify_masked(masked, SESSION, now=now()))

    def test_mask_changes_output(self):
        self.assertNotEqual(self.m.mask(self.token), self.token)

    def test_fresh_mask_each_call(self):
        a = self.m.mask(self.token)
        b = self.m.mask(self.token)
        self.assertNotEqual(a, b)

    def test_mask_is_randomized(self):
        pads = {unb64(self.m.mask(self.token))[:MASK_BYTES] for _ in range(40)}
        self.assertGreaterEqual(len(pads), 39)

    def test_mask_prepends_32_bytes(self):
        raw = unb64(self.m.mask(self.token))
        self.assertEqual(len(raw), MASK_BYTES + len(unb64(self.token)))

    def test_mask_is_xor(self):
        fixed = bytes(range(32))
        masked = self.m.mask(self.token, mask=fixed)
        raw = unb64(masked)
        self.assertEqual(raw[:32], fixed)
        payload = raw[32:]
        original = unb64(self.token)
        self.assertEqual(bytes(a ^ fixed[i % 32] for i, a in enumerate(original)), payload)

    def test_short_mask_rejected(self):
        with self.assertRaises(MaskError):
            self.m.mask(self.token, mask=b"short")

    def test_long_mask_rejected(self):
        with self.assertRaises(MaskError):
            self.m.mask(self.token, mask=b"x" * 40)

    def test_empty_mask_rejected(self):
        with self.assertRaises(MaskError):
            self.m.mask(self.token, mask=b"")

    def test_string_mask_rejected(self):
        with self.assertRaises(MaskError):
            self.m.mask(self.token, mask="x" * 32)

    def test_mask_empty_token_rejected(self):
        with self.assertRaises(TokenError):
            self.m.mask("")

    def test_mask_invalid_token_rejected(self):
        with self.assertRaises(TokenError):
            self.m.mask("not*a*token")

    def test_unmask_empty_rejected(self):
        with self.assertRaises(MaskError):
            self.m.unmask("")

    def test_unmask_bad_encoding_rejected(self):
        with self.assertRaises(MaskError):
            self.m.unmask("abc$def")

    def test_unmask_too_short_rejected(self):
        with self.assertRaises(MaskError):
            self.m.unmask(base64.urlsafe_b64encode(b"x" * 20).decode().rstrip("="))

    def test_unmask_exact_mask_length_rejected(self):
        with self.assertRaises(MaskError):
            self.m.unmask(base64.urlsafe_b64encode(b"x" * MASK_BYTES).decode().rstrip("="))

    def test_unmask_non_string_rejected(self):
        with self.assertRaises(MaskError):
            self.m.unmask(12345)

    def test_tampered_masked_token_rejected(self):
        masked = self.m.mint(SESSION, now=now())
        raw = bytearray(unb64(masked))
        raw[-1] ^= 1
        tampered = base64.urlsafe_b64encode(bytes(raw)).decode().rstrip("=")
        with self.assertRaises(TokenError):
            self.m.verify_masked(tampered, SESSION, now=now())

    def test_mismatched_session_rejected(self):
        masked = self.m.mint(SESSION, now=now())
        with self.assertRaises(TokenError):
            self.m.verify_masked(masked, "other", now=now())

    def test_no_padding_in_masked_output(self):
        masked = self.m.mint(SESSION, now=now())
        self.assertNotIn("=", masked)
        self.assertTrue(set(masked).issubset(set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")))

    def test_double_mask_unmask_yields_original_masked_inner(self):
        once = self.m.mask(self.token)
        twice = self.m.mask(once)
        self.assertEqual(self.m.unmask(twice), once)


if __name__ == "__main__":
    unittest.main()
