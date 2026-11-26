"""Token cryptography, canonical encoding, expiry and rotation tests."""

from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import unittest

from pycsrfshield import ConfigurationError, TokenError, TokenManager
from pycsrfshield.token import VERSION, _b64decode, _canonical

from _support import SECRET, b64, manager, now, raw_token, resign, unb64, pack_u32

SESSION = "session-42"


class TokenLifecycleTests(unittest.TestCase):
    def test_issue_verify_roundtrip(self):
        token = manager().issue(SESSION, now=now())
        self.assertEqual(manager().verify(token, SESSION, now=now()), manager().bind_session(SESSION))

    def test_issue_returns_url_safe_base64(self):
        token = manager().issue(SESSION, now=now())
        self.assertTrue(set(token).issubset(set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")))
        self.assertNotIn("=", token)

    def test_token_has_signature(self):
        raw = unb64(manager().issue(SESSION, now=now()))
        self.assertEqual(len(raw[-32:]), 32)
        self.assertGreater(len(raw[:-32]), 64)

    def test_tokens_are_unique(self):
        m = manager()
        tokens = {m.issue(SESSION, now=now()) for _ in range(50)}
        self.assertEqual(len(tokens), 50)

    def test_wrong_session_rejected(self):
        token = manager().issue(SESSION, now=now())
        with self.assertRaises(TokenError):
            manager().verify(token, "other-session", now=now())

    def test_tampered_signature_rejected(self):
        token = manager().issue(SESSION, now=now())
        raw = bytearray(unb64(token))
        raw[-1] ^= 1
        with self.assertRaises(TokenError):
            manager().verify(b64(bytes(raw)), SESSION, now=now())

    def test_tampered_payload_rejected(self):
        token = manager().issue(SESSION, now=now())
        raw = bytearray(unb64(token))
        raw[10] ^= 0x20
        with self.assertRaises(TokenError):
            manager().verify(b64(bytes(raw)), SESSION, now=now())

    def test_empty_token_rejected(self):
        with self.assertRaises(TokenError):
            manager().verify("", SESSION, now=now())

    def test_none_token_rejected(self):
        with self.assertRaises(TokenError):
            manager().verify(None, SESSION, now=now())

    def test_non_string_token_rejected(self):
        with self.assertRaises(TokenError):
            manager().verify(12345, SESSION, now=now())

    def test_invalid_base64_rejected(self):
        with self.assertRaises(TokenError):
            manager().verify("a*b*c", SESSION, now=now())

    def test_base64_padding_rejected(self):
        token = manager().issue(SESSION, now=now()) + "="
        with self.assertRaises(TokenError):
            manager().verify(token, SESSION, now=now())

    def test_truncated_token_rejected(self):
        token = manager().issue(SESSION, now=now())
        with self.assertRaises(TokenError):
            manager().verify(token[:-6], SESSION, now=now())

    def test_tiny_payload_rejected(self):
        with self.assertRaises(TokenError):
            manager().verify(b64(b"\x00"), SESSION, now=now())

    def test_unsupported_version_rejected(self):
        m = manager()
        raw = bytearray(unb64(m.issue(SESSION, now=now())))
        raw[0:4] = pack_u32(VERSION + 1)
        with self.assertRaises(TokenError):
            m.verify(resign(bytes(raw)), SESSION, now=now())

    def test_forged_signature_for_bad_version_rejected(self):
        m = manager()
        raw = bytearray(unb64(m.issue(SESSION, now=now())))
        raw[0:4] = pack_u32(VERSION + 1)
        with self.assertRaises(TokenError):
            m.verify(b64(bytes(raw)), SESSION, now=now())

    def test_invalid_utf8_binding_rejected(self):
        m = manager()
        raw = bytearray(unb64(m.issue(SESSION, now=now())))
        raw[8] = 0xFF
        with self.assertRaises(TokenError):
            m.verify(resign(bytes(raw)), SESSION, now=now())

    def test_empty_nonce_rejected(self):
        m = manager()
        raw = unb64(m.issue(SESSION, now=now()))
        # version + binding(len+value) + expires + issued, then nonce length
        binding_len = struct.unpack_from(">I", raw, 4)[0]
        nonce_len_offset = 4 + 4 + binding_len + 4 + 4
        raw = bytearray(raw)
        raw[nonce_len_offset:nonce_len_offset + 4] = pack_u32(0)
        with self.assertRaises(TokenError):
            m.verify(resign(bytes(raw)), SESSION, now=now())

    def test_trailing_bytes_rejected(self):
        m = manager()
        raw = unb64(m.issue(SESSION, now=now()))
        signature = raw[-32:]
        payload = raw[:-32] + b"extra"
        with self.assertRaises(TokenError):
            m.verify(b64(payload + signature), SESSION, now=now())


class ConfigurationTests(unittest.TestCase):
    def test_short_secret_rejected(self):
        with self.assertRaises(ConfigurationError):
            TokenManager(b"short")

    def test_empty_secret_rejected(self):
        with self.assertRaises(ConfigurationError):
            TokenManager(b"")

    def test_empty_secret_list_rejected(self):
        with self.assertRaises(ConfigurationError):
            TokenManager([])

    def test_bad_secret_type_rejected(self):
        with self.assertRaises(ConfigurationError):
            TokenManager(12345)

    def test_string_secret_accepted(self):
        m = TokenManager("a" * 24)
        self.assertTrue(m.verify(m.issue("s"), "s"))

    def test_bytearray_secret_accepted(self):
        m = TokenManager(bytearray(b"a" * 24))
        self.assertTrue(m.verify(m.issue("s"), "s"))

    def test_zero_ttl_rejected(self):
        with self.assertRaises(ConfigurationError):
            TokenManager(SECRET, ttl=0)

    def test_negative_ttl_rejected(self):
        with self.assertRaises(ConfigurationError):
            TokenManager(SECRET, ttl=-1)

    def test_negative_skew_rejected(self):
        with self.assertRaises(ConfigurationError):
            TokenManager(SECRET, clock_skew=-1)

    def test_skew_ge_ttl_rejected(self):
        with self.assertRaises(ConfigurationError):
            TokenManager(SECRET, ttl=60, clock_skew=60)

    def test_empty_purpose_rejected(self):
        with self.assertRaises(ConfigurationError):
            TokenManager(SECRET, purpose="")

    def test_empty_salt_rejected(self):
        with self.assertRaises(ConfigurationError):
            TokenManager(SECRET, session_salt="")

    def test_duplicate_keys_rejected(self):
        with self.assertRaises(ConfigurationError):
            TokenManager([SECRET, SECRET])

    def test_bad_nonsecret_type_in_list_rejected(self):
        with self.assertRaises(ConfigurationError):
            TokenManager([SECRET, None])

    def test_key_count(self):
        self.assertEqual(manager(secrets=[SECRET, b"b" * 24, b"c" * 24]).key_count, 3)

    def test_empty_session_rejected(self):
        with self.assertRaises(TokenError):
            manager().issue("")

    def test_non_string_session_rejected(self):
        with self.assertRaises(TokenError):
            manager().issue(None)


class ExpiryTests(unittest.TestCase):
    def test_expired_token_rejected(self):
        m = manager(ttl=60, clock_skew=0)
        token = m.issue(SESSION, now=1000)
        with self.assertRaises(TokenError):
            m.verify(token, SESSION, now=1100)

    def test_token_at_expiry_boundary_with_skew(self):
        m = manager(ttl=60, clock_skew=10)
        token = m.issue(SESSION, now=1000)
        m.verify(token, SESSION, now=1069)

    def test_token_past_expiry_skew_rejected(self):
        m = manager(ttl=60, clock_skew=10)
        token = m.issue(SESSION, now=1000)
        with self.assertRaises(TokenError):
            m.verify(token, SESSION, now=1070)

    def test_future_token_rejected(self):
        m = manager(ttl=60, clock_skew=10)
        token = m.issue(SESSION, now=2000)
        with self.assertRaises(TokenError):
            m.verify(token, SESSION, now=1980)

    def test_future_token_within_skew_accepted(self):
        m = manager(ttl=60, clock_skew=10)
        token = m.issue(SESSION, now=2000)
        m.verify(token, SESSION, now=1991)

    def test_inflated_lifetime_rejected(self):
        m = manager(ttl=60, clock_skew=10)
        raw = bytearray(unb64(m.issue(SESSION, now=1000)))
        binding_len = struct.unpack_from(">I", raw, 4)[0]
        expires_offset = 4 + 4 + binding_len
        raw[expires_offset:expires_offset + 4] = pack_u32(9999)
        with self.assertRaises(TokenError):
            m.verify(resign(bytes(raw)), SESSION, now=1000)

    def test_negative_now_issue_rejected(self):
        with self.assertRaises(TokenError):
            manager().issue(SESSION, now=-1)


class RotationTests(unittest.TestCase):
    def test_fallback_key_verifies(self):
        rotating = manager(secrets=[SECRET, b"f" * 24])
        legacy = manager(secrets=b"f" * 24)
        token = legacy.issue(SESSION, now=now())
        self.assertTrue(rotating.verify(token, SESSION, now=now()))

    def test_wrong_key_rejected(self):
        token = manager().issue(SESSION, now=now())
        with self.assertRaises(TokenError):
            manager(secrets=[b"z" * 24]).verify(token, SESSION, now=now())

    def test_primary_key_signs(self):
        m = manager(secrets=[SECRET, b"f" * 24])
        self.assertTrue(manager(secrets=[SECRET]).verify(m.issue(SESSION, now=now()), SESSION, now=now()))

    def test_fallback_only_token_rejected_after_rotation(self):
        fallback = manager(secrets=[b"f" * 24])
        token = fallback.issue(SESSION, now=now())
        with self.assertRaises(TokenError):
            manager(secrets=[SECRET]).verify(token, SESSION, now=now())


class CanonicalEncodingTests(unittest.TestCase):
    def test_separator_collision_a_b_plus_c(self):
        # Length prefixes make ("a|b", "c") distinct from ("a", "b|c").
        one = _canonical("a|b", 1, 2, b"x", "c")
        two = _canonical("a", 1, 2, b"x", "b|c")
        self.assertNotEqual(one, two)

    def test_empty_purpose_distinct(self):
        self.assertNotEqual(
            _canonical("abc", 1, 2, b"n", ""),
            _canonical("abc", 1, 2, b"n", "x"),
        )

    def test_nonce_boundary_distinct(self):
        self.assertNotEqual(
            _canonical("abc", 1, 2, b"ab", "c"),
            _canonical("abc", 1, 2, b"a", "bc"),
        )

    def test_version_is_u32_be(self):
        self.assertEqual(_canonical("a", 1, 2, b"n", "p")[:4], b"\x00\x00\x00\x01")

    def test_b64decode_rejects_bad_padding(self):
        with self.assertRaises(TokenError):
            _b64decode("A", error=TokenError("bad"))

    def test_b64decode_rejects_whitespace(self):
        with self.assertRaises(TokenError):
            _b64decode("AAAA\n", error=TokenError("bad"))

    def test_b64decode_accepts_canonical(self):
        self.assertEqual(_b64decode("AAAA", error=TokenError("bad")), b"\x00\x00\x00")

    def test_hmac_uses_sha256(self):
        m = manager()
        token = m.issue(SESSION, now=now())
        payload = unb64(token)[:-32]
        expected = hmac.new(SECRET, payload, hashlib.sha256).digest()
        self.assertEqual(unb64(token)[-32:], expected)


if __name__ == "__main__":
    unittest.main()


class HardeningTests(unittest.TestCase):
    def test_noncanonical_base64_rejected(self):
        with self.assertRaises(TokenError):
            _b64decode("AB", error=TokenError("bad"))

    def test_huge_timestamp_rejected(self):
        with self.assertRaises(TokenError):
            manager().issue(SESSION, now=0xFFFFFFFF)

    def test_purpose_mismatch_rejected(self):
        token = manager(purpose="a").issue(SESSION, now=now())
        with self.assertRaises(TokenError):
            manager(purpose="b").verify(token, SESSION, now=now())

    def test_session_salt_mismatch_rejected(self):
        token = manager(session_salt="a").issue(SESSION, now=now())
        with self.assertRaises(TokenError):
            manager(session_salt="b").verify(token, SESSION, now=now())

    def test_binding_is_domain_separated(self):
        self.assertNotEqual(
            manager(session_salt="a").bind_session(SESSION),
            manager(session_salt="b").bind_session(SESSION),
        )

    def test_issue_verify_across_key_rotation_window(self):
        old = manager(secrets=b"o" * 24)
        rotated = manager(secrets=[SECRET, b"o" * 24])
        self.assertTrue(rotated.verify(old.issue(SESSION, now=now()), SESSION, now=now()))
