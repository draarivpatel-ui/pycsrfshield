"""Cookie parsing, duplicate defense and hardened attribute tests."""

from __future__ import annotations

import unittest

from pycsrfshield import CookieError
from pycsrfshield.cookies import (
    decode_cookie_value,
    format_cookie,
    get_cookie_values,
    parse_cookie_header,
    split_cookie_header,
    unique_cookie_value,
)

NAME = "__Host-pycsrfshield"


class SplitHeaderTests(unittest.TestCase):
    def test_empty_header(self):
        self.assertEqual(split_cookie_header(""), [""])

    def test_single_cookie(self):
        self.assertEqual(split_cookie_header("a=1"), ["a=1"])

    def test_two_cookies(self):
        self.assertEqual(split_cookie_header("a=1; b=2"), ["a=1", " b=2"])

    def test_semicolon_in_quotes_preserved(self):
        self.assertEqual(split_cookie_header('a="1;2"; b=3'), ['a="1;2"', " b=3"])

    def test_backslash_does_not_escape_quote(self):
        with self.assertRaises(CookieError):
            split_cookie_header('a="1\\";2"; b=3')

    def test_unterminated_quote_rejected(self):
        with self.assertRaises(CookieError):
            split_cookie_header('a="1;2')

    def test_non_string_rejected(self):
        with self.assertRaises(CookieError):
            split_cookie_header(None)

    def test_trailing_semicolon(self):
        self.assertEqual(split_cookie_header("a=1;"), ["a=1", ""])


class ParseHeaderTests(unittest.TestCase):
    def test_none_header(self):
        self.assertEqual(parse_cookie_header(None), {})

    def test_empty_header(self):
        self.assertEqual(parse_cookie_header(""), {})

    def test_simple_pair(self):
        self.assertEqual(parse_cookie_header("a=1"), {"a": ["1"]})

    def test_multiple_names(self):
        self.assertEqual(parse_cookie_header("a=1; b=2"), {"a": ["1"], "b": ["2"]})

    def test_duplicate_names_preserved(self):
        self.assertEqual(parse_cookie_header("a=1; a=2; a=3"), {"a": ["1", "2", "3"]})

    def test_whitespace_trimmed(self):
        self.assertEqual(parse_cookie_header(" a = 1 ; b = 2 "), {"a": ["1"], "b": ["2"]})

    def test_quoted_value_preserved_as_wire_value(self):
        self.assertEqual(parse_cookie_header('a="hello"'), {"a": ['"hello"']})

    def test_quoted_semicolon_rejected(self):
        with self.assertRaises(CookieError):
            parse_cookie_header('a="1;2"')

    def test_empty_value(self):
        self.assertEqual(parse_cookie_header("a="), {"a": [""]})

    def test_malformed_pair_rejected(self):
        with self.assertRaises(CookieError):
            parse_cookie_header("novalue")

    def test_invalid_name_space_rejected(self):
        with self.assertRaises(CookieError):
            parse_cookie_header("a b=1")

    def test_equals_after_first_is_part_of_value(self):
        self.assertEqual(parse_cookie_header("a=b=1"), {"a": ["b=1"]})

    def test_comma_in_value_rejected(self):
        with self.assertRaises(CookieError):
            parse_cookie_header("a=1,2")

    def test_space_inside_value_rejected(self):
        with self.assertRaises(CookieError):
            parse_cookie_header('a="has space"')

    def test_invalid_value_control_char_rejected(self):
        with self.assertRaises(CookieError):
            parse_cookie_header("a=\x01")

    def test_invalid_value_semicolon_rejected(self):
        with self.assertRaises(CookieError):
            parse_cookie_header('a=1"2')

    def test_percent_encoded_value_preserved(self):
        self.assertEqual(parse_cookie_header("a=%41%42"), {"a": ["%41%42"]})

    def test_unicode_value_rejected(self):
        with self.assertRaises(CookieError):
            parse_cookie_header("a=é")


    def test_multiple_cookie_header_fields_preserve_duplicates(self):
        self.assertEqual(parse_cookie_header(["a=1", "a=2"]), {"a": ["1", "2"]})

    def test_multiple_cookie_header_fields_unique_names(self):
        self.assertEqual(parse_cookie_header(["a=1", "b=2"]), {"a": ["1"], "b": ["2"]})

    def test_header_sequence_rejects_non_text(self):
        with self.assertRaises(CookieError):
            parse_cookie_header(["a=1", b"b=2"])

class DuplicateDefenseTests(unittest.TestCase):
    def test_unique_value_single(self):
        self.assertEqual(unique_cookie_value("a=1; b=2", "a"), "1")

    def test_unique_value_missing(self):
        self.assertIsNone(unique_cookie_value("a=1", "b"))

    def test_unique_value_duplicate_rejected(self):
        self.assertIsNone(unique_cookie_value("a=1; a=2", "a"))

    def test_unique_value_triple_rejected(self):
        self.assertIsNone(unique_cookie_value("a=1; a=1; a=1", "a"))

    def test_cookie_tossing_subdomain_duplicate_rejected(self):
        header = "%s=%s; %s=tossed" % (NAME, "good", NAME)
        self.assertIsNone(unique_cookie_value(header, NAME))

    def test_similar_name_not_confused(self):
        header = "%s=good; %s-extra=evil" % (NAME, NAME)
        self.assertEqual(unique_cookie_value(header, NAME), "good")

    def test_suffix_name_not_confused(self):
        header = "extra-%s=evil; %s=good" % (NAME, NAME)
        self.assertEqual(unique_cookie_value(header, NAME), "good")

    def test_case_sensitive_name(self):
        self.assertIsNone(unique_cookie_value("ABC=1", "abc"))

    def test_get_values_all(self):
        self.assertEqual(get_cookie_values("a=1; a=2", "a"), ["1", "2"])

    def test_get_values_missing(self):
        self.assertEqual(get_cookie_values("a=1", "b"), [])

    def test_get_values_invalid_name(self):
        with self.assertRaises(CookieError):
            get_cookie_values("a=1", "bad name")


class DecodeTests(unittest.TestCase):
    def test_plain_value(self):
        self.assertEqual(decode_cookie_value("abc"), "abc")

    def test_percent_decoded(self):
        self.assertEqual(decode_cookie_value("%41%42%43"), "ABC")

    def test_utf8_decoded(self):
        self.assertEqual(decode_cookie_value("%C3%A9"), "é")

    def test_invalid_utf8_rejected(self):
        with self.assertRaises(CookieError):
            decode_cookie_value("%FF")

    def test_plus_is_literal(self):
        self.assertEqual(decode_cookie_value("a+b"), "a+b")


class FormatCookieTests(unittest.TestCase):
    def test_default_attributes(self):
        cookie = format_cookie(NAME, "abc")
        self.assertIn("Secure", cookie)
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)
        self.assertIn("Path=/", cookie)
        self.assertTrue(cookie.startswith(NAME + "=abc;"))

    def test_host_prefix_has_no_domain(self):
        cookie = format_cookie(NAME, "abc")
        self.assertNotIn("Domain=", cookie)

    def test_host_prefix_domain_rejected(self):
        with self.assertRaises(CookieError):
            format_cookie(NAME, "abc", domain="example.com")

    def test_secure_prefix_requires_secure(self):
        with self.assertRaises(CookieError):
            format_cookie("__Secure-csrf", "abc", secure=False)

    def test_secure_prefix_case_variants_require_secure(self):
        for name in ("__secure-csrf", "__SECURE-csrf", "__SeCuRe-csrf"):
            with self.subTest(name=name):
                with self.assertRaises(CookieError):
                    format_cookie(name, "abc", secure=False)

    def test_host_prefix_case_variants_enforce_invariants(self):
        for name in ("__host-csrf", "__HOST-csrf", "__HoSt-csrf"):
            with self.subTest(name=name):
                with self.assertRaises(CookieError):
                    format_cookie(name, "abc", path="/app")
                with self.assertRaises(CookieError):
                    format_cookie(name, "abc", domain="example.com")
                with self.assertRaises(CookieError):
                    format_cookie(name, "abc", secure=False)

    def test_non_host_prefix_domain_allowed(self):
        cookie = format_cookie("csrf", "abc", domain="example.com")
        self.assertIn("Domain=example.com", cookie)

    def test_max_age_included(self):
        self.assertIn("Max-Age=600", format_cookie("csrf", "abc", max_age=600))

    def test_negative_max_age_rejected(self):
        with self.assertRaises(CookieError):
            format_cookie("csrf", "abc", max_age=-1)

    def test_float_max_age_rejected(self):
        with self.assertRaises(CookieError):
            format_cookie("csrf", "abc", max_age=1.5)

    def test_samesite_strict(self):
        self.assertIn("SameSite=Strict", format_cookie("csrf", "abc", samesite="strict"))

    def test_samesite_none_requires_secure(self):
        with self.assertRaises(CookieError):
            format_cookie("csrf", "abc", samesite="none", secure=False)

    def test_samesite_none_with_secure(self):
        self.assertIn("SameSite=None", format_cookie("csrf", "abc", samesite="none"))

    def test_bad_samesite_rejected(self):
        with self.assertRaises(CookieError):
            format_cookie("csrf", "abc", samesite="invalid")

    def test_bad_path_rejected(self):
        with self.assertRaises(CookieError):
            format_cookie("csrf", "abc", path="relative")

    def test_insecure_allowed_when_requested(self):
        self.assertNotIn("Secure", format_cookie("csrf", "abc", secure=False))

    def test_httponly_can_be_disabled(self):
        self.assertNotIn("HttpOnly", format_cookie("csrf", "abc", httponly=False))

    def test_crlf_in_value_rejected(self):
        with self.assertRaises(CookieError):
            format_cookie("csrf", "a\r\nSet-Cookie: x=1")

    def test_semicolon_in_value_rejected(self):
        with self.assertRaises(CookieError):
            format_cookie("csrf", "a;b")

    def test_non_ascii_value_rejected(self):
        with self.assertRaises(CookieError):
            format_cookie("csrf", "é")

    def test_invalid_name_rejected(self):
        with self.assertRaises(CookieError):
            format_cookie("bad name", "abc")


if __name__ == "__main__":
    unittest.main()
