"""Origin, Referer and Fetch Metadata defense tests."""

from __future__ import annotations

import unittest

from pycsrfshield import OriginError, OriginValidator
from pycsrfshield.origin import is_safe_method, normalize_method, normalize_origin, origins_match

EXPECTED = "https://app.example.com"


class NormalizationTests(unittest.TestCase):
    def test_lowercase_scheme_and_host(self):
        self.assertEqual(normalize_origin("HTTPS://APP.EXAMPLE.COM"), EXPECTED)

    def test_default_https_port_omitted(self):
        self.assertEqual(normalize_origin("https://app.example.com:443"), EXPECTED)

    def test_default_http_port_omitted(self):
        self.assertEqual(normalize_origin("http://app.example.com:80"), "http://app.example.com")

    def test_nondefault_port_kept(self):
        self.assertEqual(normalize_origin("https://app.example.com:8443"), "https://app.example.com:8443")

    def test_trailing_slash_accepted(self):
        self.assertEqual(normalize_origin("https://app.example.com/"), EXPECTED)

    def test_trailing_dot_host_is_significant(self):
        self.assertEqual(normalize_origin("https://app.example.com."), EXPECTED + ".")
        self.assertFalse(origins_match("https://app.example.com.", EXPECTED))

    def test_origins_match(self):
        self.assertTrue(origins_match("https://APP.example.com:443", EXPECTED))

    def test_scheme_mismatch_rejected(self):
        self.assertFalse(origins_match("http://app.example.com", EXPECTED))

    def test_host_prefix_trick_rejected(self):
        self.assertFalse(origins_match("https://app.example.com.evil.com", EXPECTED))

    def test_host_suffix_trick_rejected(self):
        self.assertFalse(origins_match("https://evil-app.example.com", EXPECTED))

    def test_userinfo_trick_rejected(self):
        self.assertFalse(origins_match("https://app.example.com@evil.com", EXPECTED))

    def test_userinfo_with_password_rejected(self):
        self.assertFalse(origins_match("https://user:pass@app.example.com", EXPECTED))

    def test_null_origin_rejected(self):
        self.assertFalse(origins_match("null", EXPECTED))

    def test_path_rejected(self):
        with self.assertRaises(OriginError):
            normalize_origin("https://app.example.com/login")

    def test_query_rejected(self):
        with self.assertRaises(OriginError):
            normalize_origin("https://app.example.com/?x=1")

    def test_fragment_rejected(self):
        with self.assertRaises(OriginError):
            normalize_origin("https://app.example.com/#x")

    def test_backslash_rejected(self):
        with self.assertRaises(OriginError):
            normalize_origin("https://app.example.com\\@evil.com")

    def test_whitespace_rejected(self):
        with self.assertRaises(OriginError):
            normalize_origin("https://app.example.com\n/evil")

    def test_ftp_scheme_rejected(self):
        with self.assertRaises(OriginError):
            normalize_origin("ftp://app.example.com")

    def test_javascript_scheme_rejected(self):
        with self.assertRaises(OriginError):
            normalize_origin("javascript:alert(1)")

    def test_missing_host_rejected(self):
        with self.assertRaises(OriginError):
            normalize_origin("https://")

    def test_bad_port_rejected(self):
        with self.assertRaises(OriginError):
            normalize_origin("https://app.example.com:abc")

    def test_zero_port_rejected(self):
        with self.assertRaises(OriginError):
            normalize_origin("https://app.example.com:0")

    def test_port_out_of_range_rejected(self):
        with self.assertRaises(OriginError):
            normalize_origin("https://app.example.com:70000")

    def test_empty_origin_rejected(self):
        with self.assertRaises(OriginError):
            normalize_origin("")

    def test_non_string_origin_rejected(self):
        with self.assertRaises(OriginError):
            normalize_origin(123)

    def test_ws_scheme_accepted_for_same_host(self):
        self.assertTrue(origins_match("wss://app.example.com", "wss://app.example.com"))


    def test_ipv6_origin_normalized(self):
        self.assertEqual(
            normalize_origin("https://[2001:0db8:0000:0000:0000:0000:0000:0001]:443"),
            "https://[2001:db8::1]",
        )

    def test_ipv6_nondefault_port(self):
        self.assertEqual(normalize_origin("https://[::1]:8443"), "https://[::1]:8443")

    def test_ipv4_canonicalized(self):
        self.assertEqual(normalize_origin("https://192.0.2.10:443"), "https://192.0.2.10")

    def test_bad_ipv4_rejected(self):
        with self.assertRaises(OriginError):
            normalize_origin("https://999.999.999.999")

    def test_percent_in_host_rejected(self):
        with self.assertRaises(OriginError):
            normalize_origin("https://app%2eexample.com")

    def test_underscore_host_rejected(self):
        with self.assertRaises(OriginError):
            normalize_origin("https://app_example.com")

    def test_empty_port_rejected(self):
        with self.assertRaises(OriginError):
            normalize_origin("https://app.example.com:")

    def test_non_ascii_host_rejected(self):
        with self.assertRaises(OriginError):
            normalize_origin("https://exámple.com")

class MethodTests(unittest.TestCase):
    def test_get_is_safe(self):
        self.assertTrue(is_safe_method("GET"))

    def test_lowercase_get_is_safe(self):
        self.assertTrue(is_safe_method("get"))

    def test_mixed_case_head_is_safe(self):
        self.assertTrue(is_safe_method("HeAd"))

    def test_options_is_safe(self):
        self.assertTrue(is_safe_method("OPTIONS"))

    def test_trace_is_safe(self):
        self.assertTrue(is_safe_method("TRACE"))

    def test_post_is_unsafe(self):
        self.assertFalse(is_safe_method("POST"))

    def test_put_is_unsafe(self):
        self.assertFalse(is_safe_method("PUT"))

    def test_delete_is_unsafe(self):
        self.assertFalse(is_safe_method("DELETE"))

    def test_patch_is_unsafe(self):
        self.assertFalse(is_safe_method("PATCH"))

    def test_blank_method_rejected(self):
        with self.assertRaises(OriginError):
            normalize_method("   ")

    def test_digit_method_token_is_valid_but_unsafe(self):
        self.assertEqual(normalize_method("GE1"), "GE1")
        self.assertFalse(is_safe_method("GE1"))

    def test_separator_in_method_rejected(self):
        with self.assertRaises(OriginError):
            normalize_method("GE@T")

    def test_non_string_method_rejected(self):
        with self.assertRaises(OriginError):
            normalize_method(None)

    def test_is_safe_method_handles_invalid(self):
        self.assertFalse(is_safe_method(None))


class ValidatorConstructionTests(unittest.TestCase):
    def test_single_origin(self):
        OriginValidator(EXPECTED)

    def test_origin_list(self):
        OriginValidator([EXPECTED, "https://other.example.com"])

    def test_origin_tuple(self):
        OriginValidator((EXPECTED,))

    def test_empty_list_rejected(self):
        with self.assertRaises(OriginError):
            OriginValidator([])

    def test_bad_origin_rejected(self):
        with self.assertRaises(OriginError):
            OriginValidator("null")

    def test_non_iterable_rejected(self):
        with self.assertRaises(OriginError):
            OriginValidator(123)


class OriginHeaderTests(unittest.TestCase):
    def setUp(self):
        self.v = OriginValidator(EXPECTED, allow_missing_referer=True)

    def test_matching_origin_passes(self):
        self.v.validate_origin(EXPECTED)

    def test_matching_origin_case_insensitive(self):
        self.v.validate_origin("https://APP.example.com:443")

    def test_cross_site_origin_rejected(self):
        with self.assertRaises(OriginError):
            self.v.validate_origin("https://evil.com")

    def test_null_origin_rejected(self):
        with self.assertRaises(OriginError):
            self.v.validate_origin("null")

    def test_undefined_origin_rejected(self):
        with self.assertRaises(OriginError):
            self.v.validate_origin("undefined")

    def test_userinfo_origin_rejected(self):
        with self.assertRaises(OriginError):
            self.v.validate_origin("https://app.example.com@evil.com")

    def test_prefix_trick_rejected(self):
        with self.assertRaises(OriginError):
            self.v.validate_origin("https://app.example.com.evil.com")

    def test_suffix_trick_rejected(self):
        with self.assertRaises(OriginError):
            self.v.validate_origin("https://sub.app.example.com")

    def test_scheme_downgrade_rejected(self):
        with self.assertRaises(OriginError):
            self.v.validate_origin("http://app.example.com")

    def test_missing_origin_rejected_by_default(self):
        with self.assertRaises(OriginError):
            self.v.validate_origin(None)

    def test_missing_origin_allowed_when_configured(self):
        v = OriginValidator(EXPECTED, allow_missing_origin=True)
        v.validate_origin(None)

    def test_blank_origin_treated_as_missing(self):
        with self.assertRaises(OriginError):
            self.v.validate_origin("")


class RefererHeaderTests(unittest.TestCase):
    def setUp(self):
        self.v = OriginValidator(EXPECTED)

    def test_matching_referer_passes(self):
        self.v.validate_referer(EXPECTED + "/transfer?x=1")

    def test_cross_site_referer_rejected(self):
        with self.assertRaises(OriginError):
            self.v.validate_referer("https://evil.com/page")

    def test_null_referer_rejected(self):
        with self.assertRaises(OriginError):
            self.v.validate_referer("null")

    def test_missing_referer_allowed_by_default(self):
        self.v.validate_referer(None)

    def test_missing_referer_rejected_when_configured(self):
        v = OriginValidator(EXPECTED, allow_missing_referer=False)
        with self.assertRaises(OriginError):
            v.validate_referer(None)

    def test_userinfo_referer_rejected(self):
        with self.assertRaises(OriginError):
            self.v.validate_referer("https://app.example.com@evil.com/x")


class FetchMetadataTests(unittest.TestCase):
    def setUp(self):
        self.v = OriginValidator(EXPECTED)

    def test_same_origin_passes(self):
        self.v.validate_fetch_metadata({"Sec-Fetch-Site": "same-origin"})

    def test_same_site_passes_by_default(self):
        self.v.validate_fetch_metadata({"sec-fetch-site": "same-site"})

    def test_none_passes(self):
        self.v.validate_fetch_metadata({"Sec-Fetch-Site": "none"})

    def test_missing_header_passes(self):
        self.v.validate_fetch_metadata({})

    def test_cross_site_rejected(self):
        with self.assertRaises(OriginError):
            self.v.validate_fetch_metadata({"Sec-Fetch-Site": "cross-site"})

    def test_cross_site_case_insensitive_rejected(self):
        with self.assertRaises(OriginError):
            self.v.validate_fetch_metadata({"sec-fetch-site": "CROSS-SITE"})

    def test_same_site_can_be_rejected(self):
        v = OriginValidator(EXPECTED, allow_same_site_fetch=False)
        with self.assertRaises(OriginError):
            v.validate_fetch_metadata({"Sec-Fetch-Site": "same-site"})

    def test_invalid_value_rejected(self):
        with self.assertRaises(OriginError):
            self.v.validate_fetch_metadata({"Sec-Fetch-Site": "same-origin-evil"})

    def test_empty_value_rejected(self):
        with self.assertRaises(OriginError):
            self.v.validate_fetch_metadata({"Sec-Fetch-Site": ""})
    def test_duplicate_fetch_metadata_rejected(self):
        with self.assertRaises(OriginError):
            self.v.validate_fetch_metadata({"Sec-Fetch-Site": "same-origin", "sec-fetch-site": "cross-site"})



class CombinedValidationTests(unittest.TestCase):
    def setUp(self):
        self.v = OriginValidator(EXPECTED, allow_missing_referer=True)

    def test_safe_method_skips_origin_requirement(self):
        self.v.validate("GET", {})

    def test_safe_method_case_insensitive(self):
        self.v.validate("head", {})

    def test_safe_method_still_checks_fetch_metadata(self):
        with self.assertRaises(OriginError):
            self.v.validate("get", {"Sec-Fetch-Site": "cross-site"})

    def test_unsafe_method_requires_origin(self):
        with self.assertRaises(OriginError):
            self.v.validate("POST", {})

    def test_valid_post_passes(self):
        self.v.validate("POST", {"Origin": EXPECTED})

    def test_valid_post_with_mix_case_keys(self):
        self.v.validate("post", {"origin": EXPECTED, "Referer": EXPECTED + "/x"})

    def test_cross_site_post_rejected(self):
        with self.assertRaises(OriginError):
            self.v.validate("POST", {"Origin": "https://evil.com"})

    def test_cross_site_fetch_rejected_even_with_matching_origin(self):
        with self.assertRaises(OriginError):
            self.v.validate("POST", {"Origin": EXPECTED, "Sec-Fetch-Site": "cross-site"})

    def test_invalid_method_rejected(self):
        with self.assertRaises(OriginError):
            self.v.validate("", {})


if __name__ == "__main__":
    unittest.main()
