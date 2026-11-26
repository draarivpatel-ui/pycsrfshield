"""WSGI middleware integration tests."""

from __future__ import annotations

import io
import json
import unittest
from urllib.parse import quote

from pycsrfshield import PyCSRFShieldWSGI, TokenManager

from _support import (
    ORIGIN,
    SECRET,
    StartResponse,
    collect,
    manager,
    wsgi_environ,
)

COOKIE = "__Host-pycsrfshield"


def app(environ, start_response):
    body = environ["wsgi.input"].read()
    start_response("200 OK", [("Content-Type", "text/plain")])
    return [b"ok:" + body]


def shield(**kwargs):
    opts = {"expected_origin": ORIGIN, "session_id": "session-42", "allow_missing_referer": True}
    opts.update(kwargs)
    return PyCSRFShieldWSGI(app, manager(), **opts)


def good_request(m=None, **extra):
    m = m or manager()
    cookie_token, transport_token = m.issue_pair("session-42")
    headers = {"Origin": ORIGIN}
    headers.update(extra.pop("headers", {}))
    return wsgi_environ(
        "POST",
        cookies="%s=%s" % (COOKIE, cookie_token),
        headers=headers,
        body=("X-CSRF-Token=" + quote(transport_token)).encode(),
        **extra,
    )


class WSGIHappyPathTests(unittest.TestCase):
    def test_valid_post_passes(self):
        start = StartResponse()
        collect(shield(), good_request(), start)
        self.assertEqual(start.status, "200 OK")

    def test_body_replayed_to_app(self):
        start = StartResponse()
        captured = []

        def capturing_app(environ, sr):
            captured.append(environ["wsgi.input"].read())
            sr("200 OK", [])
            return [b"ok"]

        mw = PyCSRFShieldWSGI(capturing_app, manager(), expected_origin=ORIGIN, session_id="session-42", allow_missing_referer=True)
        cookie_token, transport_token = mw.core.tokens.issue_pair("session-42")
        body = ("X-CSRF-Token=" + quote(transport_token)).encode()
        env = wsgi_environ("POST", cookies="%s=%s" % (COOKIE, cookie_token), headers={"Origin": ORIGIN}, body=body)
        collect(mw, env, StartResponse())
        self.assertEqual(captured[0], body)

    def test_set_cookie_emitted(self):
        start = StartResponse()
        collect(shield(), good_request(), start)
        cookie = start.header("Set-Cookie")
        self.assertIsNotNone(cookie)
        self.assertIn("Secure", cookie)
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)

    def test_cache_control_no_store(self):
        start = StartResponse()
        collect(shield(), good_request(), start)
        self.assertEqual(start.header("Cache-Control"), "no-store")

    def test_get_without_token_passes(self):
        start = StartResponse()
        collect(shield(), wsgi_environ("GET"), start)
        self.assertEqual(start.status, "200 OK")

    def test_head_without_token_passes(self):
        start = StartResponse()
        collect(shield(), wsgi_environ("HEAD"), start)
        self.assertEqual(start.status, "200 OK")

    def test_options_without_token_passes(self):
        start = StartResponse()
        collect(shield(), wsgi_environ("OPTIONS"), start)
        self.assertEqual(start.status, "200 OK")

    def test_lowercase_get_passes(self):
        start = StartResponse()
        collect(shield(), wsgi_environ("get"), start)
        self.assertEqual(start.status, "200 OK")

    def test_form_body_token_accepted(self):
        start = StartResponse()
        m = manager()
        cookie_token, transport_token = m.issue_pair("session-42")
        env = wsgi_environ("POST", cookies="%s=%s" % (COOKIE, cookie_token), headers={"Origin": ORIGIN}, body=("csrf_token=" + quote(transport_token)).encode())
        collect(shield(), env, start)
        self.assertEqual(start.status, "200 OK")

    def test_custom_header_name(self):
        start = StartResponse()
        m = manager()
        cookie_token, transport_token = m.issue_pair("session-42")
        env = wsgi_environ("POST", cookies="%s=%s" % (COOKIE, cookie_token), headers={"Origin": ORIGIN, "X-Token": transport_token})
        mw = PyCSRFShieldWSGI(app, manager(), expected_origin=ORIGIN, session_id="session-42", header_name="X-Token", allow_missing_referer=True)
        collect(mw, env, start)
        self.assertEqual(start.status, "200 OK")

    def test_custom_cookie_name(self):
        start = StartResponse()
        m = manager()
        cookie_token, transport_token = m.issue_pair("session-42")
        env = wsgi_environ("POST", cookies="csrf=%s" % cookie_token, headers={"Origin": ORIGIN, "X-CSRF-Token": transport_token})
        mw = PyCSRFShieldWSGI(app, manager(), expected_origin=ORIGIN, session_id="session-42", cookie_name="csrf", allow_missing_referer=True)
        collect(mw, env, start)
        self.assertEqual(start.status, "200 OK")

    def test_unmasked_mode(self):
        start = StartResponse()
        m = manager()
        token = m.issue("session-42")
        env = wsgi_environ("POST", cookies="%s=%s" % (COOKIE, token), headers={"Origin": ORIGIN, "X-CSRF-Token": token})
        mw = PyCSRFShieldWSGI(app, manager(), expected_origin=ORIGIN, session_id="session-42", mask_tokens=False, allow_missing_referer=True)
        collect(mw, env, start)
        self.assertEqual(start.status, "200 OK")


class WSGIRejectionTests(unittest.TestCase):
    def assert_denied(self, env, **kwargs):
        start = StartResponse()
        body = collect(shield(**kwargs), env, start)
        self.assertEqual(start.status, "403 Forbidden")
        return json.loads(body)

    def test_missing_token_denied(self):
        data = self.assert_denied(wsgi_environ("POST", headers={"Origin": ORIGIN}))
        self.assertIn("detail", data)

    def test_missing_cookie_denied(self):
        m = manager()
        token = m.mint("session-42")
        self.assert_denied(wsgi_environ("POST", headers={"Origin": ORIGIN, "X-CSRF-Token": token}))

    def test_duplicate_cookie_denied(self):
        m = manager()
        cookie_token, transport_token = m.issue_pair("session-42")
        env = wsgi_environ("POST", cookies="%s=%s; %s=tossed" % (COOKIE, cookie_token, COOKIE), headers={"Origin": ORIGIN, "X-CSRF-Token": transport_token})
        self.assert_denied(env)

    def test_mismatched_token_denied(self):
        m = manager()
        cookie_token, _ = m.issue_pair("session-42")
        _, transport_token = m.issue_pair("session-42")
        env = wsgi_environ("POST", cookies="%s=%s" % (COOKIE, cookie_token), headers={"Origin": ORIGIN, "X-CSRF-Token": transport_token})
        self.assert_denied(env)

    def test_forged_token_denied(self):
        m = manager()
        cookie_token, _ = m.issue_pair("session-42")
        env = wsgi_environ("POST", cookies="%s=%s" % (COOKIE, cookie_token), headers={"Origin": ORIGIN, "X-CSRF-Token": "forged"})
        self.assert_denied(env)

    def test_expired_token_denied(self):
        m = manager(ttl=10, clock_skew=0)
        cookie_token, transport_token = m.issue_pair("session-42", now=1000)
        env = wsgi_environ("POST", cookies="%s=%s" % (COOKIE, cookie_token), headers={"Origin": ORIGIN, "X-CSRF-Token": transport_token})
        self.assert_denied(env)

    def test_wrong_session_denied(self):
        m = manager()
        cookie_token, transport_token = m.issue_pair("other")
        env = wsgi_environ("POST", cookies="%s=%s" % (COOKIE, cookie_token), headers={"Origin": ORIGIN, "X-CSRF-Token": transport_token})
        self.assert_denied(env)

    def test_cross_site_origin_denied(self):
        self.assert_denied(good_request(headers={"Origin": "https://evil.com"}))

    def test_null_origin_denied(self):
        self.assert_denied(good_request(headers={"Origin": "null"}))

    def test_cross_site_fetch_metadata_denied(self):
        self.assert_denied(good_request(headers={"Sec-Fetch-Site": "cross-site"}))

    def test_bad_cookie_name_denied(self):
        m = manager()
        cookie_token, transport_token = m.issue_pair("session-42")
        env = wsgi_environ("POST", cookies="bad name=%s" % cookie_token, headers={"Origin": ORIGIN, "X-CSRF-Token": transport_token})
        self.assert_denied(env)

    def test_header_and_form_mismatch_denied(self):
        m = manager()
        cookie_token, transport_token = m.issue_pair("session-42")
        env = wsgi_environ("POST", cookies="%s=%s" % (COOKIE, cookie_token), headers={"Origin": ORIGIN, "X-CSRF-Token": transport_token}, body="csrf_token=other".encode())
        self.assert_denied(env)

    def test_oversized_form_denied(self):
        m = manager()
        cookie_token, transport_token = m.issue_pair("session-42")
        body = b"csrf_token=" + b"x" * (1 << 21)
        env = wsgi_environ("POST", cookies="%s=%s" % (COOKIE, cookie_token), headers={"Origin": ORIGIN, "X-CSRF-Token": transport_token}, body=body)
        self.assert_denied(env)

    def test_form_extraction_disabled_denied(self):
        m = manager()
        cookie_token, transport_token = m.issue_pair("session-42")
        env = wsgi_environ("POST", cookies="%s=%s" % (COOKIE, cookie_token), headers={"Origin": ORIGIN}, body=("csrf_token=" + quote(transport_token)).encode())
        self.assert_denied(env, allow_form=False)

    def test_negative_content_length_denied(self):
        env = good_request()
        env["CONTENT_LENGTH"] = "-1"
        self.assert_denied(env)

    def test_invalid_content_length_denied(self):
        env = good_request()
        env["CONTENT_LENGTH"] = "abc"
        self.assert_denied(env)

    def test_custom_unauthorized_factory(self):
        seen = []
        mw = PyCSRFShieldWSGI(app, manager(), expected_origin=ORIGIN, session_id="session-42", unauthorized_factory=lambda reason: [b"custom:" + reason.encode()])
        start = StartResponse()
        body = collect(mw, wsgi_environ("POST", headers={"Origin": ORIGIN}), start)
        self.assertTrue(body.startswith(b"custom:"))

    def test_no_store_on_denial(self):
        start = StartResponse()
        collect(shield(), wsgi_environ("POST", headers={"Origin": ORIGIN}), start)
        self.assertEqual(start.header("Cache-Control"), "no-store")


class WSGIKeyRotationTests(unittest.TestCase):
    def test_fallback_signed_token_accepted(self):
        m = manager(secrets=[SECRET, b"f" * 24])
        legacy = manager(secrets=b"f" * 24)
        cookie_token, transport_token = legacy.issue_pair("session-42")
        start = StartResponse()
        mw = PyCSRFShieldWSGI(app, m, expected_origin=ORIGIN, session_id="session-42", allow_missing_referer=True)
        env = wsgi_environ("POST", cookies="%s=%s" % (COOKIE, cookie_token), headers={"Origin": ORIGIN, "X-CSRF-Token": transport_token})
        collect(mw, env, start)
        self.assertEqual(start.status, "200 OK")


if __name__ == "__main__":
    unittest.main()
