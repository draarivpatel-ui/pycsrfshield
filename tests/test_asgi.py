"""ASGI 3.0 middleware integration tests."""

from __future__ import annotations

import asyncio
import json
import unittest
from urllib.parse import quote

from pycsrfshield import PyCSRFShieldASGI

from _support import (
    ASGIApp,
    ORIGIN,
    SECRET,
    asgi_scope,
    drive,
    manager,
)

COOKIE = "__Host-pycsrfshield"


def run(coro):
    return asyncio.run(coro)


def shield(app=None, **kwargs):
    opts = {"expected_origin": ORIGIN, "session_id": "session-42", "allow_missing_referer": True}
    opts.update(kwargs)
    return PyCSRFShieldASGI(app or ASGIApp(), manager(), **opts)


def good_scope(m=None, pair=None, **headers):
    m = m or manager()
    cookie_token, transport_token = pair or m.issue_pair("session-42")
    all_headers = {"Origin": ORIGIN}
    all_headers.update(headers)
    return asgi_scope("POST", cookies="%s=%s" % (COOKIE, cookie_token), headers=all_headers), transport_token


class ASGIHappyPathTests(unittest.TestCase):
    def test_valid_post_passes(self):
        app = ASGIApp()
        scope, token = good_scope()
        sent = run(drive(scope, shield(app), ("X-CSRF-Token=" + quote(token)).encode()))
        self.assertEqual(sent[0]["status"], 200)

    def test_app_receives_replayed_body(self):
        app = ASGIApp()
        scope, token = good_scope()
        body = ("csrf_token=" + quote(token)).encode()
        run(drive(scope, shield(app), body))
        self.assertEqual(app.body, body)

    def test_chunked_body_replayed(self):
        app = ASGIApp()
        scope, token = good_scope()

        async def scenario():
            sent = []
            state = {"n": 0}
            chunks = [b"csrf_token=" + token[:20].encode(), token[20:].encode()]

            async def receive():
                state["n"] += 1
                return {"type": "http.request", "body": chunks[state["n"] - 1], "more_body": state["n"] < 2}

            async def send(message):
                sent.append(message)

            await shield(app)(scope, receive, send)
            return sent, state

        sent, state = run(scenario())
        self.assertEqual(state["n"], 2)
        self.assertEqual(sent[0]["status"], 200)

    def test_set_cookie_header_emitted(self):
        scope, token = good_scope()
        sent = run(drive(scope, shield(), ("X-CSRF-Token=" + quote(token)).encode()))
        headers = dict(sent[0]["headers"])
        self.assertIn(b"set-cookie", headers)
        cookie = headers[b"set-cookie"].decode()
        self.assertIn("Secure", cookie)
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)

    def test_cache_control_no_store(self):
        scope, token = good_scope()
        sent = run(drive(scope, shield(), ("X-CSRF-Token=" + quote(token)).encode()))
        self.assertEqual(dict(sent[0]["headers"])[b"cache-control"], b"no-store")

    def test_state_flag_set(self):
        app = ASGIApp()
        scope, token = good_scope()
        run(drive(scope, shield(app), ("X-CSRF-Token=" + quote(token)).encode()))
        self.assertTrue(app.state.get("pycsrfshield"))

    def test_safe_methods_pass_without_token(self):
        for method in ("GET", "HEAD", "OPTIONS", "TRACE", "get"):
            with self.subTest(method=method):
                sent = run(drive(asgi_scope(method), shield(ASGIApp())))
                self.assertEqual(sent[0]["status"], 200)

    def test_header_token_accepted(self):
        pair = manager().issue_pair("session-42")
        scope, token = good_scope(pair=pair, **{"X-CSRF-Token": pair[1]})
        sent = run(drive(scope, shield()))
        self.assertEqual(sent[0]["status"], 200)

    def test_lowercase_header_key_accepted(self):
        pair = manager().issue_pair("session-42")
        scope, token = good_scope(pair=pair, **{"x-csrf-token": pair[1]})
        sent = run(drive(scope, shield()))
        self.assertEqual(sent[0]["status"], 200)

    def test_custom_header_name(self):
        pair = manager().issue_pair("session-42")
        scope, token = good_scope(pair=pair, **{"X-Token": pair[1]})
        mw = PyCSRFShieldASGI(ASGIApp(), manager(), expected_origin=ORIGIN, session_id="session-42", header_name="X-Token", allow_missing_referer=True)
        sent = run(drive(scope, mw))
        self.assertEqual(sent[0]["status"], 200)

    def test_unmasked_mode(self):
        token = manager().issue("session-42")
        scope = asgi_scope("POST", cookies="%s=%s" % (COOKIE, token), headers={"Origin": ORIGIN, "X-CSRF-Token": token})
        mw = PyCSRFShieldASGI(ASGIApp(), manager(), expected_origin=ORIGIN, session_id="session-42", mask_tokens=False, allow_missing_referer=True)
        sent = run(drive(scope, mw))
        self.assertEqual(sent[0]["status"], 200)

    def test_websocket_scope_passes_through(self):
        app = ASGIApp()
        scope = {"type": "websocket"}
        mw = PyCSRFShieldASGI(app, manager(), expected_origin=ORIGIN, session_id="session-42", allow_missing_origin=True)
        sent = run(drive(scope, mw))
        self.assertEqual(sent[0]["status"], 200)

    def test_form_extraction_disabled(self):
        scope, token = good_scope()
        mw = PyCSRFShieldASGI(ASGIApp(), manager(), expected_origin=ORIGIN, session_id="session-42", allow_form=False, allow_missing_referer=True)
        sent = run(drive(scope, mw, ("csrf_token=" + quote(token)).encode()))
        self.assertEqual(sent[0]["status"], 403)


class ASGIRejectionTests(unittest.TestCase):
    def assert_denied(self, scope, body=b"", **kwargs):
        sent = run(drive(scope, shield(**kwargs), body))
        self.assertEqual(sent[0]["status"], 403)
        return json.loads(sent[1]["body"])

    def test_missing_token_denied(self):
        m = manager()
        scope = asgi_scope("POST", cookies="%s=%s" % (COOKIE, m.issue("session-42")), headers={"Origin": ORIGIN})
        data = self.assert_denied(scope)
        self.assertIn("detail", data)

    def test_missing_cookie_denied(self):
        m = manager()
        token = m.mint("session-42")
        scope = asgi_scope("POST", headers={"Origin": ORIGIN, "X-CSRF-Token": token})
        self.assert_denied(scope)

    def test_duplicate_cookie_denied(self):
        m = manager()
        cookie_token, transport_token = m.issue_pair("session-42")
        scope = asgi_scope("POST", cookies="%s=%s; %s=tossed" % (COOKIE, cookie_token, COOKIE), headers={"Origin": ORIGIN, "X-CSRF-Token": transport_token})
        self.assert_denied(scope)

    def test_mismatched_token_denied(self):
        m = manager()
        cookie_token, _ = m.issue_pair("session-42")
        _, transport_token = m.issue_pair("session-42")
        scope = asgi_scope("POST", cookies="%s=%s" % (COOKIE, cookie_token), headers={"Origin": ORIGIN, "X-CSRF-Token": transport_token})
        self.assert_denied(scope)

    def test_cross_site_origin_denied(self):
        scope, token = good_scope(Origin="https://evil.com")
        self.assert_denied(scope, ("X-CSRF-Token=" + quote(token)).encode())

    def test_null_origin_denied(self):
        scope, token = good_scope(Origin="null")
        self.assert_denied(scope, ("X-CSRF-Token=" + quote(token)).encode())

    def test_cross_site_fetch_metadata_denied(self):
        scope, token = good_scope(**{"Sec-Fetch-Site": "cross-site"})
        self.assert_denied(scope, ("X-CSRF-Token=" + quote(token)).encode())

    def test_header_and_form_mismatch_denied(self):
        pair = manager().issue_pair("session-42")
        scope, token = good_scope(pair=pair, **{"X-CSRF-Token": pair[1]})
        self.assert_denied(scope, b"csrf_token=other")

    def test_forged_token_denied(self):
        scope, _ = good_scope()
        self.assert_denied(scope, b"X-CSRF-Token=forged")

    def test_wrong_session_denied(self):
        m = manager()
        cookie_token, transport_token = m.issue_pair("other")
        scope = asgi_scope("POST", cookies="%s=%s" % (COOKIE, cookie_token), headers={"Origin": ORIGIN, "X-CSRF-Token": transport_token})
        self.assert_denied(scope)

    def test_expired_token_denied(self):
        m = manager(ttl=10, clock_skew=0)
        cookie_token, transport_token = m.issue_pair("session-42", now=1000)
        scope = asgi_scope("POST", cookies="%s=%s" % (COOKIE, cookie_token), headers={"Origin": ORIGIN, "X-CSRF-Token": transport_token})
        self.assert_denied(scope)

    def test_oversized_form_denied(self):
        scope, token = good_scope()
        self.assert_denied(scope, b"csrf_token=" + b"x" * (1 << 21))

    def test_ambiguous_header_denied(self):
        pair = manager().issue_pair("session-42")
        scope, token = good_scope(pair=pair, **{"X-CSRF-Token": pair[1]})
        scope["headers"].append([b"x-csrf-token", b"other"])
        self.assert_denied(scope)

    def test_no_cookie_on_denial(self):
        scope, token = good_scope(Origin="https://evil.com")
        sent = run(drive(scope, shield(), ("X-CSRF-Token=" + quote(token)).encode()))
        self.assertNotIn(b"set-cookie", dict(sent[0]["headers"]))

    def test_fallback_key_accepted(self):
        m = manager(secrets=[SECRET, b"f" * 24])
        legacy = manager(secrets=b"f" * 24)
        cookie_token, transport_token = legacy.issue_pair("session-42")
        scope = asgi_scope("POST", cookies="%s=%s" % (COOKIE, cookie_token), headers={"Origin": ORIGIN, "X-CSRF-Token": transport_token})
        mw = PyCSRFShieldASGI(ASGIApp(), m, expected_origin=ORIGIN, session_id="session-42", allow_missing_referer=True)
        sent = run(drive(scope, mw))
        self.assertEqual(sent[0]["status"], 200)

    def test_disconnect_still_denies_without_token(self):
        scope = asgi_scope("POST", headers={"Origin": ORIGIN})

        async def scenario():
            sent = []

            async def receive():
                return {"type": "http.disconnect"}

            async def send(message):
                sent.append(message)

            await shield()(scope, receive, send)
            return sent

        sent = run(scenario())
        self.assertEqual(sent[0]["status"], 403)


if __name__ == "__main__":
    unittest.main()
