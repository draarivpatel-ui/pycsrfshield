"""End-to-end hardening regression tests for production request flows."""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import unittest
from urllib.parse import quote

from pycsrfshield import ConfigurationError, CookieError, MaskError, OriginError, OriginValidator, PyCSRFShieldASGI, PyCSRFShieldWSGI, TokenError
from pycsrfshield.cookies import format_cookie, unique_cookie_value
from pycsrfshield.origin import origin_from_url, origins_match

from _support import ASGIApp, ORIGIN, OTHER_SECRET, SECRET, StartResponse, asgi_scope, b64, collect, drive, manager, now, wsgi_environ

COOKIE = "__Host-pycsrfshield"
SESSION = "session-42"


def run(coro):
    return asyncio.run(coro)


def plain_app(environ, start_response):
    body = environ["wsgi.input"].read()
    start_response("200 OK", [("Content-Type", "text/plain")])
    return [b"ok:" + body]


def wsgi_shield(app=None, **kwargs):
    opts = {"expected_origin": ORIGIN, "session_id": SESSION, "allow_missing_referer": True}
    opts.update(kwargs)
    return PyCSRFShieldWSGI(app or plain_app, manager(), **opts)


def valid_wsgi_request(body_field="header", **kwargs):
    m = manager()
    cookie_token, transport_token = m.issue_pair(SESSION)
    headers = {"Origin": ORIGIN}
    body = b""
    if body_field == "header":
        headers["X-CSRF-Token"] = transport_token
    elif body_field == "form":
        body = ("csrf_token=" + quote(transport_token)).encode()
    headers.update(kwargs.pop("headers", {}))
    return wsgi_environ("POST", cookies="%s=%s" % (COOKIE, cookie_token), headers=headers, body=body, **kwargs), cookie_token, transport_token


class TokenPairTests(unittest.TestCase):
    def test_issue_pair_returns_cookie_and_masked_transport_forms(self):
        m = manager()
        cookie_token, transport_token = m.issue_pair(SESSION, now=now())
        self.assertNotEqual(cookie_token, transport_token)
        self.assertEqual(m.unmask(transport_token), cookie_token)

    def test_issue_pair_both_forms_verify(self):
        m = manager()
        cookie_token, transport_token = m.issue_pair(SESSION, now=now())
        self.assertTrue(m.verify(cookie_token, SESSION, now=now()))
        self.assertTrue(m.verify_masked(transport_token, SESSION, now=now()))

    def test_session_binding_is_keyed(self):
        self.assertNotEqual(
            manager(secrets=SECRET).bind_session(SESSION),
            manager(secrets=OTHER_SECRET).bind_session(SESSION),
        )

    def test_session_binding_is_not_plain_sha256_concatenation(self):
        binding = manager().bind_session(SESSION)
        import base64
        plain = base64.urlsafe_b64encode(
            hashlib.sha256(b"pycsrfshield-session" + SESSION.encode()).digest()
        ).decode().rstrip("=")
        self.assertNotEqual(binding, plain)

    def test_key_rotation_uses_the_matching_key_for_binding(self):
        old = manager(secrets=OTHER_SECRET)
        rotated = manager(secrets=[SECRET, OTHER_SECRET])
        token = old.issue(SESSION, now=now())
        self.assertTrue(rotated.verify(token, SESSION, now=now()))

    def test_verify_rejects_noncanonical_payload_length(self):
        token = manager().issue(SESSION, now=now())
        with self.assertRaises(TokenError):
            manager().verify(token[:-1] + "A", SESSION, now=now())


class CookieHardeningTests(unittest.TestCase):
    def test_host_cookie_requires_secure(self):
        with self.assertRaises(CookieError):
            format_cookie(COOKIE, "abc", secure=False)

    def test_host_cookie_requires_root_path(self):
        with self.assertRaises(CookieError):
            format_cookie(COOKIE, "abc", path="/app")

    def test_default_cookie_exact_attribute_order(self):
        self.assertEqual(
            format_cookie(COOKIE, "abc"),
            COOKIE + "=abc; Path=/; Secure; HttpOnly; SameSite=Lax",
        )

    def test_domain_normalization_is_lowercase_without_leading_dot(self):
        cookie = format_cookie("csrf", "abc", domain=".EXAMPLE.com")
        self.assertIn("Domain=example.com", cookie)

    def test_invalid_domain_rejected(self):
        with self.assertRaises(CookieError):
            format_cookie("csrf", "abc", domain="evil example.com")

    def test_control_character_in_path_rejected(self):
        with self.assertRaises(CookieError):
            format_cookie("csrf", "abc", path="/\x7f")

    def test_multiple_cookie_header_fields_tossing_rejected(self):
        self.assertIsNone(unique_cookie_value(["a=1", "a=2"], "a"))

    def test_multiple_cookie_header_fields_single_value_accepted(self):
        self.assertEqual(unique_cookie_value(["a=1", "b=2"], "a"), "1")


class OriginHardeningTests(unittest.TestCase):
    def test_origin_from_url_removes_path_and_query(self):
        self.assertEqual(origin_from_url(ORIGIN + "/deep/path?q=1"), ORIGIN)

    def test_origin_from_url_preserves_nondefault_port(self):
        self.assertEqual(origin_from_url("https://app.example.com:8443/x"), "https://app.example.com:8443")

    def test_default_ports_do_not_confuse_http_and_https(self):
        self.assertFalse(origins_match("http://app.example.com:80", "https://app.example.com:443"))

    def test_userinfo_in_referer_url_rejected(self):
        with self.assertRaises(OriginError):
            origin_from_url("https://app.example.com@evil.com/path")

    def test_fragment_in_referer_url_rejected(self):
        with self.assertRaises(OriginError):
            origin_from_url(ORIGIN + "/path#fragment")

    def test_ipv6_referer_origin(self):
        self.assertEqual(origin_from_url("https://[2001:db8::1]:443/path"), "https://[2001:db8::1]")


class WSGIStandardFlowTests(unittest.TestCase):
    def test_raw_cookie_plus_independently_masked_header_accepted(self):
        env, cookie_token, transport_token = valid_wsgi_request()
        start = StartResponse()
        collect(wsgi_shield(), env, start)
        self.assertEqual(start.status, "200 OK")

    def test_raw_cookie_plus_masked_form_accepted(self):
        env, cookie_token, transport_token = valid_wsgi_request(body_field="form")
        start = StartResponse()
        collect(wsgi_shield(), env, start)
        self.assertEqual(start.status, "200 OK")

    def test_set_cookie_contains_unmasked_signed_token(self):
        env, cookie_token, transport_token = valid_wsgi_request()
        start = StartResponse()
        collect(wsgi_shield(), env, start)
        emitted = start.header("Set-Cookie").split(";", 1)[0].split("=", 1)[1]
        self.assertEqual(emitted, cookie_token)
        self.assertTrue(manager().verify(emitted, SESSION))

    def test_successful_post_does_not_rotate_cookie_token(self):
        env, cookie_token, transport_token = valid_wsgi_request()
        start = StartResponse()
        collect(wsgi_shield(), env, start)
        emitted = start.header("Set-Cookie").split(";", 1)[0].split("=", 1)[1]
        self.assertEqual(emitted, cookie_token)

    def test_transport_token_exposed_to_wsgi_application(self):
        captured = {}

        def capturing_app(environ, start_response):
            captured["token"] = environ.get("pycsrfshield.token")
            start_response("200 OK", [])
            return [b"ok"]

        env, cookie_token, transport_token = valid_wsgi_request()
        collect(wsgi_shield(capturing_app), env, StartResponse())
        self.assertEqual(manager().unmask(captured["token"]), cookie_token)

    def test_expired_cookie_on_safe_get_is_rotated(self):
        m = manager()
        expired = m.issue(SESSION, now=1000)
        env = wsgi_environ("GET", cookies="%s=%s" % (COOKIE, expired))
        start = StartResponse()
        collect(wsgi_shield(), env, start)
        emitted = start.header("Set-Cookie").split(";", 1)[0].split("=", 1)[1]
        self.assertNotEqual(emitted, expired)
        self.assertTrue(m.verify(emitted, SESSION))

    def test_json_body_is_not_consumed_before_application(self):
        captured = []

        def capturing_app(environ, start_response):
            captured.append(environ["wsgi.input"].read())
            start_response("200 OK", [])
            return [b"ok"]

        m = manager()
        cookie_token, transport_token = m.issue_pair(SESSION)
        body = b'{"action":"transfer"}'
        env = wsgi_environ(
            "POST",
            cookies="%s=%s" % (COOKIE, cookie_token),
            headers={"Origin": ORIGIN, "X-CSRF-Token": transport_token},
            body=body,
            content_type="application/json",
        )
        collect(wsgi_shield(capturing_app), env, StartResponse())
        self.assertEqual(captured[0], body)

    def test_form_charset_parameter_accepted(self):
        m = manager()
        cookie_token, transport_token = m.issue_pair(SESSION)
        body = ("csrf_token=" + quote(transport_token)).encode()
        env = wsgi_environ(
            "POST",
            cookies="%s=%s" % (COOKIE, cookie_token),
            headers={"Origin": ORIGIN},
            body=body,
            content_type="application/x-www-form-urlencoded; charset=utf-8",
        )
        start = StartResponse()
        collect(wsgi_shield(), env, start)
        self.assertEqual(start.status, "200 OK")

    def test_incomplete_wsgi_body_rejected(self):
        env, cookie_token, transport_token = valid_wsgi_request(body_field="form")
        env["CONTENT_LENGTH"] = str(len(env["wsgi.input"].getvalue()) + 1)
        start = StartResponse()
        collect(wsgi_shield(), env, start)
        self.assertEqual(start.status, "403 Forbidden")

    def test_dynamic_session_callable_accepted(self):
        def session_from_environ(environ):
            return environ.get("HTTP_X_SESSION_ID", "missing")

        mw = wsgi_shield(session_id=session_from_environ)
        m = manager()
        cookie_token, transport_token = m.issue_pair("user-a")
        env = wsgi_environ(
            "POST",
            cookies="%s=%s" % (COOKIE, cookie_token),
            headers={"Origin": ORIGIN, "X-CSRF-Token": transport_token, "X-Session-Id": "user-a"},
        )
        start = StartResponse()
        collect(mw, env, start)
        self.assertEqual(start.status, "200 OK")

    def test_dynamic_session_wrong_user_rejected(self):
        def session_from_environ(environ):
            return environ.get("HTTP_X_SESSION_ID", "missing")

        mw = wsgi_shield(session_id=session_from_environ)
        m = manager()
        cookie_token, transport_token = m.issue_pair("user-b")
        env = wsgi_environ(
            "POST",
            cookies="%s=%s" % (COOKIE, cookie_token),
            headers={"Origin": ORIGIN, "X-CSRF-Token": transport_token, "X-Session-Id": "user-a"},
        )
        start = StartResponse()
        collect(mw, env, start)
        self.assertEqual(start.status, "403 Forbidden")


class ASGIStandardFlowTests(unittest.TestCase):
    def asgi_shield(self, app=None, **kwargs):
        opts = {"expected_origin": ORIGIN, "session_id": SESSION, "allow_missing_referer": True}
        opts.update(kwargs)
        return PyCSRFShieldASGI(app or ASGIApp(), manager(), **opts)

    def valid_scope(self):
        m = manager()
        cookie_token, transport_token = m.issue_pair(SESSION)
        scope = asgi_scope(
            "POST",
            cookies="%s=%s" % (COOKIE, cookie_token),
            headers={"Origin": ORIGIN, "X-CSRF-Token": transport_token},
        )
        return scope, cookie_token, transport_token

    def test_raw_cookie_plus_independently_masked_header_accepted(self):
        scope, cookie_token, transport_token = self.valid_scope()
        sent = run(drive(scope, self.asgi_shield()))
        self.assertEqual(sent[0]["status"], 200)

    def test_scope_exposes_masked_transport_token(self):
        app = ASGIApp()
        scope, cookie_token, transport_token = self.valid_scope()
        run(drive(scope, self.asgi_shield(app)))
        token = scope["pycsrfshield"]["token"]
        self.assertEqual(manager().unmask(token), cookie_token)

    def test_json_body_remains_available_to_application(self):
        app = ASGIApp()
        m = manager()
        cookie_token, transport_token = m.issue_pair(SESSION)
        scope = asgi_scope(
            "POST",
            cookies="%s=%s" % (COOKIE, cookie_token),
            headers={"Origin": ORIGIN, "X-CSRF-Token": transport_token, "Content-Type": "application/json"},
        )
        scope["headers"] = [pair for pair in scope["headers"] if pair[0] != b"content-type"]
        scope["headers"].append([b"content-type", b"application/json"])
        body = b'{"action":"transfer"}'
        sent = run(drive(scope, self.asgi_shield(app), body))
        self.assertEqual(sent[0]["status"], 200)
        self.assertEqual(app.body, body)

    def test_duplicate_cookie_header_fields_rejected(self):
        scope, cookie_token, transport_token = self.valid_scope()
        scope["headers"].append([b"cookie", ("%s=tossed" % COOKIE).encode()])
        sent = run(drive(scope, self.asgi_shield()))
        self.assertEqual(sent[0]["status"], 403)

    def test_duplicate_origin_headers_rejected(self):
        scope, cookie_token, transport_token = self.valid_scope()
        scope["headers"].append([b"origin", ORIGIN.encode()])
        sent = run(drive(scope, self.asgi_shield()))
        self.assertEqual(sent[0]["status"], 403)

    def test_dynamic_session_callable_accepted(self):
        def session_from_scope(scope):
            return dict((k.decode(), v.decode()) for k, v in scope["headers"]).get("x-session-id", "missing")

        m = manager()
        cookie_token, transport_token = m.issue_pair("user-a")
        scope = asgi_scope(
            "POST",
            cookies="%s=%s" % (COOKIE, cookie_token),
            headers={"Origin": ORIGIN, "X-CSRF-Token": transport_token, "X-Session-Id": "user-a"},
        )
        mw = self.asgi_shield(session_id=session_from_scope)
        sent = run(drive(scope, mw))
        self.assertEqual(sent[0]["status"], 200)

    def test_asgi_set_cookie_is_stable_unmasked_token(self):
        scope, cookie_token, transport_token = self.valid_scope()
        sent = run(drive(scope, self.asgi_shield()))
        headers = dict(sent[0]["headers"])
        emitted = headers[b"set-cookie"].decode().split(";", 1)[0].split("=", 1)[1]
        self.assertEqual(emitted, cookie_token)


class WireFormHardeningTests(unittest.TestCase):
    def test_masked_transport_token_rejected_as_wsgi_cookie(self):
        m = manager()
        cookie_token, transport_token = m.issue_pair(SESSION)
        env = wsgi_environ(
            "POST",
            cookies="%s=%s" % (COOKIE, transport_token),
            headers={"Origin": ORIGIN, "X-CSRF-Token": transport_token},
        )
        start = StartResponse()
        collect(wsgi_shield(), env, start)
        self.assertEqual(start.status, "403 Forbidden")

    def test_unmasked_cookie_token_rejected_as_wsgi_transport(self):
        m = manager()
        cookie_token, transport_token = m.issue_pair(SESSION)
        env = wsgi_environ(
            "POST",
            cookies="%s=%s" % (COOKIE, cookie_token),
            headers={"Origin": ORIGIN, "X-CSRF-Token": cookie_token},
        )
        start = StartResponse()
        collect(wsgi_shield(), env, start)
        self.assertEqual(start.status, "403 Forbidden")

    def test_masked_transport_token_rejected_as_asgi_cookie(self):
        m = manager()
        cookie_token, transport_token = m.issue_pair(SESSION)
        scope = asgi_scope(
            "POST",
            cookies="%s=%s" % (COOKIE, transport_token),
            headers={"Origin": ORIGIN, "X-CSRF-Token": transport_token},
        )
        sent = run(drive(scope, PyCSRFShieldASGI(ASGIApp(), manager(), expected_origin=ORIGIN, session_id=SESSION, allow_missing_referer=True)))
        self.assertEqual(sent[0]["status"], 403)

    def test_quoted_cookie_wire_value_is_not_unquoted_for_verification(self):
        m = manager()
        cookie_token, transport_token = m.issue_pair(SESSION)
        env = wsgi_environ(
            "POST",
            cookies='%s="%s"' % (COOKIE, cookie_token),
            headers={"Origin": ORIGIN, "X-CSRF-Token": transport_token},
        )
        start = StartResponse()
        collect(wsgi_shield(), env, start)
        self.assertEqual(start.status, "403 Forbidden")

    def test_nonascii_header_and_form_tokens_fail_closed(self):
        m = manager()
        cookie_token, _ = m.issue_pair(SESSION)
        env = wsgi_environ(
            "POST",
            cookies="%s=%s" % (COOKIE, cookie_token),
            headers={"Origin": ORIGIN, "X-CSRF-Token": "\xe9"},
            body="csrf_token=\xe9".encode("utf-8"),
        )
        start = StartResponse()
        collect(wsgi_shield(), env, start)
        self.assertEqual(start.status, "403 Forbidden")

    def test_asgi_latin1_header_and_utf8_form_tokens_fail_closed(self):
        scope, cookie_token, transport_token = ASGIStandardFlowTests().valid_scope()
        scope["headers"] = [
            [name, b"\xe9" if name == b"x-csrf-token" else value]
            for name, value in scope["headers"]
        ]
        body = "csrf_token=\xe9".encode("utf-8")
        mw = PyCSRFShieldASGI(ASGIApp(), manager(), expected_origin=ORIGIN, session_id=SESSION, allow_missing_referer=True)
        sent = run(drive(scope, mw, body))
        self.assertEqual(sent[0]["status"], 403)


class ResponseHardeningTests(unittest.TestCase):
    def test_wsgi_cache_control_is_replaced_not_stacked(self):
        def caching_app(environ, start_response):
            start_response("200 OK", [("Cache-Control", "public, max-age=3600"), ("cache-control", "must-revalidate")])
            return [b"ok"]

        env, cookie_token, transport_token = valid_wsgi_request()
        start = StartResponse()
        collect(wsgi_shield(caching_app), env, start)
        values = [value for name, value in start.headers if name.lower() == "cache-control"]
        self.assertEqual(values, ["no-store"])

    def test_asgi_cache_control_is_replaced_not_stacked(self):
        async def caching_app(scope, receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": [(b"cache-control", b"public, max-age=3600"), (b"cache-control", b"must-revalidate")]})
            await send({"type": "http.response.body", "body": b"ok"})

        scope, cookie_token, transport_token = ASGIStandardFlowTests().valid_scope()
        mw = PyCSRFShieldASGI(caching_app, manager(), expected_origin=ORIGIN, session_id=SESSION, allow_missing_referer=True)
        sent = run(drive(scope, mw))
        values = [value for name, value in sent[0]["headers"] if name.lower() == b"cache-control"]
        self.assertEqual(values, [b"no-store"])

    def test_wsgi_downstream_cannot_clobber_shield_cookie(self):
        def clobbering_app(environ, start_response):
            start_response("200 OK", [
                ("Set-Cookie", COOKIE + "=forged; Path=/"),
                ("Set-Cookie", "other=kept; Path=/"),
            ])
            return [b"ok"]

        env, cookie_token, transport_token = valid_wsgi_request()
        start = StartResponse()
        collect(wsgi_shield(clobbering_app), env, start)
        values = [value for name, value in start.headers if name.lower() == "set-cookie"]
        self.assertEqual(len(values), 2)
        shield_values = [value for value in values if value.startswith(COOKIE + "=")]
        self.assertEqual(len(shield_values), 1)
        self.assertIn(cookie_token, shield_values[0])
        self.assertNotIn("forged", shield_values[0])
        self.assertIn("other=kept; Path=/", values)

    def test_asgi_downstream_cannot_clobber_shield_cookie(self):
        async def clobbering_app(scope, receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": [
                (b"set-cookie", (COOKIE + "=forged; Path=/").encode("ascii")),
                (b"set-cookie", b"other=kept; Path=/"),
            ]})
            await send({"type": "http.response.body", "body": b"ok"})

        scope, cookie_token, transport_token = ASGIStandardFlowTests().valid_scope()
        mw = PyCSRFShieldASGI(clobbering_app, manager(), expected_origin=ORIGIN, session_id=SESSION, allow_missing_referer=True)
        sent = run(drive(scope, mw))
        values = [value.decode("latin-1") for name, value in sent[0]["headers"] if name.lower() == b"set-cookie"]
        self.assertEqual(len(values), 2)
        shield_values = [value for value in values if value.startswith(COOKIE + "=")]
        self.assertEqual(len(shield_values), 1)
        self.assertIn(cookie_token, shield_values[0])
        self.assertNotIn("forged", shield_values[0])
        self.assertIn("other=kept; Path=/", values)


class ExceptionPropagationTests(unittest.TestCase):
    def test_wsgi_session_callable_value_error_propagates(self):
        def broken_session(environ):
            raise ValueError("application session failure")

        mw = wsgi_shield(session_id=broken_session)
        with self.assertRaises(ValueError):
            collect(mw, wsgi_environ("GET"), StartResponse())

    def test_asgi_session_callable_value_error_propagates(self):
        def broken_session(scope):
            raise ValueError("application session failure")

        mw = PyCSRFShieldASGI(ASGIApp(), manager(), expected_origin=ORIGIN, session_id=broken_session, allow_missing_referer=True)
        with self.assertRaises(ValueError):
            run(drive(asgi_scope("GET"), mw))

    def test_wsgi_application_error_propagates(self):
        def broken_app(environ, start_response):
            raise RuntimeError("application failure")

        with self.assertRaises(RuntimeError):
            collect(wsgi_shield(broken_app), wsgi_environ("GET"), StartResponse())

    def test_asgi_application_error_propagates(self):
        async def broken_app(scope, receive, send):
            raise RuntimeError("application failure")

        mw = PyCSRFShieldASGI(broken_app, manager(), expected_origin=ORIGIN, session_id=SESSION, allow_missing_referer=True)
        with self.assertRaises(RuntimeError):
            run(drive(asgi_scope("GET"), mw))


class ConfigurationHardeningTests(unittest.TestCase):
    def test_duplicate_fallback_keys_rejected(self):
        with self.assertRaises(ConfigurationError):
            manager(secrets=[SECRET, OTHER_SECRET, OTHER_SECRET])

    def test_wsgi_requires_explicit_session_binding(self):
        with self.assertRaises(TypeError):
            PyCSRFShieldWSGI(plain_app, manager(), expected_origin=ORIGIN)

    def test_asgi_requires_explicit_session_binding(self):
        with self.assertRaises(TypeError):
            PyCSRFShieldASGI(ASGIApp(), manager(), expected_origin=ORIGIN)

    def test_invalid_cookie_configuration_rejected_at_construction(self):
        with self.assertRaises(ConfigurationError):
            wsgi_shield(cookie_path="/app")

    def test_invalid_header_name_rejected_at_construction(self):
        with self.assertRaises(ConfigurationError):
            wsgi_shield(header_name="bad header")

    def test_non_ascii_cookie_path_rejected(self):
        with self.assertRaises(CookieError):
            format_cookie("csrf", "abc", path="/é")

    def test_validate_combined_rejects_duplicate_fetch_metadata_keys(self):
        validator = OriginValidator(ORIGIN)
        with self.assertRaises(OriginError):
            validator.validate("GET", {"Sec-Fetch-Site": "same-origin", "sec-fetch-site": "cross-site"})

    def test_empty_header_token_is_invalid_not_missing(self):
        m = manager()
        cookie_token, transport_token = m.issue_pair(SESSION)
        env = wsgi_environ(
            "POST",
            cookies="%s=%s" % (COOKIE, cookie_token),
            headers={"Origin": ORIGIN, "X-CSRF-Token": ""},
        )
        start = StartResponse()
        collect(wsgi_shield(), env, start)
        self.assertEqual(start.status, "403 Forbidden")

    def test_form_without_content_length_is_bounded_and_accepted(self):
        env, cookie_token, transport_token = valid_wsgi_request(body_field="form")
        del env["CONTENT_LENGTH"]
        start = StartResponse()
        collect(wsgi_shield(), env, start)
        self.assertEqual(start.status, "200 OK")

    def test_oversized_form_without_content_length_rejected(self):
        m = manager()
        cookie_token, transport_token = m.issue_pair(SESSION)
        env = wsgi_environ(
            "POST",
            cookies="%s=%s" % (COOKIE, cookie_token),
            headers={"Origin": ORIGIN},
            body=b"x" * ((1 << 20) + 1),
        )
        del env["CONTENT_LENGTH"]
        start = StartResponse()
        collect(wsgi_shield(), env, start)
        self.assertEqual(start.status, "403 Forbidden")

    def test_oversized_raw_token_rejected_before_verification(self):
        with self.assertRaises(TokenError):
            manager().verify(b64(b"x" * 5000), SESSION)

    def test_oversized_masked_token_rejected_before_unmasking(self):
        with self.assertRaises(MaskError):
            manager().unmask(b64(b"m" * (32 + 5000)))


if __name__ == "__main__":
    unittest.main()
