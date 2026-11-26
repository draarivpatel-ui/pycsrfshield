"""Framework-agnostic WSGI and ASGI CSRF middleware."""

from __future__ import annotations

import hmac
import io
import json
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, Optional, Tuple, Union
from urllib.parse import parse_qs

from .cookies import format_cookie, unique_cookie_value
from .errors import ConfigurationError, CookieError, CSRFError, MaskError, TokenError
from .origin import OriginValidator, is_safe_method, normalize_method
from .token import TokenManager

TOKEN_HEADER = "X-CSRF-Token"
DEFAULT_COOKIE_NAME = "__Host-pycsrfshield"
DEFAULT_HEADER_NAME = "X-CSRF-Token"
MAX_FORM_BYTES = 1 << 20
_FORM_CONTENT_TYPE = "application/x-www-form-urlencoded"
_HEADER_NAME_CHARS = frozenset("!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
_REASONS = {
    "missing": "CSRF token is missing",
    "duplicate": "CSRF token is ambiguous",
    "invalid": "CSRF token is invalid",
}

HeadersMulti = Dict[str, List[str]]


def _add_header(headers: HeadersMulti, name: str, value: str) -> None:
    headers.setdefault(name.lower(), []).append(value)


def _values(headers: HeadersMulti, name: str) -> List[str]:
    return list(headers.get(name.lower(), ()))


def _single_header(headers: HeadersMulti, name: str) -> Optional[str]:
    values = _values(headers, name)
    if len(values) > 1:
        raise CSRFError("ambiguous request header")
    return values[0] if values else None


def _headers_from_wsgi(environ: Mapping[str, Any]) -> HeadersMulti:
    headers: HeadersMulti = {}
    if environ.get("CONTENT_TYPE") is not None:
        _add_header(headers, "content-type", str(environ["CONTENT_TYPE"]))
    if environ.get("CONTENT_LENGTH") is not None:
        _add_header(headers, "content-length", str(environ["CONTENT_LENGTH"]))
    for key, value in environ.items():
        if key.startswith("HTTP_"):
            _add_header(headers, key[5:].replace("_", "-"), str(value))
    return headers


def _headers_from_asgi(scope: Mapping[str, Any]) -> HeadersMulti:
    result: HeadersMulti = {}
    for raw_name, raw_value in scope.get("headers", ()):
        try:
            name = raw_name.decode("latin-1").lower()
            value = raw_value.decode("latin-1")
        except (AttributeError, UnicodeDecodeError) as exc:
            raise CSRFError("invalid request header") from exc
        separators = '()<>@,;:\\"/[]?={} \t'
        if not name or any(ord(ch) < 0x21 or ord(ch) > 0x7E or ch in separators for ch in name):
            raise CSRFError("invalid request header")
        _add_header(result, name, value)
    return result


def _origin_view(headers: HeadersMulti) -> Dict[str, str]:
    """Return the security-relevant headers, rejecting duplicates."""
    view: Dict[str, str] = {}
    for name in ("origin", "referer", "sec-fetch-site"):
        value = _single_header(headers, name)
        if value is not None:
            view[name] = value
    return view


def _is_form_content_type(content_type: str) -> bool:
    return content_type.split(";", 1)[0].strip().lower() == _FORM_CONTENT_TYPE


def _decode_form(body: bytes, content_type: str, header_name: str) -> Optional[str]:
    if not body or not _is_form_content_type(content_type):
        return None
    if len(body) > MAX_FORM_BYTES:
        raise CSRFError("request body is too large")
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CSRFError("invalid form encoding") from exc
    parsed = parse_qs(text, keep_blank_values=True, strict_parsing=False)
    names = []
    for name in (header_name, "csrf_token"):
        if name not in names:
            names.append(name)
    values: List[str] = []
    for name in names:
        values.extend(parsed.get(name, []))
    if len(values) > 1:
        raise CSRFError("CSRF token is ambiguous")
    return values[0] if values else None


def _extract_token(
    headers: HeadersMulti,
    body: bytes,
    *,
    header_name: str,
    allow_form: bool,
) -> str:
    header_token = _single_header(headers, header_name)
    content_type = _single_header(headers, "content-type") or ""
    form_token = _decode_form(body, content_type, header_name) if allow_form else None
    header_present = header_token is not None
    form_present = form_token is not None
    if header_present and form_present:
        if not hmac.compare_digest(header_token or "", form_token or ""):
            raise CSRFError("CSRF token mismatch")
        return header_token or ""
    if header_present:
        return header_token or ""
    if form_present:
        return form_token or ""
    raise CSRFError("CSRF token is missing")


def _reason_for(exc: Exception) -> str:
    if isinstance(exc, CSRFError):
        text = str(exc).lower()
        if "missing" in text:
            return "missing"
        if "ambiguous" in text or "duplicate" in text or "duplicated" in text:
            return "duplicate"
    return "invalid"


@dataclass(frozen=True)
class _PreparedRequest:
    session_id: str
    cookie_token: str
    transport_token: str
    set_cookie: str


class _ShieldCore:
    """Shared verification logic for both middleware flavors."""

    def __init__(
        self,
        tokens: TokenManager,
        origin_validator: OriginValidator,
        *,
        cookie_name: str,
        header_name: str,
        session_id: Union[str, Callable[[Any], str]],
        cookie_max_age: Optional[int],
        cookie_path: str,
        cookie_secure: bool,
        cookie_samesite: str,
        allow_form: bool,
        mask_tokens: bool,
    ) -> None:
        if not cookie_name or not isinstance(cookie_name, str):
            raise ConfigurationError("cookie_name must be a non-empty string")
        if not header_name or not isinstance(header_name, str):
            raise ConfigurationError("header_name must be a non-empty string")
        if any(ch not in _HEADER_NAME_CHARS for ch in header_name):
            raise ConfigurationError("header_name must be an HTTP token")
        if not callable(session_id) and (not isinstance(session_id, str) or not session_id):
            raise ConfigurationError("session_id must be a non-empty string or callable")
        try:
            format_cookie(
                cookie_name,
                "configuration-check",
                max_age=cookie_max_age,
                path=cookie_path,
                secure=cookie_secure,
                httponly=True,
                samesite=cookie_samesite,
            )
        except CookieError as exc:
            raise ConfigurationError("invalid cookie configuration") from exc
        self.tokens = tokens
        self.origin_validator = origin_validator
        self.cookie_name = cookie_name
        self.header_name = header_name
        self.session_id = session_id
        self.cookie_max_age = cookie_max_age
        self.cookie_path = cookie_path
        self.cookie_secure = cookie_secure
        self.cookie_samesite = cookie_samesite
        self.allow_form = allow_form
        self.mask_tokens = mask_tokens

    def _session_for(self, context: Any) -> str:
        value = self.session_id(context) if callable(self.session_id) else self.session_id
        if not isinstance(value, str) or not value:
            raise TokenError("invalid session identifier")
        return value

    def _normalize_token(self, value: str, session_id: str) -> str:
        """Return the canonical unmasked token, accepting either wire form."""
        if not isinstance(value, str) or not value:
            raise TokenError("invalid token")
        try:
            self.tokens.verify(value, session_id)
            return value
        except TokenError:
            pass
        if self.mask_tokens:
            try:
                unmasked = self.tokens.unmask(value)
                self.tokens.verify(unmasked, session_id)
                return unmasked
            except (MaskError, TokenError):
                pass
        raise TokenError("CSRF token is invalid")

    def _prepared(self, cookie_token: str, session_id: str) -> _PreparedRequest:
        return _PreparedRequest(
            session_id=session_id,
            cookie_token=cookie_token,
            transport_token=self.tokens.mask(cookie_token) if self.mask_tokens else cookie_token,
            set_cookie=format_cookie(
                self.cookie_name,
                cookie_token,
                max_age=self.cookie_max_age,
                path=self.cookie_path,
                secure=self.cookie_secure,
                httponly=True,
                samesite=self.cookie_samesite,
            ),
        )

    def _cookie_value(self, headers: HeadersMulti) -> Optional[str]:
        return unique_cookie_value(_values(headers, "cookie"), self.cookie_name)

    def prepare(
        self,
        method: str,
        headers: HeadersMulti,
        body: bytes,
        context: Any,
    ) -> _PreparedRequest:
        """Validate one request and return its canonical CSRF state."""
        self.origin_validator.validate(method, _origin_view(headers))
        session_id = self._session_for(context)
        if is_safe_method(method):
            canonical: Optional[str] = None
            try:
                cookie_value = self._cookie_value(headers)
                if cookie_value is not None:
                    canonical = self._normalize_token(cookie_value, session_id)
            except (CookieError, TokenError, MaskError):
                canonical = None
            if canonical is None:
                canonical = self.tokens.issue(session_id)
            return self._prepared(canonical, session_id)

        cookie_value = self._cookie_value(headers)
        if cookie_value is None:
            raise CookieError("CSRF cookie is missing or duplicated")
        cookie_token = self._normalize_token(cookie_value, session_id)
        supplied = _extract_token(
            headers,
            body,
            header_name=self.header_name,
            allow_form=self.allow_form,
        )
        supplied_token = self._normalize_token(supplied, session_id)
        if not hmac.compare_digest(cookie_token, supplied_token):
            raise TokenError("CSRF double-submit mismatch")
        return self._prepared(cookie_token, session_id)


def _validate_origin_first(core: _ShieldCore, method: str, headers: HeadersMulti) -> None:
    core.origin_validator.validate(method, _origin_view(headers))


class PyCSRFShieldWSGI:
    """WSGI middleware that protects unsafe HTTP methods.

    The verified masked transport token is exposed to the wrapped application
    as ``environ["pycsrfshield.token"]``. Render that value into forms or a
    meta tag; JavaScript and form posts then echo it in ``X-CSRF-Token``.
    """

    def __init__(
        self,
        app: Callable[..., Any],
        tokens: TokenManager,
        *,
        expected_origin: object,
        cookie_name: str = DEFAULT_COOKIE_NAME,
        header_name: str = DEFAULT_HEADER_NAME,
        session_id: Union[str, Callable[[Any], str]],
        allow_missing_origin: bool = False,
        allow_missing_referer: bool = True,
        allow_same_site_fetch: bool = True,
        cookie_max_age: Optional[int] = None,
        cookie_path: str = "/",
        cookie_secure: bool = True,
        cookie_samesite: str = "Lax",
        allow_form: bool = True,
        mask_tokens: bool = True,
        unauthorized_factory: Optional[Callable[[str], Any]] = None,
    ) -> None:
        self.app = app
        self.core = _ShieldCore(
            tokens,
            OriginValidator(
                expected_origin,
                allow_missing_origin=allow_missing_origin,
                allow_missing_referer=allow_missing_referer,
                allow_same_site_fetch=allow_same_site_fetch,
            ),
            cookie_name=cookie_name,
            header_name=header_name,
            session_id=session_id,
            cookie_max_age=cookie_max_age,
            cookie_path=cookie_path,
            cookie_secure=cookie_secure,
            cookie_samesite=cookie_samesite,
            allow_form=allow_form,
            mask_tokens=mask_tokens,
        )
        self.unauthorized_factory = unauthorized_factory

    def _deny(self, reason: str, start_response: Callable[..., Any]) -> List[bytes]:
        if self.unauthorized_factory is not None:
            produced = self.unauthorized_factory(reason)
            if isinstance(produced, bytes):
                body = produced
            elif isinstance(produced, str):
                body = produced.encode("utf-8")
            else:
                body = b"".join(produced)
        else:
            body = json.dumps({"detail": _REASONS.get(reason, "CSRF verification failed")}).encode("utf-8")
        start_response(
            "403 Forbidden",
            [
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(body))),
                ("Cache-Control", "no-store"),
            ],
        )
        return [body]

    def _read_form_body(self, environ: Mapping[str, Any]) -> bytes:
        raw_length = environ.get("CONTENT_LENGTH")
        stream = environ.get("wsgi.input")
        if stream is None or not hasattr(stream, "read"):
            raise CSRFError("invalid request body stream")
        unknown_length = raw_length in (None, "")
        if unknown_length:
            length = MAX_FORM_BYTES
        else:
            try:
                length = int(str(raw_length), 10)
            except (TypeError, ValueError) as exc:
                raise CSRFError("invalid content length") from exc
            if length < 0:
                raise CSRFError("invalid content length")
            if length > MAX_FORM_BYTES:
                raise CSRFError("request body is too large")
        body = stream.read(length + 1 if unknown_length else length)
        if not isinstance(body, bytes):
            raise CSRFError("invalid request body stream")
        if len(body) > MAX_FORM_BYTES:
            raise CSRFError("request body is too large")
        if unknown_length:
            if len(body) > MAX_FORM_BYTES:
                raise CSRFError("request body is too large")
        elif len(body) != length:
            raise CSRFError("request body incomplete")
        return body

    def __call__(
        self,
        environ: Dict[str, Any],
        start_response: Callable[..., Any],
    ) -> Iterable[bytes]:
        body = b""
        consumed = False
        try:
            headers = _headers_from_wsgi(environ)
            method = normalize_method(str(environ.get("REQUEST_METHOD", "GET")))
            _validate_origin_first(self.core, method, headers)
            content_type = _single_header(headers, "content-type") or ""
            should_read = (
                not is_safe_method(method)
                and self.core.allow_form
                and _is_form_content_type(content_type)
            )
            if should_read:
                body = self._read_form_body(environ)
                consumed = True
            prepared = self.core.prepare(method, headers, body, environ)
        except (CSRFError, ValueError, TypeError) as exc:
            return self._deny(_reason_for(exc), start_response)

        if consumed:
            environ["wsgi.input"] = io.BytesIO(body)
        environ["pycsrfshield.token"] = prepared.transport_token
        environ["pycsrfshield.session"] = prepared.session_id

        def hardened_start(status: str, response_headers: List[Tuple[str, str]], exc_info: Any = None) -> Any:
            hardened = list(response_headers)
            hardened.append(("Set-Cookie", prepared.set_cookie))
            hardened.append(("Cache-Control", "no-store"))
            return start_response(status, hardened, exc_info)

        return self.app(environ, hardened_start)


class PyCSRFShieldASGI:
    """ASGI 3.0 middleware for FastAPI, Starlette, Quart and similar apps.

    The verified masked transport token is exposed as
    ``scope["pycsrfshield"]["token"]`` and, when the scope state is a dict,
    ``scope["state"]["pycsrfshield"]["token"]``.
    """

    def __init__(
        self,
        app: Callable[..., Awaitable[None]],
        tokens: TokenManager,
        *,
        expected_origin: object,
        cookie_name: str = DEFAULT_COOKIE_NAME,
        header_name: str = DEFAULT_HEADER_NAME,
        session_id: Union[str, Callable[[Any], str]],
        allow_missing_origin: bool = False,
        allow_missing_referer: bool = True,
        allow_same_site_fetch: bool = True,
        cookie_max_age: Optional[int] = None,
        cookie_path: str = "/",
        cookie_secure: bool = True,
        cookie_samesite: str = "Lax",
        allow_form: bool = True,
        mask_tokens: bool = True,
    ) -> None:
        self.app = app
        self.core = _ShieldCore(
            tokens,
            OriginValidator(
                expected_origin,
                allow_missing_origin=allow_missing_origin,
                allow_missing_referer=allow_missing_referer,
                allow_same_site_fetch=allow_same_site_fetch,
            ),
            cookie_name=cookie_name,
            header_name=header_name,
            session_id=session_id,
            cookie_max_age=cookie_max_age,
            cookie_path=cookie_path,
            cookie_secure=cookie_secure,
            cookie_samesite=cookie_samesite,
            allow_form=allow_form,
            mask_tokens=mask_tokens,
        )

    async def _read_form_body(self, receive: Callable[..., Awaitable[Dict[str, Any]]]) -> Tuple[bytes, List[Tuple[bytes, bool]]]:
        pieces: List[bytes] = []
        events: List[Tuple[bytes, bool]] = []
        total = 0
        while True:
            message = await receive()
            if message.get("type") == "http.disconnect":
                raise CSRFError("request body incomplete")
            if message.get("type") != "http.request":
                continue
            chunk = message.get("body", b"")
            if not isinstance(chunk, bytes):
                raise CSRFError("invalid request body")
            total += len(chunk)
            if total > MAX_FORM_BYTES:
                raise CSRFError("request body is too large")
            more = bool(message.get("more_body", False))
            pieces.append(chunk)
            events.append((chunk, more))
            if not more:
                break
        return b"".join(pieces), events

    async def __call__(
        self,
        scope: Dict[str, Any],
        receive: Callable[..., Awaitable[Dict[str, Any]]],
        send: Callable[[Dict[str, Any]], Awaitable[None]],
    ) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        body = b""
        events: List[Tuple[bytes, bool]] = []
        consumed = False
        try:
            headers = _headers_from_asgi(scope)
            method = normalize_method(str(scope.get("method", "GET")))
            _validate_origin_first(self.core, method, headers)
            content_type = _single_header(headers, "content-type") or ""
            should_read = (
                not is_safe_method(method)
                and self.core.allow_form
                and _is_form_content_type(content_type)
            )
            if should_read:
                body, events = await self._read_form_body(receive)
                consumed = True
            prepared = self.core.prepare(method, headers, body, scope)
        except (CSRFError, ValueError, TypeError) as exc:
            reason = _reason_for(exc)
            payload = json.dumps({"detail": _REASONS.get(reason, "CSRF verification failed")}).encode("utf-8")
            await send({
                "type": "http.response.start",
                "status": 403,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(payload)).encode("ascii")),
                    (b"cache-control", b"no-store"),
                ],
            })
            await send({"type": "http.response.body", "body": payload})
            return

        details = {
            "token": prepared.transport_token,
            "cookie_name": self.core.cookie_name,
        }
        scope["pycsrfshield"] = details
        state = scope.setdefault("state", {})
        if isinstance(state, dict):
            state["pycsrfshield"] = details

        if consumed:
            event_index = 0

            async def replay() -> Dict[str, Any]:
                nonlocal event_index
                if event_index < len(events):
                    chunk, more = events[event_index]
                    event_index += 1
                    return {"type": "http.request", "body": chunk, "more_body": more}
                return {"type": "http.request", "body": b"", "more_body": False}

            downstream_receive = replay
        else:
            downstream_receive = receive

        async def hardened_send(message: Dict[str, Any]) -> None:
            if message.get("type") == "http.response.start":
                hardened = dict(message)
                headers_list = list(message.get("headers", []))
                headers_list.append((b"set-cookie", prepared.set_cookie.encode("latin-1")))
                headers_list.append((b"cache-control", b"no-store"))
                hardened["headers"] = headers_list
                await send(hardened)
                return
            await send(message)

        await self.app(scope, downstream_receive, hardened_send)


__all__ = [
    "PyCSRFShieldASGI",
    "PyCSRFShieldWSGI",
    "TOKEN_HEADER",
    "DEFAULT_COOKIE_NAME",
    "DEFAULT_HEADER_NAME",
    "MAX_FORM_BYTES",
]
