"""Validate Origin, Referer and Fetch Metadata request signals."""

from __future__ import annotations

import ipaddress
import re
from typing import Iterable, Mapping, Optional, Tuple
from urllib.parse import urlsplit

from .errors import OriginError

_SAFE_METHODS = frozenset(("GET", "HEAD", "OPTIONS", "TRACE"))
_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}
_ALLOWED_SCHEMES = frozenset(_DEFAULT_PORTS)
_FETCH_SITE_VALUES = frozenset(("cross-site", "same-origin", "same-site", "none"))
_METHOD_TOKEN = frozenset("!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_IPV4_SHAPE = re.compile(r"^[0-9.]+$")


def normalize_method(method: str) -> str:
    """Return an upper-case HTTP method, rejecting blank or non-token values."""
    if not isinstance(method, str) or not method.strip():
        raise OriginError("invalid HTTP method")
    value = method.strip().upper()
    if not value.isascii() or any(ch not in _METHOD_TOKEN for ch in value):
        raise OriginError("invalid HTTP method")
    return value


def is_safe_method(method: str) -> bool:
    """Return True for methods that cannot mutate server state."""
    try:
        return normalize_method(method) in _SAFE_METHODS
    except OriginError:
        return False


def _canonical_host(hostname: str) -> Tuple[str, bool]:
    """Return ``(canonical_host, is_ipv6)`` or raise."""
    if not hostname or len(hostname) > 253 or not hostname.isascii():
        raise OriginError("invalid origin host")
    host = hostname.lower()
    if "%" in host or "_" in host:
        raise OriginError("invalid origin host")
    if ":" in host:
        try:
            return ipaddress.IPv6Address(host).compressed, True
        except ValueError as exc:
            raise OriginError("invalid origin host") from exc
    if _IPV4_SHAPE.match(host):
        try:
            return str(ipaddress.IPv4Address(host)), False
        except ValueError as exc:
            raise OriginError("invalid origin host") from exc
    trailing_root = host.endswith(".")
    dns_name = host[:-1] if trailing_root else host
    if not dns_name:
        raise OriginError("invalid origin host")
    labels = dns_name.split(".")
    if any(not _DNS_LABEL.match(label) for label in labels):
        raise OriginError("invalid origin host")
    return host, False


def _split_url(value: str, *, allow_path: bool) -> Tuple[str, str, Optional[int], bool]:
    if not isinstance(value, str) or not value.strip():
        raise OriginError("empty origin")
    text = value.strip()
    if len(text) > 2048:
        raise OriginError("origin is too long")
    if not text.isascii():
        raise OriginError("origin must be ASCII")
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in text):
        raise OriginError("invalid characters in origin")
    if "\\" in text:
        raise OriginError("invalid origin syntax")
    try:
        parsed = urlsplit(text)
    except ValueError as exc:
        raise OriginError("invalid origin syntax") from exc
    scheme = parsed.scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise OriginError("unsupported origin scheme")
    if not parsed.netloc:
        raise OriginError("missing origin host")
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        raise OriginError("userinfo is not allowed in an origin")
    if parsed.fragment:
        raise OriginError("origin must not contain a fragment")
    if not allow_path and parsed.query:
        raise OriginError("origin must not contain a query")
    if not allow_path and parsed.path not in ("", "/"):
        raise OriginError("origin must not contain a path")
    if parsed.netloc.endswith(":"):
        raise OriginError("invalid origin port")
    try:
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise OriginError("invalid origin host or port") from exc
    if not hostname:
        raise OriginError("missing origin host")
    host, is_ipv6 = _canonical_host(hostname)
    if port is not None and not (1 <= port <= 65535):
        raise OriginError("invalid origin port")
    return scheme, host, port, is_ipv6


def _split_origin(value: str) -> Tuple[str, str, Optional[int], bool]:
    return _split_url(value, allow_path=False)


def _serialize(scheme: str, host: str, port: Optional[int], is_ipv6: bool) -> str:
    effective = port if port is not None else _DEFAULT_PORTS[scheme]
    printable_host = "[%s]" % host if is_ipv6 else host
    if effective == _DEFAULT_PORTS[scheme]:
        return "%s://%s" % (scheme, printable_host)
    return "%s://%s:%d" % (scheme, printable_host, effective)


def normalize_origin(value: str) -> str:
    """Normalize an origin to exact ``scheme://host[:port]`` canonical form.

    Scheme and host are lowercase. Default ports are removed, nondefault
    ports retained, IPv6 addresses canonicalized and bracketed. Trailing root
    dots are significant and are never silently removed.
    """
    scheme, host, port, is_ipv6 = _split_origin(value)
    return _serialize(scheme, host, port, is_ipv6)


def origin_from_url(value: str) -> str:
    """Extract and normalize the origin component of a full URL."""
    scheme, host, port, is_ipv6 = _split_url(value, allow_path=True)
    return _serialize(scheme, host, port, is_ipv6)


def origins_match(actual: str, expected: str) -> bool:
    """Compare two origins with exact scheme, host and normalized port."""
    try:
        return normalize_origin(actual) == normalize_origin(expected)
    except OriginError:
        return False


class OriginValidator:
    """Defense in depth checks for Origin, Referer and Fetch Metadata."""

    def __init__(
        self,
        expected_origin: object,
        allow_missing_origin: bool = False,
        allow_missing_referer: bool = True,
        allow_same_site_fetch: bool = True,
    ) -> None:
        if isinstance(expected_origin, str):
            values: Iterable[str] = (expected_origin,)
        else:
            try:
                values = tuple(expected_origin)  # type: ignore[arg-type]
            except TypeError as exc:
                raise OriginError("expected_origin must be a string or iterable") from exc
        if not values:
            raise OriginError("at least one expected origin is required")
        self.expected = frozenset(normalize_origin(str(item)) for item in values)
        self.allow_missing_origin = bool(allow_missing_origin)
        self.allow_missing_referer = bool(allow_missing_referer)
        self.allow_same_site_fetch = bool(allow_same_site_fetch)

    def _matches_expected(self, value: str) -> bool:
        try:
            return normalize_origin(value) in self.expected
        except OriginError:
            return False

    def validate_origin(self, value: Optional[str]) -> None:
        if value is None or not value.strip():
            if self.allow_missing_origin:
                return
            raise OriginError("missing Origin header")
        lowered = value.strip().lower()
        if lowered in ("null", "undefined", "file://"):
            raise OriginError("opaque origin is not allowed")
        if not self._matches_expected(value):
            raise OriginError("Origin does not match the application origin")

    def validate_referer(self, value: Optional[str]) -> None:
        if value is None or not value.strip():
            if self.allow_missing_referer:
                return
            raise OriginError("missing Referer header")
        lowered = value.strip().lower()
        if lowered in ("null", "undefined"):
            raise OriginError("opaque Referer is not allowed")
        try:
            candidate = origin_from_url(value.strip())
        except OriginError as exc:
            raise OriginError("Referer does not match the application origin") from exc
        if candidate not in self.expected:
            raise OriginError("Referer does not match the application origin")

    def validate_fetch_metadata(self, headers: Mapping[str, str]) -> None:
        site = None
        present = False
        for key, value in headers.items():
            if str(key).lower() == "sec-fetch-site":
                if present:
                    raise OriginError("ambiguous Sec-Fetch-Site header")
                present = True
                site = str(value).strip().lower()
        if not present:
            return
        if not site:
            raise OriginError("invalid Sec-Fetch-Site value")
        if site not in _FETCH_SITE_VALUES:
            raise OriginError("invalid Sec-Fetch-Site value")
        if site == "cross-site":
            raise OriginError("cross-site Fetch Metadata request rejected")
        if site == "same-site" and not self.allow_same_site_fetch:
            raise OriginError("same-site Fetch Metadata request rejected")

    def validate(self, method: str, headers: Mapping[str, str]) -> None:
        """Validate every available origin signal for one request."""
        normalized_method = normalize_method(method)
        lowered = {str(k).lower(): v for k, v in headers.items()}
        self.validate_fetch_metadata(headers)
        if normalized_method in _SAFE_METHODS:
            return
        self.validate_origin(lowered.get("origin"))
        self.validate_referer(lowered.get("referer"))


__all__ = [
    "OriginValidator",
    "is_safe_method",
    "normalize_method",
    "normalize_origin",
    "origin_from_url",
    "origins_match",
]
