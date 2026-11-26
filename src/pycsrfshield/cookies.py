"""Raw cookie header parsing with duplicate-name and cookie-tossing defense."""

from __future__ import annotations

import ipaddress
import re
from typing import Dict, List, Optional, Sequence, Union
from urllib.parse import unquote

from .errors import CookieError

# RFC 9110 token characters, also valid for cookie names in RFC 6265.
_NAME_CHARS = frozenset(
    "!#$%&'*+-.^_`|~0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
)

# RFC 6265 cookie-octet: %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E.
_VALUE_CHARS = frozenset(
    chr(code)
    for span in ((0x21, 0x21), (0x23, 0x2B), (0x2D, 0x3A), (0x3C, 0x5B), (0x5D, 0x7E))
    for code in range(span[0], span[1] + 1)
)

_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

CookieHeader = Union[str, Sequence[str], None]


def _valid_cookie_name(name: str) -> bool:
    return isinstance(name, str) and bool(name) and all(ch in _NAME_CHARS for ch in name)


def _valid_cookie_value(value: str) -> bool:
    return all(ch in _VALUE_CHARS for ch in value)


def _header_list(header: CookieHeader) -> List[str]:
    if header is None:
        return []
    if isinstance(header, str):
        return [header]
    if isinstance(header, (bytes, bytearray, memoryview)):
        raise CookieError("Cookie header must be text")
    try:
        values = list(header)
    except TypeError as exc:
        raise CookieError("Cookie header must be text or a sequence of text") from exc
    if any(not isinstance(item, str) for item in values):
        raise CookieError("Cookie header sequence must contain only text")
    return values


def split_cookie_header(header: str) -> List[str]:
    """Split one raw Cookie header on semicolons outside double quotes."""
    if not isinstance(header, str):
        raise CookieError("Cookie header must be a string")
    parts: List[str] = []
    current: List[str] = []
    quoted = False
    for ch in header:
        if ch == '"':
            quoted = not quoted
            current.append(ch)
            continue
        if ch == ";" and not quoted:
            parts.append("".join(current))
            current = []
            continue
        current.append(ch)
    parts.append("".join(current))
    if quoted:
        raise CookieError("unterminated quoted cookie value")
    return parts


def parse_cookie_header(header: CookieHeader) -> Dict[str, List[str]]:
    """Parse all occurrences of each cookie name from raw Cookie headers.

    Duplicate names are preserved in order. Multiple Cookie header fields are
    treated as the concatenation permitted by HTTP, so a tossed duplicate can
    never become invisible merely because it arrived in another header field.
    Malformed input fails closed with :class:`CookieError`.
    """
    result: Dict[str, List[str]] = {}
    for item in _header_list(header):
        for part in split_cookie_header(item):
            if not part.strip():
                continue
            if "=" not in part:
                raise CookieError("malformed cookie pair")
            name, raw_value = part.split("=", 1)
            name = name.strip()
            value = raw_value.strip()
            if not _valid_cookie_name(name):
                raise CookieError("invalid cookie name")
            quoted = len(value) >= 2 and value[0] == '"' and value[-1] == '"'
            if quoted:
                if not _valid_cookie_value(value[1:-1]):
                    raise CookieError("invalid cookie value")
            elif '"' in value or not _valid_cookie_value(value):
                raise CookieError("invalid cookie value")
            result.setdefault(name, []).append(value)
    return result


def get_cookie_values(header: CookieHeader, name: str) -> List[str]:
    """Return every value for the exact case-sensitive cookie ``name``."""
    if not _valid_cookie_name(name):
        raise CookieError("invalid cookie name")
    cookies = parse_cookie_header(header)
    return list(cookies.get(name, []))


def unique_cookie_value(header: CookieHeader, name: str) -> Optional[str]:
    """Return a value only when exactly one cookie with ``name`` is present.

    Multiple values, including a valid token plus a tossed duplicate from a
    sibling subdomain, are always rejected.
    """
    values = get_cookie_values(header, name)
    if len(values) != 1:
        return None
    return values[0]


def decode_cookie_value(value: str) -> str:
    """Percent-decode a cookie value with strict UTF-8 handling."""
    try:
        decoded = unquote(value, encoding="utf-8", errors="strict")
    except (UnicodeDecodeError, ValueError) as exc:
        raise CookieError("invalid cookie encoding") from exc
    return decoded


def _valid_domain(domain: str) -> bool:
    if not domain or len(domain) > 253 or not domain.isascii():
        return False
    value = domain.lower().lstrip(".")
    if not value or value.endswith("."):
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass
    labels = value.split(".")
    return all(_DOMAIN_LABEL.match(label) for label in labels)


def format_cookie(
    name: str,
    value: str,
    *,
    max_age: Optional[int] = None,
    path: str = "/",
    secure: bool = True,
    httponly: bool = True,
    samesite: str = "Lax",
    domain: Optional[str] = None,
) -> str:
    """Build a hardened Set-Cookie value.

    Defaults produce a host-only ``__Host-`` compatible cookie. A ``__Host-``
    cookie must not have a Domain, must use ``Path=/`` and must be Secure.
    Values are intentionally restricted to RFC 6265 cookie octets; callers can
    percent-encode other data before formatting.
    """
    if not _valid_cookie_name(name):
        raise CookieError("invalid cookie name")
    if not isinstance(value, str) or not _valid_cookie_value(value):
        raise CookieError("invalid cookie value")
    mode = samesite.lower() if isinstance(samesite, str) else ""
    if mode not in ("lax", "strict", "none"):
        raise CookieError("invalid SameSite value")
    if mode == "none" and not secure:
        raise CookieError("SameSite=None requires Secure")
    if max_age is not None and (
        not isinstance(max_age, int) or isinstance(max_age, bool) or max_age < 0
    ):
        raise CookieError("invalid Max-Age")
    if not isinstance(path, str) or not path.startswith("/"):
        raise CookieError("invalid cookie path")
    if any(ord(ch) < 0x20 or ord(ch) > 0x7E or ch == ";" for ch in path):
        raise CookieError("invalid cookie path")
    if domain is not None:
        if not isinstance(domain, str) or not _valid_domain(domain):
            raise CookieError("invalid cookie domain")
        domain = domain.lower().lstrip(".")
    prefix_name = name.lower()
    if prefix_name.startswith("__secure-") and not secure:
        raise CookieError("__Secure- cookies must be Secure")
    if prefix_name.startswith("__host-"):
        if domain is not None:
            raise CookieError("__Host- cookies must not set Domain")
        if path != "/":
            raise CookieError("__Host- cookies must use Path=/")
        if not secure:
            raise CookieError("__Host- cookies must be Secure")
    segments = ["%s=%s" % (name, value)]
    if domain is not None:
        segments.append("Domain=%s" % domain)
    segments.append("Path=%s" % path)
    if max_age is not None:
        segments.append("Max-Age=%d" % max_age)
    if secure:
        segments.append("Secure")
    if httponly:
        segments.append("HttpOnly")
    segments.append("SameSite=%s" % mode.capitalize())
    return "; ".join(segments)
