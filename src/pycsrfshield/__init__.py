"""pycsrfshield: zero-dependency CSRF protection for Python web apps."""

from __future__ import annotations

from .cookies import (
    format_cookie,
    get_cookie_values,
    parse_cookie_header,
    split_cookie_header,
    unique_cookie_value,
)
from .errors import (
    ConfigurationError,
    CookieError,
    CSRFError,
    MaskError,
    OriginError,
    TokenError,
)
from .middleware import PyCSRFShieldASGI, PyCSRFShieldWSGI
from .origin import (
    is_safe_method,
    normalize_method,
    normalize_origin,
    origin_from_url,
    OriginValidator,
    origins_match,
)
from .token import TokenManager

__version__ = "1.0.0"

__all__ = [
    "ConfigurationError",
    "CookieError",
    "CSRFError",
    "MaskError",
    "OriginError",
    "TokenError",
    "OriginValidator",
    "PyCSRFShieldASGI",
    "PyCSRFShieldWSGI",
    "TokenManager",
    "format_cookie",
    "get_cookie_values",
    "is_safe_method",
    "normalize_method",
    "normalize_origin",
    "origin_from_url",
    "origins_match",
    "parse_cookie_header",
    "split_cookie_header",
    "unique_cookie_value",
    "__version__",
]
