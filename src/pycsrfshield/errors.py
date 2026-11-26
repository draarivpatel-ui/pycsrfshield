"""Exception hierarchy for pycsrfshield."""

from __future__ import annotations


class CSRFError(Exception):
    """Base class for all CSRF shield failures.

    Subclasses deliberately carry generic messages so that details about
    secrets, tokens and request structure never leak through error channels.
    """


class ConfigurationError(CSRFError):
    """Raised when shield or token configuration is invalid."""


class TokenError(CSRFError):
    """Raised when a token is malformed, expired or fails verification."""


class MaskError(TokenError):
    """Raised when a masked token has an invalid mask or encoding."""


class CookieError(CSRFError):
    """Raised when cookie headers or attributes are malformed."""


class OriginError(CSRFError):
    """Raised when origin, referer or Fetch Metadata checks fail."""
