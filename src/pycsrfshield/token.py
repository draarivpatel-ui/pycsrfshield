"""Signed double-submit CSRF tokens with BREACH-safe masking."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets as secrets_module
import struct
import time
from typing import Iterable, Optional, Sequence, Tuple, Union

from .errors import ConfigurationError, MaskError, TokenError

MIN_SECRET_BYTES = 16
VERSION = 1
MASK_BYTES = 32
NONCE_BYTES = 16
MAX_TOKEN_BYTES = 4096
_B64_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64decode(text: str, *, error: TokenError) -> bytes:
    """Decode canonical unpadded base64url or raise the supplied error."""
    if not isinstance(text, str) or not text:
        raise error
    if any(ch not in _B64_CHARS for ch in text):
        raise error
    if len(text) % 4 == 1:
        raise error
    padding = "=" * (-len(text) % 4)
    try:
        raw = base64.urlsafe_b64decode((text + padding).encode("ascii"))
    except (ValueError, TypeError) as exc:
        raise error from exc
    if _b64encode(raw) != text:
        raise error
    return raw


def _as_secret(secret: Union[str, bytes], *, label: str) -> bytes:
    if isinstance(secret, str):
        value = secret.encode("utf-8")
    elif isinstance(secret, (bytes, bytearray, memoryview)):
        value = bytes(secret)
    else:
        raise ConfigurationError("%s must be str or bytes" % label)
    if len(value) < MIN_SECRET_BYTES:
        raise ConfigurationError("%s must be at least 16 bytes" % label)
    return value


def _u32(value: int) -> bytes:
    return struct.pack(">I", value)


def _length_prefixed(value: bytes) -> bytes:
    if len(value) > 0xFFFFFFFF:
        raise TokenError("field is too long")
    return _u32(len(value)) + value


def _canonical(
    session: str,
    expires: int,
    issued: int,
    nonce: bytes,
    purpose: str,
) -> bytes:
    pieces = (
        _u32(VERSION),
        _length_prefixed(session.encode("utf-8")),
        _u32(expires),
        _u32(issued),
        _length_prefixed(nonce),
        _length_prefixed(purpose.encode("utf-8")),
    )
    return b"".join(pieces)


class _PayloadReader:
    """Strict cursor over an authenticated canonical token payload."""

    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.offset = 0

    def read_u32(self) -> int:
        if self.offset + 4 > len(self.payload):
            raise TokenError("invalid token field")
        value = struct.unpack_from(">I", self.payload, self.offset)[0]
        self.offset += 4
        return value

    def read_field(self) -> bytes:
        length = self.read_u32()
        if length > len(self.payload) - self.offset:
            raise TokenError("invalid token field")
        value = self.payload[self.offset:self.offset + length]
        self.offset += length
        return value

    def finish(self) -> None:
        if self.offset != len(self.payload):
            raise TokenError("invalid token length")


class TokenManager:
    """Create and verify length-prefixed, HMAC-SHA256 CSRF tokens.

    The signed payload binds a keyed session digest, an absolute expiry, an
    issue time, a random nonce and a purpose string. Length prefixes remove
    the delimiter confusion that makes naive ``a|b`` encodings ambiguous.

    ``secrets`` is a primary secret or a sequence whose first item signs new
    tokens. Later items are fallback verification keys used during rotation.
    """

    def __init__(
        self,
        secrets: Union[str, bytes, Sequence[Union[str, bytes]]],
        *,
        ttl: int = 3600,
        clock_skew: int = 60,
        purpose: str = "csrf",
        session_salt: str = "pycsrfshield-session",
    ) -> None:
        if isinstance(secrets, (str, bytes, bytearray, memoryview)):
            raw_secrets: Iterable[Union[str, bytes]] = [secrets]  # type: ignore[list-item]
        else:
            try:
                raw_secrets = tuple(secrets)  # type: ignore[arg-type]
            except TypeError as exc:
                raise ConfigurationError("secrets must be a secret or a sequence") from exc
        keys = [_as_secret(item, label="secret") for item in raw_secrets]
        if not keys:
            raise ConfigurationError("at least one secret is required")
        if len(set(keys)) != len(keys):
            raise ConfigurationError("secrets must be distinct")
        if (not isinstance(ttl, int) or isinstance(ttl, bool) or ttl <= 0):
            raise ConfigurationError("ttl must be a positive integer")
        if (not isinstance(clock_skew, int) or isinstance(clock_skew, bool) or clock_skew < 0):
            raise ConfigurationError("clock_skew must be a non-negative integer")
        if clock_skew >= ttl:
            raise ConfigurationError("clock_skew must be smaller than ttl")
        if not isinstance(purpose, str) or not purpose:
            raise ConfigurationError("purpose must be a non-empty string")
        if not isinstance(session_salt, str) or not session_salt:
            raise ConfigurationError("session_salt must be a non-empty string")
        self._keys = tuple(keys)
        self.ttl = ttl
        self.clock_skew = clock_skew
        self.purpose = purpose
        self._session_salt = session_salt.encode("utf-8")

    @property
    def key_count(self) -> int:
        """Number of configured keys, including fallbacks."""
        return len(self._keys)

    def _session_binding(self, key: bytes, session_id: str) -> str:
        if not isinstance(session_id, str) or not session_id:
            raise TokenError("invalid session identifier")
        material = b"".join(
            (
                _length_prefixed(b"pycsrfshield-session-binding-v1"),
                _length_prefixed(self._session_salt),
                _length_prefixed(session_id.encode("utf-8")),
            )
        )
        return _b64encode(hmac.new(key, material, hashlib.sha256).digest())

    def bind_session(self, session_id: str) -> str:
        """Derive the primary-key session binding value."""
        return self._session_binding(self._keys[0], session_id)

    @staticmethod
    def _clock_value(now: Optional[float]) -> int:
        value = time.time() if now is None else now
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise TokenError("invalid clock value")
        if value < 0:
            raise TokenError("invalid clock value")
        try:
            return int(value)
        except (OverflowError, ValueError) as exc:
            raise TokenError("invalid clock value") from exc

    def issue(self, session_id: str, *, now: Optional[float] = None) -> str:
        """Return a signed, unmasked token for ``session_id``."""
        binding = self.bind_session(session_id)
        timestamp = self._clock_value(now)
        if timestamp < 0 or timestamp > 0xFFFFFFFF - self.ttl:
            raise TokenError("invalid clock value")
        nonce = secrets_module.token_bytes(NONCE_BYTES)
        payload = _canonical(binding, timestamp + self.ttl, timestamp, nonce, self.purpose)
        signature = hmac.new(self._keys[0], payload, hashlib.sha256).digest()
        return _b64encode(payload + signature)

    def issue_pair(self, session_id: str, *, now: Optional[float] = None) -> Tuple[str, str]:
        """Return ``(cookie_token, masked_transport_token)`` for one signed token.

        Store the first value in the CSRF cookie. Put the second in the HTML,
        form or API response that the client echoes back. The random mask is
        fresh for this pair, so compressed responses never expose a stable
        token byte string.
        """
        cookie_token = self.issue(session_id, now=now)
        return cookie_token, self.mask(cookie_token)

    def _split_signed_token(self, token: str) -> bytes:
        raw = _b64decode(token, error=TokenError("invalid token encoding"))
        if len(raw) > MAX_TOKEN_BYTES:
            raise TokenError("invalid token length")
        signed_end = len(raw) - 32
        if signed_end < 16:
            raise TokenError("invalid token length")
        return raw

    def _matching_key(self, raw: bytes) -> Tuple[int, bytes]:
        signed_end = len(raw) - 32
        payload = raw[:signed_end]
        signature = raw[signed_end:]
        matched_index = -1
        matched_key = b""
        for index, key in enumerate(self._keys):
            expected = hmac.new(key, payload, hashlib.sha256).digest()
            if hmac.compare_digest(expected, signature):
                matched_index = index
                matched_key = key
        if matched_index < 0:
            raise TokenError("token signature mismatch")
        return matched_index, matched_key

    def verify(
        self,
        token: str,
        session_id: str,
        *,
        now: Optional[float] = None,
    ) -> str:
        """Verify a token and return its session binding string.

        The signature is authenticated before the attacker-controlled payload
        is parsed. Malformed input, an unknown key, expiry or a session or
        purpose mismatch raises :class:`TokenError`.
        """
        if not isinstance(token, str) or not token:
            raise TokenError("invalid token")
        try:
            expected_binding = self.bind_session(session_id)
        except TokenError as exc:
            raise TokenError("token verification failed") from exc
        raw = self._split_signed_token(token)
        signed_end = len(raw) - 32
        payload = raw[:signed_end]
        key_index, key = self._matching_key(raw)

        reader = _PayloadReader(payload)
        version = reader.read_u32()
        if version != VERSION:
            raise TokenError("unsupported token version")
        token_binding_raw = reader.read_field()
        expires = reader.read_u32()
        issued = reader.read_u32()
        nonce = reader.read_field()
        purpose_raw = reader.read_field()
        reader.finish()

        try:
            token_binding = token_binding_raw.decode("ascii", errors="strict")
            token_purpose = purpose_raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise TokenError("invalid token field") from exc
        if len(token_binding) != 43 or any(ch not in _B64_CHARS for ch in token_binding):
            raise TokenError("invalid token field")
        actual_binding = self._session_binding(key, session_id)
        if key_index == 0:
            actual_binding = expected_binding
        if not hmac.compare_digest(token_binding, actual_binding):
            raise TokenError("token session mismatch")
        if token_purpose != self.purpose:
            raise TokenError("token purpose mismatch")
        if len(nonce) < NONCE_BYTES:
            raise TokenError("invalid token nonce")
        if expires <= issued:
            raise TokenError("invalid token lifetime")
        if expires - issued > self.ttl + self.clock_skew:
            raise TokenError("invalid token lifetime")
        current = self._clock_value(now)
        if current + self.clock_skew < issued:
            raise TokenError("token is not yet valid")
        if current - self.clock_skew >= expires:
            raise TokenError("token has expired")
        return token_binding

    def mint(self, session_id: str, *, now: Optional[float] = None) -> str:
        """Return a fresh masked transport token."""
        return self.mask(self.issue(session_id, now=now))

    def mask(self, token: str, *, mask: Optional[bytes] = None) -> str:
        """XOR-mask a token with a fresh random 32-byte pad.

        The pad is prepended to the masked value. This masking is a BREACH
        randomization measure, not encryption, and is always used together
        with the signed token checks above.
        """
        if not isinstance(token, str) or not token:
            raise TokenError("invalid token")
        raw = _b64decode(token, error=TokenError("invalid token encoding"))
        if len(raw) > MAX_TOKEN_BYTES:
            raise TokenError("invalid token length")
        pad = secrets_module.token_bytes(MASK_BYTES) if mask is None else mask
        if not isinstance(pad, (bytes, bytearray, memoryview)):
            raise MaskError("invalid mask length")
        pad_bytes = bytes(pad)
        if len(pad_bytes) != MASK_BYTES:
            raise MaskError("invalid mask length")
        mixed = bytes(
            value ^ pad_bytes[index % MASK_BYTES]
            for index, value in enumerate(raw)
        )
        return _b64encode(pad_bytes + mixed)

    def unmask(self, masked: str) -> str:
        """Recover an unmasked token from a masked token."""
        if not isinstance(masked, str) or not masked:
            raise MaskError("invalid masked token")
        raw = _b64decode(masked, error=MaskError("invalid masked token encoding"))
        if len(raw) > MASK_BYTES + MAX_TOKEN_BYTES:
            raise MaskError("masked token is too long")
        if len(raw) <= MASK_BYTES:
            raise MaskError("masked token is too short")
        pad = raw[:MASK_BYTES]
        payload = raw[MASK_BYTES:]
        restored = bytes(
            value ^ pad[index % MASK_BYTES]
            for index, value in enumerate(payload)
        )
        return _b64encode(restored)

    def verify_masked(
        self,
        masked: str,
        session_id: str,
        *,
        now: Optional[float] = None,
    ) -> str:
        """Unmask and verify a transport token in one step."""
        return self.verify(self.unmask(masked), session_id, now=now)


__all__ = [
    "MASK_BYTES",
    "MAX_TOKEN_BYTES",
    "MIN_SECRET_BYTES",
    "NONCE_BYTES",
    "TokenManager",
    "ConfigurationError",
    "MaskError",
    "TokenError",
]
