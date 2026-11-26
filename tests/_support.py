"""Shared test helpers for pycsrfshield's offline unittest suite."""

from __future__ import annotations

import base64
import io
import struct
from typing import Any, Dict, List, Mapping, Optional

from pycsrfshield import TokenManager

SECRET = b"0123456789abcdefTESTSECRET"
OTHER_SECRET = b"fedcba9876543210OTHERSECRET"
ORIGIN = "https://app.example.com"


def now() -> int:
    return 1_700_000_000


def manager(**kwargs: Any) -> TokenManager:
    options: Dict[str, Any] = {"ttl": 3600, "clock_skew": 60}
    options.update(kwargs)
    options.setdefault("secrets", SECRET)
    return TokenManager(**options)


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def raw_token(token: str) -> bytes:
    return unb64(token)


def resign(raw: bytes, secret: bytes = SECRET) -> str:
    """Re-sign a mutated payload so structure tests reach semantic checks."""
    import hashlib
    import hmac

    signature = hmac.new(secret, raw, hashlib.sha256).digest()
    return b64(raw + signature)


def wsgi_environ(
    method: str = "POST",
    *,
    cookies: Optional[str] = None,
    headers: Optional[Mapping[str, str]] = None,
    body: bytes = b"",
    content_type: str = "application/x-www-form-urlencoded",
) -> Dict[str, Any]:
    environ: Dict[str, Any] = {
        "REQUEST_METHOD": method,
        "wsgi.input": io.BytesIO(body),
        "CONTENT_LENGTH": str(len(body)),
        "wsgi.url_scheme": "https",
        "SERVER_NAME": "app.example.com",
        "SERVER_PORT": "443",
        "SCRIPT_NAME": "",
        "PATH_INFO": "/transfer",
        "QUERY_STRING": "",
    }
    if cookies is not None:
        environ["HTTP_COOKIE"] = cookies
    if body:
        environ["CONTENT_TYPE"] = content_type
    for key, value in (headers or {}).items():
        environ["HTTP_" + key.upper().replace("-", "_")] = value
    return environ


def asgi_scope(
    method: str = "POST",
    *,
    cookies: Optional[str] = None,
    headers: Optional[Mapping[str, str]] = None,
) -> Dict[str, Any]:
    pairs: List[List[bytes]] = []
    if cookies is not None:
        pairs.append([b"cookie", cookies.encode("latin-1")])
    if method.upper() in ("POST", "PUT", "PATCH", "DELETE"):
        pairs.append([b"content-type", b"application/x-www-form-urlencoded"])
    for key, value in (headers or {}).items():
        pairs.append([key.lower().encode("latin-1"), str(value).encode("latin-1")])
    return {
        "type": "http",
        "method": method,
        "scheme": "https",
        "path": "/transfer",
        "headers": pairs,
        "server": ("app.example.com", 443),
    }


class StartResponse:
    """Minimal WSGI start_response recorder."""

    def __init__(self) -> None:
        self.status = ""
        self.headers: List[Any] = []
        self.exc_info: Any = None

    def __call__(self, status: str, headers: List[Any], exc_info: Any = None) -> None:
        self.status = status
        self.headers = headers
        self.exc_info = exc_info

    def header(self, name: str) -> Optional[str]:
        for key, value in self.headers:
            if key.lower() == name.lower():
                return value
        return None


def collect(app: Any, environ: Dict[str, Any], start: StartResponse) -> bytes:
    return b"".join(app(environ, start))


class ASGIApp:
    """Tiny ASGI app that records the replayed request body."""

    def __init__(self, status: int = 200) -> None:
        self.status = status
        self.body = b""
        self.messages: List[Dict[str, Any]] = []
        self.state: Dict[str, Any] = {}

    async def __call__(self, scope: Dict[str, Any], receive: Any, send: Any) -> None:
        self.state = scope.get("state", {})
        while True:
            message = await receive()
            if message["type"] == "http.request":
                self.body += message.get("body", b"")
                if not message.get("more_body", False):
                    break
        await send({"type": "http.response.start", "status": self.status, "headers": [(b"content-type", b"text/plain")]})
        await send({"type": "http.response.body", "body": b"ok"})
        self.messages.append({"type": "done"})


async def drive(scope: Dict[str, Any], app: Any, body: bytes = b"", *, more: bool = False) -> List[Dict[str, Any]]:
    sent: List[Dict[str, Any]] = []
    state = {"used": False}

    async def receive() -> Dict[str, Any]:
        if state["used"]:
            return {"type": "http.request", "body": b"", "more_body": False}
        state["used"] = True
        return {"type": "http.request", "body": body, "more_body": more}

    async def send(message: Dict[str, Any]) -> None:
        sent.append(message)

    await app(scope, receive, send)
    return sent


def pack_u32(value: int) -> bytes:
    return struct.pack(">I", value)
