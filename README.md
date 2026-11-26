# pycsrfshield

Zero-dependency CSRF protection for Python web applications. It combines signed
double-submit tokens, per-client session binding, strict origin checks,
cookie-tossing defense, BREACH-safe token masking, and framework-agnostic WSGI
and ASGI middleware.

- Python 3.9 or newer, standard library only
- HMAC-SHA256 tokens with length-prefixed canonical encoding
- Keyed session binding and constant-time signature verification
- Key rotation with primary and fallback secrets
- Random per-response XOR masking for transport tokens
- Raw `Cookie` header parsing that preserves and rejects duplicate names
- Exact Origin and Referer matching plus `Sec-Fetch-Site` validation
- Hardened `__Host-` cookies with `Secure`, `HttpOnly` and `SameSite=Lax`
- WSGI and ASGI 3.0 middleware with bounded form parsing
- 370 offline tests, all passing

## Install

```sh
python3 -m pip install pycsrfshield
```

## Security model

The middleware uses two wire forms of one signed token:

1. the unmasked cookie token, stored only in the CSRF cookie
2. the masked transport token, rendered into HTML or returned to the client and
   echoed in `X-CSRF-Token` or a URL-encoded form field

Each location accepts only its documented wire form: the unmasked token in the
cookie and the masked token in transport fields when masking is enabled. The
server verifies the HMAC signature, expiry, purpose and session binding, then
compares the canonical values with `hmac.compare_digest`.

A token is bound to the session identifier supplied by the application. This
must be stable for one client and must differ between clients. A user id is
suitable after login. Login and other anonymous flows need a random anonymous
session identifier issued by the application. A fixed string is useful in tests
but is not a safe production substitute because it does not separate clients.

Cookies are host-only `__Host-` cookies by default. They require HTTPS, cannot
be set with a Domain attribute and use `Path=/`. Unsafe requests are rejected
if a duplicate cookie of the same name appears, including a cookie tossed by a
sibling subdomain. The middleware owns the response header for its cookie name
and replaces downstream attempts to set it. It also forces a single
`Cache-Control: no-store` response header so a masked transport token cannot
be cached by accident.

## Quick start

Create one `TokenManager` per application and keep its secret out of source
control. Secrets must be at least 16 bytes; use at least 32 random bytes in
production.

```python
from pycsrfshield import TokenManager

tokens = TokenManager(
    secrets=["replace-with-32-plus-random-bytes"],
    ttl=3600,
    clock_skew=60,
)
```

The lower-level API can issue both wire forms for one token:

```python
cookie_token, transport_token = tokens.issue_pair(session_id)
```

Store `cookie_token` in the CSRF cookie. Render `transport_token` in a hidden
form field or meta tag. Never expose the signing secret or the raw session id.

## Flask or another WSGI framework

```python
from flask import Flask
from pycsrfshield import PyCSRFShieldWSGI, TokenManager

app = Flask(__name__)
tokens = TokenManager(secrets=["replace-with-32-plus-random-bytes"])

def session_id_from_environ(environ):
    return environ["example.session_id"]

app.wsgi_app = PyCSRFShieldWSGI(
    app.wsgi_app,
    tokens,
    expected_origin="https://app.example.com",
    session_id=session_id_from_environ,
)
```

`example.session_id` must be written by the session or authentication middleware
that runs before this adapter. The verified masked token for the current request
is available to the wrapped application as `environ["pycsrfshield.token"]`.
Render that value as a hidden field or as `<meta name="csrf-token" content="...">`.

## FastAPI, Starlette or Quart (ASGI)

```python
from fastapi import FastAPI
from pycsrfshield import PyCSRFShieldASGI, TokenManager

app = FastAPI()
tokens = TokenManager(secrets=["replace-with-32-plus-random-bytes"])

def session_id_from_scope(scope):
    return scope["example.session_id"]

app.add_middleware(
    PyCSRFShieldASGI,
    tokens=tokens,
    expected_origin="https://app.example.com",
    session_id=session_id_from_scope,
)
```

For direct wrapping:

```python
app = PyCSRFShieldASGI(
    app,
    tokens,
    expected_origin="https://app.example.com",
    session_id=session_id_from_scope,
)
```

The masked transport token is available as `scope["pycsrfshield"]["token"]`.
When the scope state is a dict it is also available as
`scope["state"]["pycsrfshield"]["token"]`.

## Plain WSGI

```python
from pycsrfshield import PyCSRFShieldWSGI, TokenManager

application = PyCSRFShieldWSGI(
    application,
    TokenManager(secrets=["replace-with-32-plus-random-bytes"]),
    expected_origin="https://app.example.com",
    session_id=lambda environ: environ["example.session_id"],
)
```

## Client contract

Unsafe methods such as POST, PUT, PATCH and DELETE must include one token in
one of these places:

- the `X-CSRF-Token` header
- a URL-encoded form field named `X-CSRF-Token`
- a URL-encoded form field named `csrf_token`

If both header and form values are present they must be identical. Duplicate
fields are rejected. Form parsing is limited to 1 MiB and applies only to
`application/x-www-form-urlencoded` bodies. JSON bodies are not consumed by the
middleware.

GET, HEAD, OPTIONS and TRACE are safe-method exemptions and do not require a
token. Method names are normalized case-insensitively. Fetch Metadata is still
enforced, and `Sec-Fetch-Site: cross-site` is rejected.

## Key rotation

```python
tokens = TokenManager(
    secrets=["current-secret", "previous-secret"],
)
```

The first secret signs new tokens. Every secret verifies tokens. Because the
session binding is keyed, verification uses the same key that authenticated the
token. Remove an old secret after every token it signed has expired.

## Origin, Referer and Fetch Metadata

`OriginValidator` accepts a single origin or a list. Matching is exact after
canonicalization: scheme, lowercase host and normalized default port.
Nondefault ports are significant. Opaque origins such as `null`, userinfo such
as `https://example.com@evil.test`, host prefix or suffix tricks, malformed IP
addresses and duplicate security headers are rejected.

Unsafe methods require a matching Origin by default. Referer validation is
defense in depth when present; missing Referer headers are tolerated by default
because some privacy tools suppress them. Both behaviors are configurable.

## Operational notes

- WebSocket and lifespan scopes pass through the ASGI adapter. If the wrapped
  application accepts WebSockets, enforce its own Origin policy during the
  handshake.
- Tokens expire after `ttl` seconds. Render fresh transport tokens from safe
  page responses and keep `clock_skew` small.
- The middleware re-emits the canonical cookie token rather than rotating it
  after every POST, preventing clients from being locked out by a response they
  did not parse.
- Denial responses are intentionally generic JSON with status 403 and
  `Cache-Control: no-store`.
- `mask_tokens=False` is provided for constrained non-browser integrations.
  Keep the default enabled whenever tokens appear in compressed HTML responses.

## Testing

```sh
PYTHONPATH=src python3 -m unittest discover -s tests
```

## License

MIT. See [LICENSE](LICENSE).
