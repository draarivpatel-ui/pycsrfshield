# Good first issues

Each task is modular, has a clear definition of done, and needs no framework
installation. Add or update offline `unittest` coverage with every change.

1. **Token introspection helper.** Add `TokenManager.inspect(token, session_id)`
   that verifies first and returns a read-only mapping with version, issue time,
   expiry and purpose. Do not expose the nonce, signature, secret or session id.

2. **Token vector fixture file.** Move the structural token corruption cases into
   a table of named vectors in `tests/`. Each vector needs the mutation, the
   expected exception type and the security reason.

3. **Key rotation runbook.** Write `docs/key-rotation.md` covering primary
   promotion, fallback overlap, rollback and removal timing. Add one test that
   follows the documented sequence with two keys.

4. **Threat model document.** Write `docs/threat-model.md` describing what the
   library prevents, what the framework must provide, and what is out of scope.
   Include session binding, cookie tossing, BREACH and websocket boundaries.

5. **Cookie parser fuzz corpus.** Add a corpus-driven test table for raw Cookie
   headers: empty segments, duplicate names, quoted values, control characters,
   commas, malformed percent encoding and multiple header fields.

6. **Exact cookie serialization tests.** Add table-driven tests for
   `format_cookie` covering attribute order, `Max-Age`, all SameSite modes,
   leading-dot Domain normalization and every `__Host-` rejection.

7. **IPv6 origin matrix.** Expand origin tests for compressed and expanded
   IPv6 forms, default and nondefault ports, malformed brackets, zone ids and
   IPv4-mapped forms. Document which forms are accepted.

8. **Referer edge matrix.** Add tests for trusted Referer URLs with deep paths,
   encoded paths, query strings, explicit default ports, userinfo, fragments and
   trailing root-dot hosts.

9. **Fetch Metadata policy matrix.** Add method-by-value coverage for
   `same-origin`, `same-site`, `none`, `cross-site`, invalid values, empty
   values and duplicate headers in both middleware adapters.

10. **WSGI stream contract tests.** Add tests for `read(size)`, `read()`,
    `readline()` and iteration after form-body replay, including empty and
    exactly bounded bodies.

11. **ASGI chunk preservation tests.** Assert that replayed request chunks keep
    their original boundaries and `more_body` flags for empty chunks and for a
    body exactly at the form size limit.

12. **WebSocket policy proposal.** Draft `docs/websockets.md` with a concrete
    safe default for Origin validation on ASGI websocket scopes. Include a
    compatibility analysis before changing code.

13. **Framework example smoke tests.** Add dependency-free examples under
    `examples/` for plain WSGI and a minimal ASGI app, then test their token
    rendering helpers with the standard library only.

14. **README example lint.** Add a test that extracts Python code blocks from
    `README.md` and verifies each block with `ast.parse`, without executing
    examples or requiring Flask or FastAPI.

15. **Configuration error matrix.** Add construction-time tests for invalid
    cookie names, cookie attributes, header names, weak secrets, duplicate
    rotation keys and malformed expected origins in both adapters.

Open one focused pull request per issue. Run the full unittest suite before
submitting. Security-relevant changes must name the attack being closed and
include a regression test that fails without the fix.
