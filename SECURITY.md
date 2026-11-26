# Security policy

## Supported versions

Only the latest released 1.x version receives security fixes.

## Reporting a vulnerability

Do not open a public issue for a security vulnerability. Use the repository's
private security advisory form or contact the maintainers through the contact
method listed on the package page. Include:

- the affected version
- a minimal reproduction
- the expected and observed behavior
- any suggested mitigation

You will receive an acknowledgement and a fix timeline once the report is
triaged. Please allow maintainers time to release a patch before disclosure.

## Scope

In scope:

- token forgery, replay or separator confusion
- cookie tossing and duplicate-cookie handling
- origin, referer and Fetch Metadata bypasses
- masking weaknesses that leak deterministic token bytes
- middleware request smuggling or body replay errors

Out of scope:

- vulnerabilities in the calling framework or web server
- denial of service from oversized requests beyond the documented limit
- deployment misconfiguration, including weak application secrets
