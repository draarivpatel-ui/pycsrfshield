# Contributing

Thanks for helping improve pycsrfshield.

## Setup

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e .
```

The library has no runtime dependencies. Tests use only `unittest`.

## Before opening a pull request

1. Add or update tests for your change.
2. Run `PYTHONPATH=src python3 -m unittest discover -s tests`.
3. Keep Python 3.9 compatibility. Avoid newer syntax.
4. Keep the public API small and documented.
5. Do not add runtime dependencies.

For security-relevant changes, explain the attack being closed and include a
test that fails before the fix.

## Style

- Use type hints on public functions.
- Prefer explicit comparisons and constant-time checks for secrets.
- Avoid ambiguous string concatenation in cryptographic encodings.
- Keep error messages generic so they cannot leak token material.

## Good first issues

See [docs/good-first-issues.md](docs/good-first-issues.md) for self-contained
starter tasks.
