# Contributing

## Proposing ideas and features

Open an Issue in the repository with a short description of the problem and
the behaviour you would like to see.

## Proposing code

Send a Pull Request with a description of the changes. Before merging, make
sure that:

```bash
# tests
python -m pytest

# linter
ruff check .
```

- The code passes the tests and the linter
- User-facing strings (output, prompts, help) are added to both catalogs in
  `nginxparse/i18n.py` (`ru` and `en`) and used in code only via `t()`
- The PR description provides context: what it was, what it became, and why
- `detect_*`/`find_*` functions return structured data, `print_*` functions
  only format it: a new feature means a new pair of functions rather than
  growing existing files

## Important: access log privacy

Access logs contain real IPs, User-Agents and paths. If a PR or Issue includes
log samples or report output, you **must** do the following before publishing:

- replace real IPs with documentation ranges
  (`203.0.113.0/24`, `198.51.100.0/24`, `2001:db8::/32`)
- replace real domains with `example.com` / `example.local`
- use only synthetic data in tests and fixtures, never real logs

## Versioning and releases

- SemVer: `MAJOR.MINOR.PATCH`. The source of truth is `VERSION` in
  `nginxparse/constants.py`; `pyproject.toml` reads it automatically, so the
  version never needs to be duplicated by hand.
- Every change gets an entry in `CHANGELOG.md` (Keep a Changelog).
- Release: update `VERSION` -> add a CHANGELOG entry -> tag `vX.Y.Z`.
