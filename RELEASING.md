# Releases

The process for shipping a new version. It is the same for every module in the
Jealous Moon toolkit (`jealous-nginx`, `jealous-strace`, `jealous-domain`).

## Versioning

[Semantic Versioning](https://semver.org/): `MAJOR.MINOR.PATCH`.

- **MAJOR** - breaking changes: a flag is removed, output semantics change,
  or the JSON report format changes
- **MINOR** - new functionality without breakage: a new report section,
  a new flag, a new console command
- **PATCH** - fixes that do not change the interface: bug fixes, docs

**The source of truth for the version is `VERSION` in `<pkg>/constants.py`.**
`pyproject.toml` reads it automatically via `[tool.setuptools.dynamic]` and
`__init__.py` re-exports it as `__version__`. The version never needs to be
duplicated anywhere else.

## Release checklist

1. Make sure the tests and the linter are green:
   ```bash
   python -m pytest
   ruff check .
   ```
2. Update `VERSION` in `<pkg>/constants.py`
3. Add an entry to `CHANGELOG.md` (Keep a Changelog):
   - release date
   - Added / Changed / Fixed / Removed sections
   - version comparison links at the bottom of the file
4. Commit: `git commit -m "Release vX.Y.Z"`
5. Create an annotated tag:
   ```bash
   git tag -a vX.Y.Z -m "<module> X.Y.Z"
   ```
6. Verify that the package builds:
   ```bash
   pip install .
   <module-command> --version
   ```
7. Push together with the tag:
   ```bash
   git push origin master --tags
   ```

## Module synchronisation

The modules are independent and are released separately - there is no need to
synchronise versions. However, when a shared contract changes in a breaking
way (the JSON report format, CLI flags) and the Jealous Moon dashboard relies
on it, update the `modules/conf/<name>.yaml` manifest in the dashboard
repository and mention it in the CHANGELOG.
