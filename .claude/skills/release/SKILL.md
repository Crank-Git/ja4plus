---
name: release
description: Cut a ja4plus release to PyPI. Use when asked to release, publish, cut a version, or ship to PyPI.
allowed-tools: Bash, Read, Edit
---

# Release ja4plus

A publish to PyPI cannot be undone. Every check below runs before the publish, not
after.

## Before you start

Confirm all of the following. Stop and report if any is false.

- The work is merged into `master`.
- `pytest tests/` passes, including the conformance suite.
- `ruff check`, `ruff format --check` and `mypy ja4plus/` report nothing.
- `CHANGELOG.md` has a section for the version you are about to publish.

## Steps

1. Set the version. It lives in `pyproject.toml` only. `ja4plus/__init__.py` reads it
   with `importlib.metadata.version`.

2. Confirm the version and the changelog agree.

   ```bash
   python - <<'PY'
   import re, tomllib, pathlib
   v = tomllib.loads(pathlib.Path("pyproject.toml").read_text())["project"]["version"]
   changelog = pathlib.Path("CHANGELOG.md").read_text()
   assert re.search(rf"^## \[{re.escape(v)}\]", changelog, re.M), f"no changelog section for {v}"
   print(f"version {v} has a changelog section")
   PY
   ```

3. Build the package.

   ```bash
   rm -rf dist/ build/
   python -m build
   twine check dist/*
   ```

4. Confirm the wheel holds what it must, and nothing it must not.

   ```bash
   unzip -l dist/*.whl | grep -E "py.typed|ja4plus-mapping.csv"
   unzip -l dist/*.whl | grep -E "tests/|examples/|docs/" && echo "FAIL: wheel holds files it should not"
   ```

5. Verify the wheel in a clean environment. The source tree must not be on the path, so
   an import cannot resolve to the working copy.

   ```bash
   TMP=$(mktemp -d)
   python -m venv "$TMP/venv"
   "$TMP/venv/bin/pip" install --quiet dist/*.whl pytest
   (cd "$TMP" && "$TMP/venv/bin/ja4plus" --version)
   "$TMP/venv/bin/python" -m pytest tests/ -m spec_validation -q
   ```

6. Create the GitHub release. The publish workflow triggers on a published release and
   uses trusted publishing, so no token is needed.

   ```bash
   gh release create "v<version>" --title "v<version>" --notes-file <(python - <<'PY'
   import re, pathlib, tomllib
   v = tomllib.loads(pathlib.Path("pyproject.toml").read_text())["project"]["version"]
   text = pathlib.Path("CHANGELOG.md").read_text()
   m = re.search(rf"^## \[{re.escape(v)}\].*?(?=^## \[|\Z)", text, re.M | re.S)
   print(m.group(0).strip())
   PY
   )
   ```

7. Confirm the publish.

   ```bash
   gh run list --workflow=publish.yml --limit 1
   pip download --no-deps --dest /tmp/ja4check "ja4plus==<version>"
   ```

## Rules

- Never publish when any step above failed. A partial publish cannot be undone.
- Never bump a version and publish in one action without a human confirming the
  changelog.
- Version 1.0.0 states that the interface is stable. A breaking change after it needs
  version 2.0.0.
