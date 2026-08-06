---
name: test
description: Run the ja4plus test suites and report what failed. Use when asked to test, verify a change, check coverage, or confirm the suite is green before a pull request.
allowed-tools: Bash, Read
---

# Test ja4plus

## Which suite to run

| You changed | Run |
|---|---|
| Anything under `ja4plus/fingerprinters/` or `ja4plus/utils/` | Every suite below, including conformance. |
| `ja4plus/cli.py` or `ja4plus/output.py` | The unit suite and the command-line tests. |
| A docstring, a Markdown file, or an example | The unit suite and the documentation suite. |
| Packaging or a workflow | The unit suite and the packaging suite. |

## Steps

1. Confirm the environment has the dependencies.

   ```bash
   python -c "import scapy, cryptography" 2>/dev/null || pip install -e ".[dev]"
   ```

2. Run the unit suite.

   ```bash
   python -m pytest tests/ -m "not spec_validation" -q
   ```

3. Run the conformance suite. If it reports that vectors are missing, read
   `docs/specs/features/00-foundation.md` before you download anything. The vectors are
   committed, and a missing file is a problem to report, not to work around.

   ```bash
   python -m pytest tests/ -m spec_validation -q
   ```

4. Run the lint and the type check.

   ```bash
   ruff check ja4plus/ tests/
   ruff format --check ja4plus/ tests/
   mypy ja4plus/
   ```

5. Measure coverage when you are preparing a pull request.

   ```bash
   python -m pytest tests/ --cov=ja4plus --cov-report=term-missing -q
   ```

## Rules

- Use `sys.executable` in any test that starts a Python subprocess. A bare `python` is
  absent in many virtual environments.
- A conformance failure names the vector, the stream, the method, the expected value and
  the produced value. Report all five. Do not summarize it as "conformance failed".
- A skipped conformance test is not a pass. Report the skip count with the pass count.
- Report the real numbers. If a test fails, quote the failure output.
