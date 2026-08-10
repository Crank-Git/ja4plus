"""A case that skips in every environment, which proves the skip gate refuses one.

**This file lands in no branch.** #541 adds it on a proof branch, reads the run, and closes
the pull request with the branch deleted. Round 197 used the same file and the same case
name to prove the gate the first time.

**A green manual run alone proves nothing.** A repair that turned the gate off would produce
one too. The gate therefore needs the other direction as well: a case that skips on every
job of a pull-request run, which the run must refuse.
"""

import pytest


def test_the_case_that_skips_in_every_environment() -> None:
    """The case skips on every job, so the skip gate names it and fails the run."""
    pytest.skip("the proof of #541: this case skips on every job that selects it")
