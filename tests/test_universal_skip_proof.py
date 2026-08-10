"""One case that skips in every environment, which proves the skip gate on the runner.

**Warning: this file belongs to the proof branch of #524 and it never reaches `dev`.** The
user approved a deliberately red pull request, under the rules #438 followed. The pull
request targets the integration branch of batch #523, it merges into nothing, and it closes
as soon as the run is read.

A gate proved in one direction is a gate that may pass always. #438 records that sentence
and this file is the other direction.
"""

import pytest


def test_the_case_that_skips_in_every_environment() -> None:
    """No job of the matrix runs an assertion of this case, and the gate must name it."""
    pytest.skip("#524 proves the skip gate, and this case reaches no assertion anywhere")
