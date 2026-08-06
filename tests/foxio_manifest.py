"""The manifest of the FoxIO vector set.

`tests/foxio_vector_manifest.json` names every vector the conformance suite expects and
the number of test cases that vector carries. The suite compares the manifest against
what it collected, and it fails when the two differ.

The manifest exists because a missing vector is silent without it. The suite builds its
cases from the files it finds, so a deleted capture removes its cases and the suite
still reports green. A vector that disappears removes coverage, which is the failure
this project must never report as a pass.

The deviation register does not close the same gap. It names only a case that fails
today, so a deleted vector that passes leaves nothing behind to notice.

## How to add a vector

1. Put the capture and its expected-output file under `tests/foxio_vectors/`.
2. Run `python tests/generate_foxio_baseline.py`. It rewrites the manifest and the
   register from the vectors it finds.
3. Read the difference. The manifest gains one line, and the register gains one entry
   for each case the new vector fails.

A vector is a two-file change on purpose. A capture that arrives without a manifest
line, or leaves without one, fails the suite.
"""

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

MANIFEST_PATH = Path(__file__).parent / "foxio_vector_manifest.json"


def load_manifest(path=MANIFEST_PATH):
    """Return the manifest of the vector set.

    Args:
        path: The path of the manifest file. Defaults to the committed manifest.

    Returns:
        A map of vector file name to the number of test cases the vector carries.

    Raises:
        ValueError: The manifest is absent, or an entry holds no case count.
    """
    if not Path(path).exists():
        raise ValueError("the vector manifest is absent from {}".format(path))
    with open(path) as handle:
        entries = json.load(handle)
    manifest = {}
    for vector, count in entries.items():
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise ValueError("vector {}: the entry holds no case count".format(vector))
        manifest[vector] = count
    return manifest


def compare(manifest, collected):
    """Return the lines that describe every difference between the two counts.

    Args:
        manifest: The map the manifest file holds.
        collected: A map of vector file name to the number of cases the suite collected.

    Returns:
        A sorted list of one line for each difference. The list is empty when the two
        maps agree.
    """
    differences = []
    for vector in sorted(set(manifest) - set(collected)):
        differences.append(
            "{} is absent from tests/foxio_vectors, and it carries {} case(s)".format(
                vector, manifest[vector]
            )
        )
    for vector in sorted(set(collected) - set(manifest)):
        differences.append("{} is not in the manifest".format(vector))
    for vector in sorted(set(manifest) & set(collected)):
        if manifest[vector] != collected[vector]:
            differences.append(
                "{} carries {} case(s), and the manifest expects {}".format(
                    vector, collected[vector], manifest[vector]
                )
            )
    return differences
