"""Tests that the publish workflow deploys the documentation site to GitHub Pages.

`FR-documentation-8` asks the site to publish to GitHub Pages on a push to the live branch.
The live branch is `master` under the dev-and-live branch model.

**No case here observes a deployment.** This repository holds no GitHub Pages site, and
`gh api repos/Crank-Git/ja4plus` reports `has_pages: false`. The user decides whether to
turn Pages on, because that change publishes a public website. These cases therefore read
the workflow as text, and the deployment stays unverified until the user changes the
setting.
The issue body states the behaviour the workflow must have until then: the run fails with a
message that names the setting.

**The publish workflow builds nothing of its own.** `.github/workflows/docs-build.yml`
already installs the committed pins into an empty environment and runs
`mkdocs build --strict`. A publish job that rebuilds the site with a second recipe is a
second source of truth, and the two drift apart in silence. The publish workflow calls the
build workflow instead, and `docs-build.yml` uploads the site as the Pages artifact when
the caller asks for it.

These cases read configuration. They import nothing from `ja4plus` and they produce no
fingerprint.
"""

from pathlib import Path
import re

REPO_ROOT = Path(__file__).resolve().parent.parent

WORKFLOWS = REPO_ROOT / ".github" / "workflows"
PUBLISH_WORKFLOW = WORKFLOWS / "docs.yml"
BUILD_WORKFLOW = WORKFLOWS / "docs-build.yml"

# The live branch of the dev-and-live model. `CLAUDE.md` states it, and a promotion from
# `dev` to `master` is a separate step the user approves.
LIVE_BRANCH = "master"

# The path the publish workflow calls. A relative path names a workflow of this repository.
BUILD_REFERENCE = "uses: ./.github/workflows/docs-build.yml"

# An action reference, as `uses: actions/deploy-pages@d6db901...  # v4.0.5`. Every workflow
# of this repository pins a third-party action to a commit, because a tag moves.
ACTION_REFERENCE = re.compile(r"uses:\s+([A-Za-z0-9][^\s@]*)@(\S+)")

COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")


def _publish_text() -> str:
    """Return the text of the publish workflow.

    Returns:
        The whole file text.

    Raises:
        AssertionError: The repository holds no publish workflow.
    """
    assert PUBLISH_WORKFLOW.is_file(), f"{PUBLISH_WORKFLOW} holds no publish workflow"
    return PUBLISH_WORKFLOW.read_text(encoding="utf-8")


def _trigger_block(text: str, trigger: str) -> str:
    """Return the block of one trigger of a workflow.

    Args:
        text: The workflow text.
        trigger: The trigger name with its colon, as `push:`.

    Returns:
        The text from the trigger line to the next trigger or to the job list.

    Raises:
        AssertionError: The workflow carries no such trigger.
    """
    start = text.find(f"\n  {trigger}\n")
    assert start != -1, f"{PUBLISH_WORKFLOW.name} carries no {trigger} trigger"
    boundaries = ("\n  pull_request:", "\n  workflow_dispatch:", "\n  workflow_call:", "\njobs:")
    after = [text.find(boundary, start + 1) for boundary in boundaries]
    return text[start : min(position for position in after if position != -1)]


def test_the_publish_workflow_fires_on_a_push_to_the_live_branch() -> None:
    """The publish workflow triggers on a push to `master` and on no push to `dev`.

    `dev` is the integration branch, and a promotion to `master` is the release step. A
    workflow that published from `dev` would publish work the user has not approved.
    """
    block = _trigger_block(_publish_text(), "push:")
    assert LIVE_BRANCH in block, f"the push trigger names no {LIVE_BRANCH} branch"
    assert "dev" not in block, "the push trigger names the integration branch"


def test_the_publish_workflow_holds_the_permissions_the_deployment_needs() -> None:
    """The workflow grants `pages: write` and `id-token: write` to the deployment.

    `actions/deploy-pages` states both permissions and the `github-pages` environment.
    Verified against https://github.com/actions/deploy-pages (v4), retrieved 2026-08-09.
    """
    text = _publish_text()
    for permission in ("pages: write", "id-token: write"):
        assert permission in text, f"{PUBLISH_WORKFLOW.name} grants no {permission}"
    assert "github-pages" in text, f"{PUBLISH_WORKFLOW.name} names no github-pages environment"


def test_the_publish_workflow_reports_the_setting_when_pages_is_off() -> None:
    """A run against a repository without Pages fails with a message that names the setting.

    A red run that reports `404` alone tells a reader nothing to change. The message names
    the page of the settings, the field, and the value the workflow needs.
    """
    text = _publish_text()
    assert "::error::" in text, f"{PUBLISH_WORKFLOW.name} writes no workflow error annotation"
    for word in ("Settings", "Pages", "Build and deployment", "Source", "GitHub Actions"):
        assert word in text, f"the failure message of {PUBLISH_WORKFLOW.name} names no {word!r}"


def test_the_publish_workflow_reuses_the_build_of_the_documentation_job() -> None:
    """The publish workflow calls `docs-build.yml` and runs no build of its own.

    Two recipes for one site drift apart, and the drift shows up as a published page that
    no check ever built. The build job owns the pins and the strict build, and #391 owns
    that job.
    """
    assert BUILD_REFERENCE in _publish_text(), (
        f"{PUBLISH_WORKFLOW.name} calls no {BUILD_WORKFLOW.name}"
    )
    # A comment of the workflow names the build command to say why the job reuses it, so
    # this case reads the steps and not the comments.
    steps = "\n".join(
        line for line in _publish_text().splitlines() if not line.lstrip().startswith("#")
    )
    assert "mkdocs build" not in steps, f"{PUBLISH_WORKFLOW.name} builds the site a second time"
    assert "pip install" not in steps, f"{PUBLISH_WORKFLOW.name} resolves the pins a second time"


def test_the_build_workflow_uploads_the_site_as_the_pages_artifact() -> None:
    """`docs-build.yml` accepts a call and uploads the site as the Pages artifact.

    A called workflow runs inside the run of its caller, so the deployment job of the caller
    reads the artifact this step writes.
    """
    text = BUILD_WORKFLOW.read_text(encoding="utf-8")
    assert "workflow_call:" in text, f"{BUILD_WORKFLOW.name} answers no call"
    assert "upload-pages-artifact" in text, f"{BUILD_WORKFLOW.name} uploads no Pages artifact"
    assert "path: site" in text, f"{BUILD_WORKFLOW.name} uploads some other directory than `site`"


def test_the_build_workflow_uploads_no_artifact_for_a_pull_request() -> None:
    """The upload step runs only where the caller asks for it.

    A pull request builds the site to prove the pins, and it publishes nothing. The input
    is absent on a `push` trigger and on a `pull_request` trigger, so the condition reads
    false there.
    """
    text = BUILD_WORKFLOW.read_text(encoding="utf-8")
    assert "upload_pages_artifact" in text, f"{BUILD_WORKFLOW.name} states no upload input"
    assert "if: ${{ inputs.upload_pages_artifact }}" in text, (
        f"the upload step of {BUILD_WORKFLOW.name} runs on every trigger"
    )


def test_every_action_of_the_publish_workflow_pins_a_commit() -> None:
    """A third-party action of the publish workflow names a 40-character commit.

    A tag moves, and a moved tag runs code that nobody reviewed. Every other workflow of
    this repository pins a commit and writes the version in a comment.
    """
    floating = [
        f"{name}@{reference}"
        for name, reference in ACTION_REFERENCE.findall(_publish_text())
        if not COMMIT_SHA.match(reference)
    ]
    assert floating == [], f"these actions of {PUBLISH_WORKFLOW.name} name no commit: {floating}"
