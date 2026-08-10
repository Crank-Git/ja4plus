"""Tests that a mutation of a module body keeps a body reader in the cover rule.

`.claude/rules/conformance.md` states the cover procedure. Step 2 of that procedure
subtracts the lines the import runs. A mutation of a module body then keeps no case that
reads it, and the cost rule holds the cheapest test file. #414 measured the result on
`ja4plus/__init__.py`: the cover the cost rule builds is `tests/test_parity.py`, and the
sweep reads 1 killed and 31 survived.

`tests/mutation_cover.py` names the body reader of that module. It reads the names the
module body binds and the identifier strings those statements build, and it names the
test file whose own source holds the most of them.

These cases read no packet and they produce no fingerprint.
"""

from __future__ import annotations

from pathlib import Path

from tests import mutation_cover

REPO_ROOT = Path(__file__).resolve().parent.parent
RULE = REPO_ROOT / ".claude" / "rules" / "conformance.md"


class TestTheTokensOfOneModuleBody:
    def test_the_token_set_holds_the_name_the_module_body_binds(self) -> None:
        found = mutation_cover.body_tokens(REPO_ROOT / "ja4plus" / "__init__.py")
        assert "__all__" in found
        assert "__version__" in found

    def test_the_token_set_holds_each_entry_of_the_public_interface_list(self) -> None:
        found = mutation_cover.body_tokens(REPO_ROOT / "ja4plus" / "__init__.py")
        assert "JA4Fingerprinter" in found
        assert "generate_ja4" in found
        assert "compute_ja4x_from_pem" in found

    def test_the_token_set_drops_a_name_that_a_function_body_binds(self, tmp_path: Path) -> None:
        # A name inside a function is not a module-body value, and the import runs no
        # line of it. A token set that holds it names a reader of the wrong line class.
        module = tmp_path / "one.py"
        module.write_text(
            'TOP = ["kept"]\n\n\ndef read():\n    inner = ["dropped"]\n    return inner\n'
        )
        found = mutation_cover.body_tokens(module)
        assert "TOP" in found
        assert "kept" in found
        assert "inner" not in found
        assert "dropped" not in found

    def test_the_token_set_holds_the_names_of_a_tuple_target(self, tmp_path: Path) -> None:
        module = tmp_path / "four.py"
        module.write_text('FIRST, SECOND = "one", "two"\n*REST, LAST = [1, 2, 3]\n')
        found = mutation_cover.body_tokens(module)
        assert "FIRST" in found
        assert "SECOND" in found
        assert "REST" in found
        assert "LAST" in found

    def test_the_token_set_holds_a_name_an_import_guard_binds(self, tmp_path: Path) -> None:
        # The import runs the body of an `if` block and the body of a `try` block, so an
        # assignment there is a module-body assignment.
        module = tmp_path / "five.py"
        module.write_text(
            "import sys\n\nif sys.version_info >= (3, 10):\n"
            '    GUARDED = "new_value"\nelse:\n    GUARDED = "old_value"\n'
            "\ntry:\n    IMPORTED = 1\nexcept ImportError:\n    IMPORTED = 0\n"
        )
        found = mutation_cover.body_tokens(module)
        assert "GUARDED" in found
        assert "new_value" in found
        assert "old_value" in found
        assert "IMPORTED" in found

    def test_the_token_set_drops_a_name_a_class_body_binds(self, tmp_path: Path) -> None:
        module = tmp_path / "six.py"
        module.write_text('TOP = 1\n\n\nclass One:\n    attribute = "dropped_value"\n')
        found = mutation_cover.body_tokens(module)
        assert "TOP" in found
        assert "attribute" not in found
        assert "dropped_value" not in found

    def test_the_token_set_of_a_module_body_that_binds_nothing_is_empty(
        self, tmp_path: Path
    ) -> None:
        module = tmp_path / "two.py"
        module.write_text(
            '"""One module that binds no module-level name."""\n\n\ndef read():\n    return 1\n'
        )
        assert mutation_cover.body_tokens(module) == []


class TestTheReaderOfOneModuleBody:
    def test_the_reader_of_the_package_module_is_the_public_interface_case_file(self) -> None:
        found = mutation_cover.body_reader(REPO_ROOT, Path("ja4plus/__init__.py"))
        assert found == "tests/test_public_interface.py"

    def test_the_body_reader_names_more_tokens_than_the_cost_rule_file(self) -> None:
        # #414 built the cover of this module from cost alone and reached
        # tests/test_parity.py, which kills 1 of the 32 mutations.
        ranked = dict(mutation_cover.body_readers(REPO_ROOT, Path("ja4plus/__init__.py")))
        assert ranked["tests/test_public_interface.py"] > ranked.get("tests/test_parity.py", 0)

    def test_every_ranked_reader_names_one_token_or_more(self) -> None:
        # An aggregate over an empty set passes, so this case reads the floor as well as
        # the counts.
        ranked = mutation_cover.body_readers(REPO_ROOT, Path("ja4plus/__init__.py"))
        assert len(ranked) > 1
        assert all(count > 0 for _, count in ranked)

    def test_the_ranked_readers_fall_from_the_greatest_count(self) -> None:
        counts = [
            count for _, count in mutation_cover.body_readers(REPO_ROOT, Path("ja4plus/cli.py"))
        ]
        assert counts == sorted(counts, reverse=True)

    def test_a_module_body_that_no_test_file_reads_names_no_reader(self, tmp_path: Path) -> None:
        module = tmp_path / "three.py"
        # The two halves join at run time, so no source file names the token. This case
        # then reads the empty answer rather than naming its own file.
        module.write_text("UNREAD" + "_TOKEN_OF_433 = 1\n")
        assert mutation_cover.body_reader(REPO_ROOT, module) is None


class TestTheCoverRuleText:
    def test_the_rule_states_a_reader_for_a_module_body(self) -> None:
        assert mutation_cover.states_the_body_reader_rule(RULE.read_text())

    def test_the_prover_refuses_the_rule_that_holds_no_such_step(self) -> None:
        # A check that the deleted sentence still passes is not a check.
        text = RULE.read_text()
        kept = [line for line in text.splitlines() if "mutation_cover.py" not in line]
        assert not mutation_cover.states_the_body_reader_rule("\n".join(kept))

    def test_the_prover_reads_a_step_that_a_writer_rewords(self) -> None:
        # A check a rewording defeats is not a check either.
        reworded = (
            "## How to scope one sweep: the minimal cover\n"
            "\n"
            "4. Name the reader of the module body. `tests/mutation_cover.py` reports the\n"
            "   test file that holds the most of those values.\n"
        )
        assert mutation_cover.states_the_body_reader_rule(reworded)

    def test_the_rule_states_the_measured_cost_of_the_reader(self) -> None:
        assert mutation_cover.states_the_reader_cost(RULE.read_text())

    def test_the_cost_prover_reads_a_sentence_that_wraps_across_two_lines(self) -> None:
        # The rule file wraps at 90 columns, so a rewrap moves the cost away from the file
        # name. A prover that read one line failed on this exact rewrap.
        wrapped = (
            "## How to scope one sweep: the minimal cover\n"
            "\n"
            "Step 4 adds the reader `tests/test_public_interface.py`, and one sweep against\n"
            "that file alone costs 39.9 seconds.\n"
        )
        assert mutation_cover.states_the_reader_cost(wrapped)

    def test_the_prover_refuses_the_rule_that_states_no_measured_cost(self) -> None:
        text = RULE.read_text()
        kept = [line for line in text.splitlines() if "seconds" not in line]
        assert not mutation_cover.states_the_reader_cost("\n".join(kept))
