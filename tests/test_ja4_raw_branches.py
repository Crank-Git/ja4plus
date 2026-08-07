"""`ja4plus/fingerprinters/ja4.py` holds no branch whose two arms build the same string.

`docs/specs/features/02-correctness-audit.md` row 10 records the defect. A branch whose
two arms produce one value tells a reader that the two orders differ where they do not,
and a later change to one arm alone moves a fingerprint without a vector.

The test reads the source with `ast`, because the defect is invisible at run time. A
dead branch produces the same value as the live branch, so no call can detect it.
"""

import ast
from pathlib import Path

SOURCE = Path(__file__).parents[1] / "ja4plus" / "fingerprinters" / "ja4.py"


def identical_arm_branches(source_text):
    """Return the line number of every `if` whose body and `else` hold the same code.

    Args:
        source_text: The text of one Python module.

    Returns:
        A list of (line, code) pairs. An empty list means no branch has identical arms.
    """
    found = []
    for node in ast.walk(ast.parse(source_text)):
        if not isinstance(node, ast.If) or not node.orelse:
            continue
        if any(isinstance(arm, ast.If) for arm in node.orelse):
            # An `elif` reads as an `If` inside `orelse`. It is a chain, not two arms.
            continue
        body = "\n".join(ast.dump(statement) for statement in node.body)
        orelse = "\n".join(ast.dump(statement) for statement in node.orelse)
        if body == orelse:
            found.append((node.lineno, ast.unparse(node.body[0])))
    return found


def test_no_branch_of_the_ja4_module_builds_one_string_in_both_arms():
    """No `if` statement of `ja4.py` holds two arms that build the same value."""
    found = identical_arm_branches(SOURCE.read_text())
    assert found == [], f"a branch of ja4.py has identical arms: {found}"


def test_the_cipher_order_branch_and_the_extension_order_branch_stay():
    """The cipher branch and the extension branch build two different strings.

    `original_order` selects the wire order, and the `else` arm selects the sorted
    order. FoxIO publishes `JA4_r` and `JA4_o` as two values, and #132 settled the
    reading. A test guards the two branches against removal beside the dead branch.
    """
    from ja4plus.fingerprinters.ja4 import get_raw_fingerprint

    tls_info = {
        "type": "client_hello",
        "version": 0x0303,
        "sni": "example.com",
        "ciphers": [0x1302, 0x1301],
        "extensions": [0x0010, 0x0000, 0x002B],
        "signature_algorithms": [0x0403],
        "alpn_protocols": ["h2"],
    }
    wire_order = get_raw_fingerprint(tls_info, original_order=True)
    sorted_order = get_raw_fingerprint(tls_info, original_order=False)
    assert wire_order is not None
    assert sorted_order is not None
    assert wire_order != sorted_order, "the wire order and the sorted order must differ"
    assert "1302,1301" in wire_order, f"the wire order lost the cipher order: {wire_order}"
    assert "1301,1302" in sorted_order, f"the sorted order lost the sort: {sorted_order}"
