"""JA4SSH spec tests for FoxIO PR #281 deterministic tiebreak.

When multiple packet sizes have the same modal frequency, the smallest
value must win.
"""
from ja4plus.fingerprinters.ja4ssh import JA4SSHFingerprinter


def test_mode_tie_picks_lowest_value():
    fp = JA4SSHFingerprinter()
    # 36 and 100 each appear twice; the smaller value (36) must win.
    assert fp._mode([100, 36, 100, 36]) == 36
    # Another arrangement of the same values
    assert fp._mode([36, 100, 36, 100]) == 36
    # 200 and 50 tie at three each; 50 wins
    assert fp._mode([200, 50, 50, 200, 200, 50]) == 50


def test_mode_three_way_tie_picks_lowest():
    fp = JA4SSHFingerprinter()
    # 36, 52, 100 each appear once; lowest (36) wins
    assert fp._mode([100, 52, 36]) == 36


def test_mode_clear_winner_unaffected():
    fp = JA4SSHFingerprinter()
    # 80 appears 3 times, 36 once; 80 wins
    assert fp._mode([80, 80, 36, 80]) == 80


def test_mode_empty_list_returns_zero():
    fp = JA4SSHFingerprinter()
    assert fp._mode([]) == 0


def test_mode_single_value():
    fp = JA4SSHFingerprinter()
    assert fp._mode([42]) == 42
