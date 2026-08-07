"""The malformed-input suite.

Every packet is hostile input. `FR-correctness-audit-8` to `FR-correctness-audit-10`
state the contract this suite measures. A parser that cannot read a packet returns
nothing, and it does not raise.
"""
