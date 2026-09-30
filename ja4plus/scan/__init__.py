"""JA4TScan, the one JA4+ method that sends packets.

The scanner sends one TCP SYN to each target and reads the SYN-ACK and every
retransmission of it. `docs/specs/features/12-active-scan.md` states the feature, and
`docs/specs/foxio/JA4TScan.md` transcribes the FoxIO scanner.

**This package is the one place in `ja4plus` that sends a packet.** No module outside it
imports it, and `import ja4plus` loads none of it. The `ja4plus scan` subcommand reaches
it through the `ja4plus.commands` entry point, so the passive path cannot reach a sender.
The maintainer ruled that boundary on 2026-09-30, in #775.
"""
