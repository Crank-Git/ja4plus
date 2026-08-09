# JA4TS

JA4TS fingerprints the TCP server. It reads one SYN-ACK packet and it emits one
fingerprint. It appends the retransmission timing when the server answers more than
once.

**JA4TS reads a SYN-ACK packet and never a SYN packet.**
[JA4T](ja4t.md) reads the SYN packet.

## The facts

| Item | Value |
|---|---|
| The `--types` token | `ja4ts` |
| The fingerprinter class | `JA4TSFingerprinter` |
| The one-shot function | `generate_ja4ts` |
| The `raw` field | Always `null` |
| The `raw_original_order` field | Always `null` |
| The hash rule | None. The method hashes no part. |
| The FoxIO source | `technical_details/JA4T.png` |

## The output format

```
<window size>_<option kinds>_<mss>_<window scale>
<window size>_<option kinds>_<mss>_<window scale>_<delays>
```

`ja4plus/utils/tcp_options.py:139` builds the first four parts, and
`ja4plus/fingerprinters/ja4ts.py:353` appends the fifth.

## The parts

| Part | What it holds |
|---|---|
| Window size | The TCP window size of the SYN-ACK packet, as a decimal number. |
| Option kinds | The kind number of each TCP option, in wire order, joined with a hyphen. It is `00` when the packet carries no option. |
| MSS | The maximum segment size the packet advertises, as at least two digits. It is `00` when the packet carries no MSS option. |
| Window scale | The window scale the packet advertises. It is `00` when the scale is zero. |
| Delays | The count of seconds between the first SYN-ACK packet and each retransmission, joined with a hyphen. |

**The fifth part is absent when the server answers once.** A server that retransmitted
five times, at 1, 2, 4, 8 and 16 seconds, writes the suffix `_1-2-4-8-16`.
`ja4plus/fingerprinters/ja4ts.py:280` holds the rule.

**A reset appends the marker `R` and the delay of the RST packet.**
`ja4plus/fingerprinters/ja4ts.py:189` builds that form.

## The hash rule

JA4TS hashes no part. Every part of the value is a number or a list of numbers.

## The raw forms

JA4TS writes no raw form. Both raw fields of the output line are `null`.

## An example

| Capture | Value |
|---|---|
| `tests/foxio_vectors/https-connect.pcap` | `29200_2-1-1-4-1-3_1360_7` |

`tests/test_method_pages.py` reads this table, runs the capture and compares the value
against what the processor emits.

The value reads a server whose SYN-ACK packet advertises the window size 29200, six TCP
options, the maximum segment size 1360 and the window scale 7. The server answered once,
so the value carries no fifth part.

## The FoxIO source

**No FoxIO file carries the name JA4TS.** `technical_details/JA4T.png` titles itself
`JA4T/S: TCP Fingerprint`, so it specifies JA4TS as well as JA4T. #196 records the
reading, and it is the half of the open question that the evidence confirmed.

`docs/specs/foxio/JA4T.md` holds this project's transcription of the image, and it covers
the two methods. `docs/specs/foxio/README.md` holds the inventory and the SHA-256 of each
file.

Verified against: https://github.com/FoxIO-LLC/ja4/tree/main/technical_details (retrieved
2026-08-08, commit `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`)

## Where to read more

- [The usage guide](../usage.md#ja4ts---tcp-server) holds a code sample.
- [JA4T](ja4t.md) describes the client value.
- [The method index](index.md) names every method.
