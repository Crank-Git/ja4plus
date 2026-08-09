# JA4T

JA4T fingerprints the TCP client. It reads one SYN packet and it emits one fingerprint.

**JA4T reads a SYN packet and never a SYN-ACK packet.**
[JA4TS](ja4ts.md) reads the SYN-ACK packet.

## The facts

| Item | Value |
|---|---|
| The `--types` token | `ja4t` |
| The fingerprinter class | `JA4TFingerprinter` |
| The one-shot function | `generate_ja4t` |
| The `raw` field | Always `null` |
| The `raw_original_order` field | Always `null` |
| The hash rule | None. The method hashes no part. |
| The FoxIO source | `technical_details/JA4T.png` |

## The output format

```
<window size>_<option kinds>_<mss>_<window scale>
```

`ja4plus/utils/tcp_options.py:139` builds the four parts, and JA4T and JA4TS share that
function.

## The parts

| Part | What it holds |
|---|---|
| Window size | The TCP window size of the SYN packet, as a decimal number. |
| Option kinds | The kind number of each TCP option, in wire order, joined with a hyphen. It is `00` when the packet carries no option. |
| MSS | The maximum segment size the packet advertises, as at least two digits. It is `00` when the packet carries no MSS option. |
| Window scale | The window scale the packet advertises. It is `00` when the scale is zero, and one digit or more otherwise. |

**The option list holds every option kind and not the six kinds a name list holds.** #215
records the reading as D3.

**The two-digit form is a decision, and it covers three cases.** An empty option list
writes `00`, the MSS part writes two digits, and a window scale of zero writes `00`. A
window scale above zero writes its own digits and no padding, which is why the example
below ends in `7` and not `07`.

The Wireshark dissector and the Zeek script both write that form, and the FoxIO Rust
implementation writes one digit. #215 records the decision as D1, and the
`Divergence register` of `docs/specs/spec.md` records the cost.

## The hash rule

JA4T hashes no part. Every part of the value is a number or a list of numbers.

## The raw forms

JA4T writes no raw form. Both raw fields of the output line are `null`.

## An example

| Capture | Value |
|---|---|
| `tests/foxio_vectors/https-connect.pcap` | `29200_2-1-1-4-1-3_1460_7` |

`tests/test_method_pages.py` reads this table, runs the capture and compares the value
against what the processor emits.

The value reads a client whose SYN packet advertises the window size 29200, six TCP
options, the maximum segment size 1460 and the window scale 7.

## The FoxIO source

`technical_details/JA4T.png` publishes JA4T as a diagram. It titles itself
`JA4T/S: TCP Fingerprint`, so it specifies JA4TS as well. #196 records the reading.

FoxIO published a text file for this method and then deleted it, so the image is the
pinned specification. `docs/specs/foxio/JA4T.md` holds this project's transcription, and
`docs/specs/foxio/README.md` holds the inventory and the SHA-256 of each file.

Verified against: https://github.com/FoxIO-LLC/ja4/tree/main/technical_details (retrieved
2026-08-08, commit `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`)

## Where to read more

- [The usage guide](../usage.md#ja4t---tcp-client) holds a code sample.
- [JA4TS](ja4ts.md) describes the server value.
- [The method index](index.md) names every method.
