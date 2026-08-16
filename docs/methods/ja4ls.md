# JA4LS

JA4LS reports the one-way latency from the server to the client. It reads the TCP
handshake, or the QUIC Initial packet and Handshake packet, and it emits one fingerprint
for each connection.

**JA4LS and [JA4L](ja4l.md) are two methods, and one fingerprinter writes both.** The
output line of a JA4LS value carries the type `ja4l`, because one fingerprinter reports
one type. Read the `JA4L-S=` prefix of the value to tell the two apart.

**The `--types` option holds one token for each of the two methods.** `--types ja4ls`
writes the JA4LS values alone. `--types ja4l` writes the JA4L values and the JA4LS values
together, which is the behaviour of version 1.1.1. #605 added the `ja4ls` token under
parity rule 2, and the Go port shipped it first.

## The facts

| Item | Value |
|---|---|
| The `--types` token | `ja4ls` |
| The fingerprinter class | `JA4LFingerprinter` |
| The one-shot function | `generate_ja4l` |
| The `raw` field | Always `null` |
| The `raw_original_order` field | Always `null` |
| The hash rule | None. The method hashes no part. |
| The FoxIO source | `technical_details/README.md` |

## The output format

```
JA4L-S=<latency>_<ttl>
JA4L-S=<latency>_<ttl>_quic
```

`ja4plus/fingerprinters/ja4l.py:446` builds the TCP form, and
`ja4plus/fingerprinters/ja4l.py:620` builds the QUIC form.

## The parts

| Part | What it holds |
|---|---|
| `JA4L-S=` | The literal prefix that names the server value. |
| Latency | The one-way latency from the server to the client, in microseconds. |
| TTL | The IP time-to-live value of the server packet, or the hop limit for IPv6. |
| `quic` | The marker a QUIC connection appends. A TCP connection appends nothing. |

## The measurement points

The fingerprinter reads the interval between the client SYN packet and the server
SYN-ACK packet. It halves that interval and truncates the result, so the value reports a
one-way latency.

## The hash rule

JA4LS hashes no part. Every part of the value is a number or a literal.

## The raw forms

JA4LS writes no raw form. Both raw fields of the output line are `null`.

## An example

| Capture | Value |
|---|---|
| `tests/foxio_vectors/https-connect.pcap` | `JA4L-S=13532_57` |

`tests/test_method_pages.py` reads this table, runs the capture and compares the value
against what the processor emits.

The value reports 13532 microseconds of one-way latency, from a server whose packet
carries the TTL 57.

## The FoxIO source

**No FoxIO image publishes JA4LS.** `technical_details/README.md` lists JA4LS as a row of
its own, and the directory holds no `JA4LS.png`. #200 read `JA4L.png` and refuted the
assumption that it carries a server form: the image titles itself
`JA4L: Light Distance/Location Fingerprint` and it states no server rule.

The FoxIO reference implementations therefore state every rule JA4LS follows.
`docs/specs/foxio/JA4L.md` holds the reading and names the two sources that name JA4LS as
a separate method. `docs/specs/foxio/README.md` holds the inventory and the SHA-256 of
each file.

**Warning: read no JA4LS value of a FoxIO Zeek baseline as a reference value.** Three
rules of the Zeek script part it from the FoxIO Python reference.
`.claude/rules/external-apis.md` states the bar, and it records that the same reasoning
reaches the Wireshark dissector.

Verified against: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/README.md
(retrieved 2026-08-08, commit `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`)

## Where to read more

- [The usage guide](../usage.md#ja4l---latency) holds a code sample.
- [JA4L](ja4l.md) describes the client value the same fingerprinter writes.
- [The method index](index.md) names every method.
