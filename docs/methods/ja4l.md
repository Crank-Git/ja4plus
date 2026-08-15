# JA4L

JA4L reports the one-way latency from the client to the server. It reads the TCP
handshake, or the QUIC Initial packet and Handshake packet, and it emits one fingerprint
for each connection.

**JA4L and [JA4LS](ja4ls.md) are two methods, and one fingerprinter writes both.**
`--types ja4l` writes the values of both methods. `--types ja4ls` writes the JA4LS values
alone, and this project holds no token that writes the JA4L values alone.

## The facts

| Item | Value |
|---|---|
| The `--types` token | `ja4l` |
| The fingerprinter class | `JA4LFingerprinter` |
| The one-shot function | `generate_ja4l` |
| The `raw` field | Always `null` |
| The `raw_original_order` field | Always `null` |
| The hash rule | None. The method hashes no part. |
| The FoxIO source | `technical_details/JA4L.png` |

## The output format

```
JA4L-C=<latency>_<ttl>
JA4L-C=<latency>_<ttl>_quic
```

`ja4plus/fingerprinters/ja4l.py:482` builds the TCP form, and
`ja4plus/fingerprinters/ja4l.py:599` builds the QUIC form.

## The parts

| Part | What it holds |
|---|---|
| `JA4L-C=` | The literal prefix that names the client value. |
| Latency | The one-way latency from the client to the server, in microseconds. |
| TTL | The IP time-to-live value of the client packet, or the hop limit for IPv6. |
| `quic` | The marker a QUIC connection appends. A TCP connection appends nothing. |

**The value reports a one-way latency and not a round-trip time.** #88 records the
correction. The fingerprinter halves the measured interval and truncates the result.

## The measurement points

The fingerprinter reads the interval between the SYN-ACK packet and the first client
packet that carries `seq=1` and `ack=1`. A bare ACK is not that packet. #88 records the
reading.

A QUIC connection uses the client Initial packet and the server Handshake packet
instead.

## The hash rule

JA4L hashes no part. Every part of the value is a number or a literal.

## The raw forms

JA4L writes no raw form. Both raw fields of the output line are `null`.

## An example

| Capture | Value |
|---|---|
| `tests/foxio_vectors/https-connect.pcap` | `JA4L-C=45_64` |

`tests/test_method_pages.py` reads this table, runs the capture and compares the value
against what the processor emits.

The value reports 45 microseconds of one-way latency, from a client whose packet carries
the TTL 64.

## The FoxIO source

`technical_details/JA4L.png` publishes JA4L as a diagram. It titles itself
`JA4L: Light Distance/Location Fingerprint`, it labels its one example `JA4L=`, and it
states no server rule.

`docs/specs/foxio/JA4L.md` holds this project's transcription of the image, and #200
records the reading. `docs/specs/foxio/README.md` holds the inventory and the SHA-256 of
each file.

**Warning: read no JA4L value of a FoxIO Zeek baseline as a reference value.** Three
rules of the Zeek script part it from the FoxIO Python reference.
`.claude/rules/external-apis.md` states the bar.

Verified against: https://github.com/FoxIO-LLC/ja4/tree/main/technical_details (retrieved
2026-08-08, commit `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`)

## Where to read more

- [The usage guide](../usage.md#ja4l---latency) holds a code sample.
- [JA4LS](ja4ls.md) describes the server value the same fingerprinter writes.
- [The method index](index.md) names every method.
