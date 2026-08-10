# The methods

FoxIO publishes twelve JA4+ methods. This project implements eleven of them.

Each page below describes one method. It states the output format, the parts of the
value, the hash rule, and the FoxIO file that publishes the method. It also names one
committed capture and the value that capture produces.

FoxIO owns the JA4+ standard. This project is an independent implementation of it. For
the standard itself, read the
[FoxIO JA4+ repository](https://github.com/FoxIO-LLC/ja4).

## The methods

| Method | Protocol | Page | Implemented |
|---|---|---|---|
| JA4 | TLS and QUIC | [The TLS client fingerprint](ja4.md) | Yes |
| JA4S | TLS and QUIC | [The TLS server fingerprint](ja4s.md) | Yes |
| JA4H | HTTP | [The HTTP client fingerprint](ja4h.md) | Yes |
| JA4L | TCP and QUIC | [The client latency fingerprint](ja4l.md) | Yes |
| JA4LS | TCP and QUIC | [The server latency fingerprint](ja4ls.md) | Yes |
| JA4X | X.509 | [The certificate fingerprint](ja4x.md) | Yes |
| JA4SSH | SSH | [The SSH session fingerprint](ja4ssh.md) | Yes |
| JA4T | TCP | [The TCP client fingerprint](ja4t.md) | Yes |
| JA4TS | TCP | [The TCP server fingerprint](ja4ts.md) | Yes |
| JA4TScan | TCP | No page. Read the decline below. | No |
| JA4D | DHCPv4 | [The DHCPv4 fingerprint](ja4d.md) | Yes |
| JA4D6 | DHCPv6 | [The DHCPv6 fingerprint](ja4d6.md) | Yes |

## Why eleven methods reach ten fingerprinter classes

`JA4LFingerprinter` writes two methods. It emits a `JA4L-C=` value for the client
latency and a `JA4L-S=` value for the server latency. The `--types` option therefore
accepts ten tokens, and `ja4l` names both JA4L and JA4LS.

**Read the ten as a count of fingerprinter classes, and never as a count of methods.**
#387 records the three documents that made that mistake.

## Why this project builds no JA4TScan

**This project declines JA4TScan by ruling, and the absence is no omission.** JA4TScan
sends crafted packets to a host the operator names, and it reads the responses. Every
other method reads traffic that already exists, so JA4TScan reaches a network the
operator did not capture. That capability is larger than fingerprint production.

`docs/specs/spec.md` holds the ruling under `Non-goals`, and #197 holds the reading.
The ruling is reversible.

## What a fingerprint is evidence of

**A fingerprint is evidence of the bytes the packet carried. It is no evidence of a real
client.** `ja4plus` adds no plausibility guard, so any sender can build bytes that
produce a well formed fingerprint. Read
[What a fingerprint is evidence of](../output-schema.md#what-a-fingerprint-is-evidence-of)
before you trust an output line that untrusted traffic produced.

## Where to read more

- [The usage guide](../usage.md) holds a code sample for each method.
- [The output schema](../output-schema.md) states the shape of each output line.
- [The implementation notes](../implementation_notes.md) record every divergence from
  the FoxIO reference.
