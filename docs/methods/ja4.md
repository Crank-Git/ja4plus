# JA4

JA4 fingerprints the TLS client. It reads one ClientHello message and it emits one
fingerprint.

## The facts

| Item | Value |
|---|---|
| The `--types` token | `ja4` |
| The fingerprinter class | `JA4Fingerprinter` |
| The one-shot function | `generate_ja4` |
| The `raw` field | A value |
| The `raw_original_order` field | A value |
| The hash rule | SHA-256, truncated to 12 characters |
| The FoxIO source | `technical_details/JA4.md` |

## The output format

```
<part a>_<cipher hash>_<extension hash>
```

Part a holds ten characters. `ja4plus/fingerprinters/ja4.py:316` builds it, and
`ja4plus/fingerprinters/ja4.py:231` joins the three parts.

## The parts

| Part | Width | What it holds |
|---|---|---|
| Transport | 1 | `t` for TLS over TCP, `q` for TLS over QUIC, `d` for DTLS. |
| Version | 2 | The highest TLS version the client offers, as `13` for TLS 1.3. |
| SNI | 1 | `d` when the client sends a server name, and `i` when it sends none. |
| Cipher count | 2 | The count of cipher suites, after the reader drops every GREASE value. It stops at `99`. |
| Extension count | 2 | The count of extensions, after the reader drops every GREASE value. It stops at `99`. |
| ALPN | 2 | The first character and the last character of the first ALPN value, or `00` when the client offers none. |
| Cipher hash | 12 | The hash of the sorted cipher list. |
| Extension hash | 12 | The hash of the sorted extension list, with the signature algorithms appended. |

## The hash rule

The fingerprinter joins the list with a comma, writes each value as four lowercase
hexadecimal digits, and hashes the result with SHA-256. It keeps the first 12 characters
of the hexadecimal digest.

**An empty list writes the zero sentinel `000000000000` and no hash.**
`ja4plus/fingerprinters/ja4.py:199` holds the hash, and
`ja4plus/fingerprinters/ja4.py:201` holds the sentinel.

## The raw forms

JA4 writes both raw forms. The `raw` field carries the `JA4_r` value, which holds the
sorted lists. The `raw_original_order` field carries the `JA4_ro` value, which holds the
lists in the order the ClientHello sent them.

The two forms differ, because JA4 sorts the cipher list and the extension list before it
hashes them.

## An example

| Capture | Value |
|---|---|
| `tests/foxio_vectors/https-connect.pcap` | `t12i860500_e18388e7f3a3_a1e935682795` |
| `tests/foxio_vectors/quic-tls-handshake.pcapng` | `q13d0310h3_55b375c5d22e_cd85d2d88918` |

`tests/test_method_pages.py` reads this table, runs the capture and compares each value
against what the processor emits.

The first value reads a TLS 1.2 client that sends no server name. The second value reads
a TLS 1.3 client over QUIC that offers the ALPN value `h3`.

## The FoxIO source

`technical_details/JA4.md` publishes JA4 as text, and it is the one method of the twelve
that holds a complete text specification. `technical_details/JA4.png` publishes the same
method as a diagram.

`docs/specs/foxio/README.md` holds the inventory, the pinned commit and the SHA-256 of
each file.

Verified against: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
(retrieved 2026-08-08, commit `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`)

## Where to read more

- [The usage guide](../usage.md#ja4---tls-client) holds a code sample.
- [The output schema](../output-schema.md) states the shape of the output line.
- [The method index](index.md) names every method.
