# JA4S

JA4S fingerprints the TLS server. It reads one ServerHello message and it emits one
fingerprint.

## The facts

| Item | Value |
|---|---|
| The `--types` token | `ja4s` |
| The fingerprinter class | `JA4SFingerprinter` |
| The one-shot function | `generate_ja4s` |
| The `raw` field | A value |
| The `raw_original_order` field | A value |
| The hash rule | SHA-256, truncated to 12 characters |
| The FoxIO source | `technical_details/JA4S.png` |

## The output format

```
<part a>_<cipher>_<extension hash>
```

`ja4plus/fingerprinters/ja4s.py:288` builds part a, and
`ja4plus/fingerprinters/ja4s.py:301` joins the three parts.

## The parts

| Part | Width | What it holds |
|---|---|---|
| Transport | 1 | `t` for TLS over TCP, and `q` for TLS over QUIC. |
| Version | 2 | The TLS version the server selects, as `13` for TLS 1.3. |
| Extension count | 2 | The count of extensions the ServerHello carries. |
| ALPN | 2 | The first character and the last character of the ALPN value the server selects, or `00` when it selects none. |
| Cipher | 4 | The one cipher suite the server selects, as four lowercase hexadecimal digits. |
| Extension hash | 12 | The hash of the extension list, in wire order. |

**The cipher part holds the value itself and no hash.** The server selects one cipher
suite, so the part needs no list.

## The hash rule

The fingerprinter joins the extension list with a comma, writes each value as four
lowercase hexadecimal digits, and hashes the result with SHA-256. It keeps the first 12
characters of the hexadecimal digest.

**An empty extension list writes the zero sentinel `000000000000` and no hash.**
`ja4plus/fingerprinters/ja4s.py:297` holds the hash, and
`ja4plus/fingerprinters/ja4s.py:299` holds the sentinel.

## The raw forms

JA4S writes the same value into both raw fields. **JA4S sorts no list**, so the sorted
form and the original-order form are one string. #108 records the correction that
removed the sort.

## An example

| Capture | Value |
|---|---|
| `tests/foxio_vectors/https-connect.pcap` | `t120200_c030_5fbb12310400` |

`tests/test_method_pages.py` reads this table, runs the capture and compares the value
against what the processor emits.

The value reads a TLS 1.2 server that carries two extensions, selects no ALPN value, and
selects the cipher suite `c030`.

## The FoxIO source

`technical_details/JA4S.png` publishes JA4S as a diagram. FoxIO published a text file for
this method and then deleted it, so the image is the pinned specification.

`docs/specs/foxio/JA4S.md` holds this project's transcription of the image, and
`docs/specs/foxio/deleted-text-specifications.md` reconciles the deleted prose against
it. `docs/specs/foxio/README.md` holds the inventory and the SHA-256 of each file.

Verified against: https://github.com/FoxIO-LLC/ja4/tree/main/technical_details (retrieved
2026-08-08, commit `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`)

## Where to read more

- [The usage guide](../usage.md#ja4s---tls-server) holds a code sample.
- [The output schema](../output-schema.md) states the shape of the output line.
- [The method index](index.md) names every method.
