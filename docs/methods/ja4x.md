# JA4X

JA4X fingerprints the structure of an X.509 certificate. It reads the object identifiers
of the issuer name, the subject name and the extensions, and it emits one fingerprint.

**JA4X reads the structure and not the content.** Two certificates that one tool issued
produce the same value, whatever names they carry.

## The facts

| Item | Value |
|---|---|
| The `--types` token | `ja4x` |
| The fingerprinter class | `JA4XFingerprinter` |
| The one-shot function | `generate_ja4x` |
| The `raw` field | A value |
| The `raw_original_order` field | A value |
| The hash rule | SHA-256, truncated to 12 characters |
| The FoxIO source | `technical_details/JA4X.png` |

## The output format

```
<issuer hash>_<subject hash>_<extension hash>
```

`ja4plus/fingerprinters/ja4x.py:81` joins the three parts.

## The parts

| Part | Width | What it holds |
|---|---|---|
| Issuer hash | 12 | The hash of the object identifier of each RDN of the issuer name, in wire order. |
| Subject hash | 12 | The hash of the object identifier of each RDN of the subject name, in wire order. |
| Extension hash | 12 | The hash of the object identifier of each extension, in wire order. |

**A self-signed certificate writes the same value into the first part and the second
part**, because its issuer name and its subject name hold the same object identifiers.

## The hash rule

The fingerprinter writes each object identifier in its hexadecimal form, joins the list
with a comma, and hashes the result with SHA-256. It keeps the first 12 characters of the
hexadecimal digest.

**An empty list writes the zero sentinel `000000000000` and no hash.**
`ja4plus/fingerprinters/ja4x.py:73` holds the issuer hash and the sentinel.

## The raw forms

JA4X writes the same value into both raw fields. **JA4X sorts no list**, so the sorted
form and the original-order form are one string.
`ja4plus/fingerprinters/ja4x.py:91` states the rule and names the FoxIO material that
carries it.

## An example

| Capture | Value |
|---|---|
| `tests/foxio_vectors/https-connect.pcap` | `7d5dbb3783b4_7d5dbb3783b4_9c5875a5c227` |

`tests/test_method_pages.py` reads this table, runs the capture and compares the value
against what the processor emits.

The first part and the second part hold the same value, so the capture carries a
self-signed certificate.

## How to fingerprint a certificate file

`ja4plus` reads a certificate from a file as well as from a TLS handshake. The `cert`
subcommand reads a DER file. `compute_ja4x_from_der` reads DER bytes and
`compute_ja4x_from_pem` reads PEM bytes. Each helper returns `None` for a certificate it
cannot parse, and it raises nothing.
[The usage guide](../usage.md#ja4x---x509-certificate) holds the code sample.

## The FoxIO source

`technical_details/JA4X.png` publishes JA4X as a diagram. FoxIO published a text file for
this method and then deleted it, so the image is the pinned specification.

`docs/specs/foxio/JA4X.md` holds this project's transcription of the image, and #202
records the reading. `docs/specs/foxio/README.md` holds the inventory and the SHA-256 of
each file.

Verified against: https://github.com/FoxIO-LLC/ja4/tree/main/technical_details (retrieved
2026-08-08, commit `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`)

## Where to read more

- [The usage guide](../usage.md#ja4x---x509-certificate) holds a code sample.
- [The output schema](../output-schema.md) states the shape of the output line.
- [The method index](index.md) names every method.
