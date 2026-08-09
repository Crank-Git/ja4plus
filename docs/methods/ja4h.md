# JA4H

JA4H fingerprints the HTTP client. It reads one HTTP request and it emits one
fingerprint.

## The facts

| Item | Value |
|---|---|
| The `--types` token | `ja4h` |
| The fingerprinter class | `JA4HFingerprinter` |
| The one-shot function | `generate_ja4h` |
| The `raw` field | Always `null` |
| The `raw_original_order` field | A value |
| The hash rule | SHA-256, truncated to 12 characters |
| The FoxIO source | `technical_details/JA4H.md`, `technical_details/JA4H.png` |

## The output format

```
<part a>_<header hash>_<cookie name hash>_<cookie value hash>
```

`ja4plus/fingerprinters/ja4h.py:429` builds part a, and
`ja4plus/fingerprinters/ja4h.py:505` joins the four parts.

## The parts

| Part | Width | What it holds |
|---|---|---|
| Method | 2 | The first two characters of the request method, in lowercase, as `ge` for `GET`. |
| Version | 2 | The HTTP version, as `11` for HTTP/1.1. |
| Cookie | 1 | `c` when the request carries a `Cookie` header, and `n` when it carries none. |
| Referer | 1 | `r` when the request carries a `Referer` header, and `n` when it carries none. |
| Header count | 2 | The count of headers the header hash reads. It stops at `99`. |
| Language | 4 | The first four characters of the first `Accept-Language` value, without a hyphen, as `enus`. It is `0000` when the request carries no such header. |
| Header hash | 12 | The hash of the header names, in wire order, without `Cookie` and without `Referer`. |
| Cookie name hash | 12 | The hash of the sorted cookie names. |
| Cookie value hash | 12 | The hash of the sorted cookie name and value pairs. |

**The header count reads the same list the header hash reads.** #219 records the defect
where the count read one list and the hash read another.

## The hash rule

The fingerprinter joins each list with a comma and hashes the result with SHA-256. It
keeps the first 12 characters of the hexadecimal digest.

**An empty list writes the zero sentinel `000000000000` and no hash.** A request that
carries no cookie therefore writes the sentinel into the third part and the fourth part.
`ja4plus/fingerprinters/ja4h.py:480` holds the header hash, and
`ja4plus/fingerprinters/ja4h.py:490` holds the cookie name hash.

## The raw forms

**JA4H writes one raw form and not two.** The `raw_original_order` field carries the
`JA4H_ro` value. The `raw` field is always `null`, because FoxIO publishes no `JA4H_r`
value.

[The output schema](../output-schema.md#the-raw-forms) states the same fact for the
output line.

## An example

| Capture | Value |
|---|---|
| `tests/foxio_vectors/single-packets.pcap` | `ge11cr06enus_8c2f9ef95269_2a79f5d9f8b3_7b4d78c057bc` |
| `tests/foxio_vectors/http-empty-useragent.pcap` | `ge10nn010000_b8bcd45ac095_000000000000_000000000000` |

`tests/test_method_pages.py` reads this table, runs the capture and compares each value
against what the processor emits.

The first value reads a `GET` request over HTTP/1.1 that carries a cookie, a referer, six
headers and the language `en-US`. The second value reads a `GET` request over HTTP/1.0
that carries no cookie, so the third part and the fourth part hold the zero sentinel.

## The FoxIO source

`technical_details/JA4H.md` is 278 bytes. It names the purpose of JA4H and it states one
rule, the two-digit header count that omits `Cookie` and `Referer`. It builds no
fingerprint, so JA4H is an image method.

`technical_details/JA4H.png` publishes the algorithm as a diagram.
`docs/specs/foxio/JA4H.md` holds this project's transcription of it, and
`docs/specs/foxio/README.md` holds the inventory and the SHA-256 of each file.

Verified against: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4H.md
(retrieved 2026-08-08, commit `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`)

## Where to read more

- [The usage guide](../usage.md#ja4h---http) holds a code sample.
- [The output schema](../output-schema.md) states the shape of the output line.
- [The method index](index.md) names every method.
