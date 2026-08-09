# JA4D6

JA4D6 fingerprints a DHCPv6 endpoint. It reads one DHCPv6 message and it emits one
fingerprint.

## The facts

| Item | Value |
|---|---|
| The `--types` token | `ja4d6` |
| The fingerprinter class | `JA4D6Fingerprinter` |
| The one-shot function | `generate_ja4d6` |
| The `raw` field | Always `null` |
| The `raw_original_order` field | Always `null` |
| The hash rule | None. The method hashes no part. |
| The FoxIO source | `technical_details/JA4D6.png` |

## The output format

```
<section a>_<option list>_<request list>
```

`ja4plus/fingerprinters/ja4d6.py:295` builds section a, and
`ja4plus/fingerprinters/ja4d6.py:299` joins the three sections.

## The parts

| Part | Width | What it holds |
|---|---|---|
| Message type | 5 | The name of the DHCPv6 message type, as `solct` for Solicit. A type with no name writes its number in five digits. |
| DUID length | 4 | The length of the client DUID, in bytes. It stops at `9999`. |
| Address association | 1 | `i` when the message carries an IA_TA option, and `n` when it carries none. |
| FQDN | 1 | `d` when the message carries a fully qualified domain name, and `n` when it carries none. |
| Option list | | The code of each DHCPv6 option, in wire order, joined with a hyphen. |
| Request list | | The code of each entry of the option request list, joined with a hyphen. |

The fingerprinter reads DHCPv6 on the UDP ports 546 and 547.
`ja4plus/fingerprinters/ja4d6.py:275` holds the range, and the Wireshark dissector states
`UDP_PORT_DHCPV6_RANGE "546-547"`.

**A message type of 0 writes five digits.** DHCPv6 defines no message type 0, and the
Wireshark dissector emits a value for any `dhcpv6.msgtype` field, so the five-digit form
reports it. `ja4plus/fingerprinters/ja4d6.py:284` records the reading as D11.

## The hash rule

JA4D6 hashes no part. Every part of the value is a name, a number or a list of numbers.

## The raw forms

JA4D6 writes no raw form. Both raw fields of the output line are `null`.

## An example

| Capture | Value |
|---|---|
| `tests/foxio_vectors/dhcpv6.pcap` | `solct0014nn_1-6-8-25_23-24` |

`tests/test_method_pages.py` reads this table, runs the capture and compares the value
against what the processor emits.

The value reads a Solicit message whose client DUID is 14 bytes, which carries no IA_TA
option and no domain name, which holds the options 1, 6, 8 and 25, and which requests
the options 23 and 24.

## The FoxIO source

`technical_details/JA4D6.png` publishes JA4D6 as a diagram. **The image is the only FoxIO
prose that has ever specified this method.** FoxIO published no text file for JA4D6 and
deleted none.

**Warning: JA4D6 rests on one source.** The Wireshark dissector is the one FoxIO
implementation that writes a JA4D6 value, so nothing corroborates its six values the way
the Zeek baseline corroborates the four JA4D values. Treat a JA4D6 mismatch as a question
before you treat it as a defect in this project.
`tests/foxio_vectors/wireshark_expected/` holds a copy of the file.

`docs/specs/foxio/JA4D.md` holds this project's transcription of the two DHCP images, and
#204 records the reading. `docs/specs/foxio/README.md` holds the inventory and the
SHA-256 of each file.

Verified against: https://github.com/FoxIO-LLC/ja4/tree/main/technical_details (retrieved
2026-08-08, commit `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`)

## Where to read more

- [The usage guide](../usage.md) holds the code samples of the library.
- [JA4D](ja4d.md) describes the DHCPv4 method.
- [The method index](index.md) names every method.
