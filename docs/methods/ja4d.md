# JA4D

JA4D fingerprints a DHCPv4 endpoint. It reads one DHCP message and it emits one
fingerprint.

## The facts

| Item | Value |
|---|---|
| The `--types` token | `ja4d` |
| The fingerprinter class | `JA4DFingerprinter` |
| The one-shot function | `generate_ja4d` |
| The `raw` field | Always `null` |
| The `raw_original_order` field | Always `null` |
| The hash rule | None. The method hashes no part. |
| The FoxIO source | `technical_details/JA4D.png` |

## The output format

```
<section a>_<option list>_<parameter list>
```

`ja4plus/fingerprinters/ja4d.py:220` builds section a, and
`ja4plus/fingerprinters/ja4d.py:228` joins the three sections.

## The parts

| Part | Width | What it holds |
|---|---|---|
| Message type | 5 | The name of the DHCP message type, as `disco` for Discover and `reqst` for Request. A type with no name writes its number in five digits. |
| Maximum message size | 4 | The size of the largest message the sender accepts, in bytes. It stops at `9999`, and it is `0000` when the message carries no such option. |
| Requested address | 1 | `i` when the message carries a requested IP address, and `n` when it carries none. |
| FQDN | 1 | `d` when the message carries a fully qualified domain name, and `n` when it carries none. |
| Option list | | The code of each DHCP option, in wire order, joined with a hyphen. |
| Parameter list | | The code of each entry of the parameter request list, joined with a hyphen. It is `00` when the message carries no such list. |

The fingerprinter reads DHCP on the UDP ports 67, 68 and 4011.
`ja4plus/fingerprinters/ja4d.py:61` holds the set, and the Wireshark dissector states
`#define DHCP_UDP_PORT_RANGE  "67-68,4011"`.

## The hash rule

JA4D hashes no part. Every part of the value is a name, a number or a list of numbers.

## The raw forms

JA4D writes no raw form. Both raw fields of the output line are `null`.

## An example

| Capture | Value |
|---|---|
| `tests/foxio_vectors/dhcp.pcapng` | `disco0000in_61-55_1-3-6-42` |

`tests/test_method_pages.py` reads this table, runs the capture and compares the value
against what the processor emits.

The value reads a Discover message that advertises no maximum message size, carries a
requested address, carries no domain name, holds the options 61 and 55, and requests the
parameters 1, 3, 6 and 42.

## The FoxIO source

`technical_details/JA4D.png` publishes JA4D as a diagram. **The image is the only FoxIO
prose that has ever specified this method.** FoxIO published no text file for JA4D and
deleted none, and commit `6239c08` added the two DHCP images and nothing else.

**The FoxIO Python implementation emits no JA4D value**, so
`python/test/testdata/dhcp.pcapng.json` holds an empty array. The Wireshark dissector is
the one FoxIO implementation that writes a reference value, and the Zeek baseline
`zeek/tests/Traces/Scripts.ja4-dhcp/ja4d.log` holds the same four values.
`tests/foxio_vectors/wireshark_expected/` holds a copy of the file.

`docs/specs/foxio/JA4D.md` holds this project's transcription of the two DHCP images, and
#204 records the reading. `docs/specs/foxio/README.md` holds the inventory and the
SHA-256 of each file.

Verified against: https://github.com/FoxIO-LLC/ja4/tree/main/technical_details (retrieved
2026-08-08, commit `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`)

## Where to read more

- [The usage guide](../usage.md) holds the code samples of the library.
- [JA4D6](ja4d6.md) describes the DHCPv6 method.
- [The method index](index.md) names every method.
