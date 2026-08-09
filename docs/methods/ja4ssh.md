# JA4SSH

JA4SSH fingerprints an SSH session. It reads the size and the direction of the encrypted
SSH messages, and it emits one fingerprint for each window of 200 SSH packets.

**JA4SSH reads no plaintext.** The session is encrypted, so the method reads the traffic
pattern alone.

## The facts

| Item | Value |
|---|---|
| The `--types` token | `ja4ssh` |
| The fingerprinter class | `JA4SSHFingerprinter` |
| The one-shot function | `generate_ja4ssh` |
| The `raw` field | Always `null` |
| The `raw_original_order` field | Always `null` |
| The hash rule | None. The method hashes no part. |
| The FoxIO source | `technical_details/JA4SSH.png` |

## The output format

```
c<client mode>s<server mode>_c<client count>s<server count>_c<client acks>s<server acks>
```

`ja4plus/fingerprinters/ja4ssh.py:473` joins the three parts.

## The parts

| Part | What it holds |
|---|---|
| Part a | The most common SSH payload size of the client, then the most common size of the server. |
| Part b | The count of SSH messages the client sent in the window, then the count the server sent. |
| Part c | The count of bare ACK packets the client sent, then the count the server sent. |

**A bare ACK is an ACK packet that carries no payload and no other flag.** A SYN-ACK
packet, a FIN-ACK packet and an RST-ACK packet are not bare ACKs. #92 records the
correction.

## The window

**JA4SSH emits one fingerprint for every 200 SSH packets on a connection.** The window is
the count of packets the method reads before it emits. A connection that ends before the
window fills holds an open window.

`Processor.close_open_windows` emits every open window, and a reader of a capture file
calls it after the last packet. Without that call the last window of each connection
reaches no reader. #214 records the correction.

**The count of 200 replaced a count of 10 in version 0.6.0.** Read
[the migration page](../migration-0.6-to-1.0.md) before you compare a value of version
0.6.0 against a value of version 1.0.0.

## The hash rule

JA4SSH hashes no part. Every part of the value is a count or a literal.

## The raw forms

JA4SSH writes no raw form. Both raw fields of the output line are `null`.

## An example

| Capture | Value |
|---|---|
| `tests/foxio_vectors/ssh.pcapng` | `c36s36_c76s124_c0s0` |

`tests/test_method_pages.py` reads this table, runs the capture and compares the value
against what the processor emits.

The value reads a session where the client and the server each sent a most common
payload of 36 bytes, the client sent 76 SSH messages, the server sent 124, and neither
endpoint sent a bare ACK inside the window.

## The FoxIO source

`technical_details/JA4SSH.png` publishes JA4SSH as a diagram. FoxIO published a text file
for this method and then deleted it, so the image is the pinned specification.

`docs/specs/foxio/JA4SSH.md` holds this project's transcription of the image, and #199
records the reading. `docs/specs/foxio/README.md` holds the inventory and the SHA-256 of
each file.

Verified against: https://github.com/FoxIO-LLC/ja4/tree/main/technical_details (retrieved
2026-08-08, commit `27f0cbf9fd3000c072f82a0f7d0361dc99acf6c8`)

## Where to read more

- [The usage guide](../usage.md#ja4ssh---ssh) holds a code sample.
- [The output schema](../output-schema.md) states the shape of the output line.
- [The method index](index.md) names every method.
