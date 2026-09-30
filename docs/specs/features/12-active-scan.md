---
id: active-scan
feature: Active scan
epic: "Epic 12: Active scan"
status: issued
issues: [775, 776]
mockups: []
---

## Purpose

FoxIO publishes twelve methods, and JA4TScan is the one method that sends packets. It sends
one TCP SYN to a host and reads the SYN-ACK and every retransmission of it. The value
describes how the TCP stack of that host answers and how it retransmits.

This project declined JA4TScan on 2026-08-08, and #197 holds that reading. **The
maintainer reversed the decline on 2026-09-30, in #775.** The capability boundary that
earned the decline stays, as a boundary between modules. `docs/specs/foxio/JA4TScan.md`
transcribes the FoxIO scanner, and this page states what this project builds from it.

The maintainer ruled on two questions on 2026-09-30.

1. **Firewall state: document, don't touch.** The library never changes firewall state.
   The scanner states the rule the operator must add, so that the kernel of the scanning
   host sends no RST for the SYN-ACK of the target. The scanner warns when a target gives
   a SYN-ACK and no retransmission arrives, because that shape usually means the rule is
   missing.
2. **Packaging: optional extra plus subcommand.** `pip install ja4plus[scan]`, a
   `ja4plus scan` subcommand, and a `ja4plus.scan` module. Nothing in `Processor` or any
   passive fingerprinter can send a packet.

## User stories

- As a scan operator, I want one JA4TScan value for each host I name, so that I can
  compare it against values another tool wrote.
- As a scan operator, I want the scanner to tell me the firewall rule it needs, so that I
  decide what changes on my host.
- As a capture analyst, I want the passive methods to stay unable to send a packet, so that
  reading a capture never reaches a network.

## Functional requirements

FR-active-scan-1 — `ja4plus scan` sends one TCP SYN to each target and sends no other
packet to it.

FR-active-scan-2 — The SYN carries the header values of S2 of
`docs/specs/foxio/JA4TScan.md`.

FR-active-scan-3 — The SYN carries the option bytes of S3 of
`docs/specs/foxio/JA4TScan.md`, in that order.

FR-active-scan-4 — The code that sends a packet lives in `ja4plus.scan` alone.

FR-active-scan-5 — No module outside `ja4plus.scan` imports `ja4plus.scan`.

FR-active-scan-6 — The `scan` extra of `pyproject.toml` names every dependency that
`ja4plus.scan` needs beyond the core install.

FR-active-scan-7 — The scanner changes no firewall state. It runs no `iptables` command
and no `pfctl` command.

FR-active-scan-8 — Before it sends the first SYN, the scanner writes the firewall rule for
the host system to standard error. Open question 4 decides the rule text.

FR-active-scan-9 — The scanner writes a warning to standard error for each target that
sends one SYN-ACK and no later response within the wait.

FR-active-scan-10 — The scanner waits 120 seconds after the last SYN for later responses.

FR-active-scan-11 — `--retransmit no` sets the wait to 8 seconds and turns the warning of
FR-active-scan-9 off.

FR-active-scan-12 — `--rate` sets the SYN count per second, and the default is 10.

FR-active-scan-13 — `--port` sets the one TCP port the scanner sends to, and the default
is 80.

FR-active-scan-14 — The scanner accepts one IPv4 address, one IPv4 network in CIDR form,
or the path of a file that holds one address on each line.

FR-active-scan-15 — The scanner reads a response only where it answers the SYN, under the
acknowledgment rule of S4 of `docs/specs/foxio/JA4TScan.md`.

FR-active-scan-16 — The scanner writes one result for each target that sent a SYN-ACK.

FR-active-scan-17 — The result uses the schema of `docs/specs/features/05-structured-output.md`,
with the `type` value `ja4tscan`.

FR-active-scan-18 — The state table of the scanner holds at most 10000 targets, and it
drops a target when the wait ends.

FR-active-scan-19 — Without the privilege to open a raw socket, the scanner sends nothing
and exits with status 1. The message names the required privilege.

FR-active-scan-20 — The value that one target produces follows the form open question 1
decides.

## User flows

**An operator scans one network.**

1. The operator installs the extra with `pip install ja4plus[scan]`.
2. The operator runs `sudo ja4plus scan 203.0.113.0/28 --port 443`.
3. The scanner writes the firewall rule for the host to standard error.
4. The operator adds the rule, or the operator accepts a result with no part e.
5. The scanner sends one SYN to each address at 10 SYN packets each second.
6. The scanner waits 120 seconds after the last SYN.
7. The scanner writes one result for each target that sent a SYN-ACK.
8. The scanner warns about each target that sent one SYN-ACK and nothing more.

**An operator scans with no retransmission.**

1. The operator runs `sudo ja4plus scan hosts.txt --retransmit no`.
2. The scanner writes no firewall rule, because the kernel RST is harmless in this mode.
3. The scanner waits 8 seconds after the last SYN.
4. Each result holds part a to part d and no part e.

## Screens & states

| Screen | Purpose | States |
|---|---|---|
| The firewall rule | The operator reads the rule the scan needs. | Linux rule; macOS rule; no rule under `--retransmit no`. |
| The result | A person or a tool reads one value for each target. | Table, JSON Lines or CSV, as `05-structured-output.md` states. |
| The warning | The operator learns that a target never retransmitted. | One line on standard error for each such target. |

## Behaviour rules

- The library never changes firewall state. The operator adds the rule and removes it.
- `Processor`, every fingerprinter and every module under `ja4plus/utils/` stay unable to
  send a packet. The boundary is a boundary between modules, and a case reads the imports.
- The scanner sends to the targets the operator names and to no other address.
- The scanner sends no second packet to a target, whatever the target answers.
- The scanner writes results to standard output and diagnostics to standard error, as
  FR-structured-output-9 states.
- The source port, the sequence number and the timestamp value of the SYN vary between
  runs. None of them reaches the value.

## Data touched

#776 builds every item of this list, and #775 changes no file under `ja4plus/`.

- New package `ja4plus/scan/`.
- Changed file `ja4plus/cli.py`, which adds the `scan` subcommand.
- Changed file `pyproject.toml`, which adds the `scan` extra. `scapy` is a core dependency
  already, so #776 states what the extra holds.
- Changed file `docs/output-schema.md`, which adds the `type` value `ja4tscan`.
- New cases under `tests/`.

## Interfaces

```
ja4plus scan TARGET [--port PORT] [--rate RATE] [--retransmit {yes,no}]
                    [--format {table,json,csv}] [--output FILE] [--force]
```

**Each option name and each default comes from the FoxIO wrapper.** S16 of
`docs/specs/foxio/JA4TScan.md` holds them. The port `Crank-Git/ja4plus-go` ships no
scanner, so parity rule 2 names no interface to adopt. The port adopts this one.

The JSON Lines object of one target:

```json
{
  "schema_version": 1,
  "timestamp": "2026-09-30T12:34:56Z",
  "type": "ja4tscan",
  "fingerprint": "64240_2-1-3-1-1-4_1460_8_1-2-4-8-R6",
  "raw": null,
  "raw_original_order": null,
  "src_ip": "203.0.113.7",
  "src_port": 443,
  "dst_ip": "192.0.2.10",
  "dst_port": 40112,
  "identified_as": null
}
```

- `src_ip` and `src_port` name the target, because the target sent the responses the value
  reads. `ja4tscan/module_ja4tscan.c:153` records the same address as `ip_src_num`.
- `dst_ip` and `dst_port` name the scanning host and the source port of its SYN.
- `timestamp` is the receive time of the last response of the target.
  `ja4tscan/module_ja4tscan.c:152` records the same time.

## Edge cases & failures

| Case | What happens |
|---|---|
| The target sends no response. | The scanner writes no result for it. |
| The target sends one SYN-ACK and nothing more. | The scanner writes a result with no part e, and it writes the warning of FR-active-scan-9. |
| The target answers the SYN with a RST. | Open question 2 decides it. |
| An ICMP message answers the SYN. | Open question 2 decides it. |
| A response carries an option length past the end of the options. | The scanner reads part b up to that option, as S6 states. It raises nothing. |
| The target file holds a line that is no address. | The scanner exits with status 1 before it sends a SYN, and it names the line. |
| The target is an IPv6 address. | Open question 3 decides it. |
| The `scan` extra is absent. | `ja4plus scan` exits with status 1 and names `pip install ja4plus[scan]`. |

## How the scanner is tested with no network

**No case of this feature sends a packet, and no case opens a raw socket.** FoxIO
publishes no JA4TScan capture, so each case feeds a recorded or constructed response
sequence to the code under test.

1. The formatter reads a list of responses. Each response holds a receive time, the TCP
   flags, the window and the option bytes. A case builds the list, and it compares the
   value against the expected string.
2. The SYN builder returns bytes. A case compares them against S2 and S3 of
   `docs/specs/foxio/JA4TScan.md`, with the source port, the sequence number and the
   timestamp value masked.
3. The scan loop takes the send function and the receive function as parameters. A case
   passes a fake pair, so the loop runs, waits and writes results with no network.
4. The published values that fit the form open question 1 selects become constructed
   cases. `The published values` of `docs/specs/foxio/JA4TScan.md` names which ones fit.
5. A case reads the imports of every module under `ja4plus/` and fails where a module
   outside `ja4plus/scan/` imports `ja4plus.scan`.

## Acceptance criteria

- [ ] `ja4plus scan --help` names `--port`, `--rate`, `--retransmit`, `--format`,
      `--output` and `--force`.
- [ ] The SYN builder writes the option bytes `020405b4 030307 0402 080a`, then the
      timestamp value, four zero bytes and one zero byte.
- [ ] The SYN builder writes the window 65535, the IP identification 54321 and the time to
      live 255.
- [ ] A fake scan of one target that sends one SYN-ACK calls the send function once.
- [ ] A fake scan of one target that sends a SYN-ACK and four retransmissions writes one
      result.
- [ ] A fake scan of one target that sends one SYN-ACK writes one warning line to
      standard error.
- [ ] A fake scan under `--retransmit no` writes no warning line.
- [ ] A fake scan writes no firewall rule under `--retransmit no`.
- [ ] A fake scan on Linux writes the Linux rule to standard error before the first SYN.
- [ ] A fake scan on macOS writes the macOS rule to standard error before the first SYN.
- [ ] No module under `ja4plus/` calls `subprocess`, `os.system` or `os.popen` with
      `iptables` or `pfctl`.
- [ ] No module outside `ja4plus/scan/` imports `ja4plus.scan`.
- [ ] `import ja4plus` imports no module under `ja4plus/scan/`.
- [ ] A fake scan without raw-socket privilege exits with status 1 and sends nothing.
- [ ] A target file that holds a line that is no address exits with status 1 and sends
      nothing.
- [ ] `ja4plus scan <target> --format json` writes objects that hold the 11 fields of
      `05-structured-output.md`, with `"type": "ja4tscan"`.
- [ ] The response sequence of the Windows 10 example produces
      `64240_2-1-3-1-1-4_1460_8_1-2-4-8-R6`.
- [ ] The response sequence of the Amazon AWS Linux 2 example produces
      `62727_2-4-8-1-3_8961_7_1-2-4-8-16`.
- [ ] A response sequence of one SYN-ACK produces four parts and no part e.
- [ ] The state table holds at most 10000 targets under a fake scan of 20000 targets.

**Each answer to an open question below adds the criteria that answer implies.** The
criteria above hold under every option each question names.

## Out of scope

- `--lookup` on a scan result. `ja4plus/data/ja4plus-mapping.csv` holds a `ja4tscan`
  column, and a later issue may read it.
- More than one port in one scan. The FoxIO wrapper scans one port.
- JA4TScan inside `Processor`, `ja4plus analyze` or `ja4plus watch`.
- Windows. Live capture already excludes it.

## Open questions

**Each question below reaches no ruling of 2026-09-30, and #776 builds nothing that
depends on the answer.** Each one names the options and the evidence.

1. **Which form do part a to part e follow?** `docs/specs/foxio/JA4TScan.md` measures three
   places where the FoxIO module and the JA4TS form of this project differ.
   - Part b: the module writes one `0` for any run of End of Option List bytes (S6). JA4TS
     writes one `0` for each byte (R5 of `docs/specs/foxio/JA4T.md`).
   - Part d: the module writes a zero scale as `0` (S8). JA4TS writes `00` (R11).
   - Part e: the module rounds a delay of exactly one half down (S10). JA4TS rounds it up
     (R12).

   Option A follows the module, and it fits five of the eight published values. Option B
   reuses `tcp_prefix` and the JA4TS delay rule, and it fits seven of the eight. Neither
   option fits the HP ILO value, whose delays exceed the wait.
2. **What does a target produce where it answers with no SYN-ACK?** The module writes
   `0_00_00_` for a RST that answers the SYN (S12). The wrapper rewrites that value to
   `0_rst-ack` (S15). The module writes an ICMP row with an empty value (S11).
   - Option A writes `0_rst-ack`, the bytes the FoxIO wrapper publishes.
   - Option B writes the four parts of the RST in the form of question 1, with no
     truncation.
   - Option C writes no result for such a target, and writes one line to standard error.
3. **Does the scanner read IPv6?** The FoxIO module reads IPv4 alone (S17). The passive
   methods of this project read both.
   - Option A scans IPv4 alone, as FoxIO does.
   - Option B scans IPv4 and IPv6. The SYN then needs an IPv6 header that no FoxIO source
     states.
4. **Which firewall rule does the scanner state?** The FoxIO wrapper adds four `INPUT`
   rules that drop every new inbound packet (S14).
   - Option A states the four FoxIO rules on Linux, and a pf rule of the same effect on
     macOS.
   - Option B states one rule that drops each outbound RST to the scanned port. On Linux
     that is `iptables -A OUTPUT -p tcp --tcp-flags RST RST --dport <port> -j DROP`. On
     macOS that is `block drop out quick proto tcp to any port <port> flags R/R`.

   Option B blocks no inbound traffic of the host. Option A leaves inbound connections of
   the host dropped for the whole scan.

Verified against: https://man7.org/linux/man-pages/man8/iptables-extensions.8.html (`--tcp-flags` and `--dport` of the `tcp` match, retrieved 2026-09-30)
Verified against: `man pf.conf` of macOS 27.0 (`flags <a>/<b>`, read 2026-09-30)
