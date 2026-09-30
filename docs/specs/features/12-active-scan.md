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

**The maintainer ruled on four more questions on 2026-09-30**, at
https://github.com/Crank-Git/ja4plus/issues/775#issuecomment-5921253786.
`## The rulings on the four open questions` below quotes them, and the requirements below
state each one.

## User stories

- As a scan operator, I want one JA4TScan value for each host I name, so that I can
  compare it with another tool.
- As a scan operator, I want the scanner to state the firewall rule it needs, so that I
  decide the change.
- As a capture analyst, I want the passive methods unable to send a packet, so that a
  capture read reaches no network.

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

FR-active-scan-8 — Before it sends the first SYN, the scanner writes the firewall rules of
`## The firewall rules the scanner states` to standard error, for the host system.

FR-active-scan-9 — The scanner writes a warning to standard error for each target that
sends one SYN-ACK and no later response within the wait.

FR-active-scan-10 — The scanner waits 120 seconds after the last SYN for later responses.

FR-active-scan-11 — `--retransmit no` sets the wait to 8 seconds and turns the warning of
FR-active-scan-9 off.

FR-active-scan-12 — `--rate` sets the SYN count per second, and the default is 10.

FR-active-scan-13 — `--port` sets the one TCP port the scanner sends to, and the default
is 80.

FR-active-scan-14 — The scanner accepts one IPv4 address, one IPv4 network in CIDR form,
or a file of IPv4 addresses, one on each line.

FR-active-scan-15 — The scanner reads a response only where it answers the SYN, under the
acknowledgment rule of S4 of `docs/specs/foxio/JA4TScan.md`.

FR-active-scan-16 — The scanner writes one result for each target that sent a SYN-ACK or
a RST.

FR-active-scan-17 — The result uses the schema of `docs/specs/features/05-structured-output.md`,
with the `type` value `ja4tscan`.

FR-active-scan-18 — The state table of the scanner holds at most 10000 targets, and it
drops a target when the wait ends.

FR-active-scan-19 — Without the privilege to open a raw socket, the scanner sends nothing
and exits with status 1. The message names the required privilege.

FR-active-scan-20 — Part a to part d of the value are the JA4TS parts of the first SYN-ACK,
which `tcp_prefix` of `ja4plus/utils/tcp_options.py` writes.

FR-active-scan-21 — Part e follows R12 and R13 of `docs/specs/foxio/JA4T.md`, the JA4TS
delay rule, and it counts each delay from the previous response of the target.

FR-active-scan-22 — A target whose first response carries RST produces the value
`0_rst-ack`.

FR-active-scan-23 — An ICMP message that answers the SYN produces no value.

FR-active-scan-24 — The scanner reads IPv4 alone. An IPv6 target stops the scan with
status 1 before the first SYN.

FR-active-scan-25 — The scanner sends the SYN as a link-layer frame, as zmap does.

## The rulings on the four open questions

The maintainer ruled on 2026-09-30. The comment reads, quoted rather than rewritten:

> 1. **Form of parts a to e: reuse the JA4TS form of this project** (`tcp_prefix` and the JA4TS delay rule). A scan prefix then equals the passive JA4TS prefix of the same server. The three measured differences of `module_ja4tscan.c` (S6 End-of-Option-List run, S8 zero window scale, S10 rounding at 0.5 s) go into the divergence register.
> 2. **A target that sends no SYN-ACK: publish `0_rst-ack` for a RST**, the final form of the FoxIO wrapper. ICMP or no answer gives no value.
> 3. **IPv6: IPv4 only.** The FoxIO module reads IPv4 only.
> 4. **Firewall rule text: FoxIO's four iptables INPUT rules** (accept established and related, accept ICMP, accept loopback, drop every other inbound packet), plus a pf equivalent. The library prints the rules and never applies them. That part of the 2026-09-30 ruling stands.

**Ruling 1 parts the scanner from the FoxIO module in three places**, and the divergence
register of `docs/specs/spec.md` holds one row for each.

| Part | The FoxIO module | This project |
|---|---|---|
| b | One `0` for any run of End of Option List bytes (S6) | One `0` for each such byte (R5) |
| d | A zero scale writes `0` (S8) | A zero scale writes `00` (R11) |
| e | A delay of exactly one half second rounds down (S10) | It rounds away from zero (R12) |

**Ruling 1 leaves one published value outside the form.** The F5 Big IP value writes part
d as `0`, and this project writes `00` for the same responses. The other seven published
values fit the form. `The published values` of `docs/specs/foxio/JA4TScan.md` holds the
reading.

**Ruling 2 names the value the wrapper publishes on real traffic.** The module writes
`0_00_00_` for such a RST, and the wrapper rewrites it to `0_rst-ack` (S12 and S15). The
wrapper writes the window of the RST in place of the first `0`, and a RST carries a window
of 0 on real traffic. This project writes the ruled value `0_rst-ack` for every such
target.

## The firewall rules the scanner states

**The scanner prints these rules and never applies them.** The operator adds them before
the scan and removes them after it.

On Linux, the scanner prints the four rules of `ja4tscan/ja4tscan.py:15-18`, verbatim.

```
iptables -t filter -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -t filter -A INPUT -p icmp -j ACCEPT
iptables -t filter -A INPUT -i lo -j ACCEPT
iptables -t filter -A INPUT -j DROP
```

The scanner also prints the four commands of `ja4tscan/ja4tscan.py:22-25`, which remove
the rules.

On macOS, the scanner prints the pf equivalent. Each line matches one rule above.

```
pass out all
pass in quick inet proto icmp all
pass in quick on lo0 all
block drop in all
```

- `pass out all` keeps state for each connection the host opens, so pf passes its replies.
  That is the `ESTABLISHED,RELATED` rule. The `pass out` example of the macOS `pf.conf`
  manual keeps state with no option.
- `quick` ends the evaluation at the first match, so ICMP and loopback traffic pass.
- `block drop in all` drops every other inbound packet, and the SYN-ACK of a target among
  them.

**The rules work only where the SYN bypasses the firewall, and FR-active-scan-25 states
that.** zmap writes an Ethernet frame at `ja4tscan/module_ja4tscan.c:178-179`, so the
connection tracker of the host holds no state for the SYN. The SYN-ACK then matches no
established connection, and the last rule drops it before the kernel reads it. A SYN that
leaves through a raw IP socket passes the firewall, the tracker records it, and the first
rule then accepts the SYN-ACK. The kernel then sends the RST that the rules exist to
stop. The capture of the scanner reads the SYN-ACK before the firewall on both systems.

## User flows

**An operator scans one network.**

1. The operator installs the extra with `pip install ja4plus[scan]`.
2. The operator runs `sudo ja4plus scan 203.0.113.0/28 --port 443`.
3. The scanner writes the firewall rules for the host to standard error.
4. The operator adds the rules, or the operator accepts a result with no part e.
5. The scanner sends one SYN to each address at 10 SYN packets each second.
6. The scanner waits 120 seconds after the last SYN.
7. The scanner writes one result for each target that sent a SYN-ACK or a RST.
8. The scanner warns about each target that sent one SYN-ACK and nothing more.

**An operator scans with no retransmission.**

1. The operator runs `sudo ja4plus scan hosts.txt --retransmit no`.
2. The scanner writes no firewall rule, because the kernel RST is harmless in this mode.
3. The scanner waits 8 seconds after the last SYN.
4. Each result holds part a to part d and no part e.

## Screens & states

| Screen | Purpose | States |
|---|---|---|
| The firewall rules | The operator reads the rules the scan needs. | Linux rules; macOS rules; no rules under `--retransmit no`. |
| The result | A person or a tool reads one value for each target. | Table, JSON Lines or CSV, as `05-structured-output.md` states. |
| The warning | The operator learns that a target never retransmitted. | One line on standard error for each such target. |

## Behaviour rules

- The library never changes firewall state. The operator adds the rules and removes them.
- `Processor`, every fingerprinter and every module under `ja4plus/utils/` stay unable to
  send a packet. The boundary is a boundary between modules, and a case reads the imports.
- The scanner sends to the targets the operator names and to no other address.
- The scanner sends no second packet to a target, whatever the target answers.
- The scanner writes results to standard output and diagnostics to standard error, as
  FR-structured-output-9 states.
- The source port, the sequence number and the timestamp value of the SYN vary between
  runs. None of them reaches the value.
- A scan value of a server holds the same part a to part d as the passive JA4TS value of
  that server, for the same SYN-ACK.

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
| The target answers the SYN with a RST. | The scanner writes one result with the value `0_rst-ack`. Later responses of the target change nothing. |
| An ICMP message answers the SYN. | The scanner writes no result for the target. |
| A response carries an option length past the end of the options. | `tcp_prefix` reads part b up to that option. It raises nothing. |
| The target file holds a line that is no IPv4 address. | The scanner exits with status 1 before it sends a SYN, and it names the line. |
| The target is an IPv6 address or network. | The scanner exits with status 1 before it sends a SYN, and it states that the scanner reads IPv4 alone. |
| The `scan` extra is absent. | `ja4plus scan` exits with status 1 and names `pip install ja4plus[scan]`. |

## How the scanner is tested with no network

**No case of this feature sends a packet, and no case opens a raw socket.** FoxIO
publishes no JA4TScan capture. Each case therefore feeds a recorded or constructed
response sequence to the code under test.

1. The formatter reads a list of responses. Each response holds a receive time, the TCP
   flags, the window and the option bytes. A case builds the list, and it compares the
   value against the expected string.
2. The SYN builder returns bytes. A case compares them against S2 and S3 of
   `docs/specs/foxio/JA4TScan.md`, with the source port, the sequence number and the
   timestamp value masked.
3. The scan loop takes the send function and the receive function as parameters. A case
   passes a fake pair, so the loop runs, waits and writes results with no network.
4. The seven published values that fit the form become constructed cases.
5. A case reads the imports of every module under `ja4plus/` and fails where a module
   outside `ja4plus/scan/` imports `ja4plus.scan`.

## Acceptance criteria

- [ ] `ja4plus scan --help` names `--port`, `--rate`, `--retransmit`, `--format`,
      `--output` and `--force`.
- [ ] The SYN builder writes the option bytes `020405b4 030307 0402 080a`, then the
      timestamp value, four zero bytes and one zero byte.
- [ ] The SYN builder writes the window 65535, the IP identification 54321 and the time to
      live 255.
- [ ] The SYN builder returns a frame that opens with an Ethernet header.
- [ ] A fake scan of one target that sends one SYN-ACK calls the send function once.
- [ ] A fake scan of one target that sends a SYN-ACK and four retransmissions writes one
      result.
- [ ] A fake scan of one target that sends one SYN-ACK writes one warning line to
      standard error.
- [ ] A fake scan under `--retransmit no` writes no warning line.
- [ ] A fake scan writes no firewall rule under `--retransmit no`.
- [ ] A fake scan on Linux writes the four `iptables` rules of
      `## The firewall rules the scanner states` to standard error before the first SYN.
- [ ] A fake scan on Linux writes the four `iptables -t filter -D INPUT` commands to
      standard error.
- [ ] A fake scan on macOS writes the four pf rules of
      `## The firewall rules the scanner states` to standard error before the first SYN.
- [ ] No module under `ja4plus/` calls `subprocess`, `os.system` or `os.popen` with
      `iptables` or `pfctl`.
- [ ] No module outside `ja4plus/scan/` imports `ja4plus.scan`.
- [ ] `import ja4plus` imports no module under `ja4plus/scan/`.
- [ ] A fake scan without raw-socket privilege exits with status 1 and sends nothing.
- [ ] A target file that holds a line that is no IPv4 address exits with status 1 and
      sends nothing.
- [ ] `ja4plus scan 2001:db8::1` exits with status 1 and sends nothing.
- [ ] `ja4plus scan <target> --format json` writes objects that hold the 11 fields of
      `05-structured-output.md`, with `"type": "ja4tscan"`.
- [ ] The response sequence of the Windows 10 example produces
      `64240_2-1-3-1-1-4_1460_8_1-2-4-8-R6`.
- [ ] The response sequence of the Windows 2003 example produces
      `16384_2-1-3-1-1-8-1-1-4_1460_00_2-7`.
- [ ] The response sequence of the Amazon AWS Linux 2 example produces
      `62727_2-4-8-1-3_8961_7_1-2-4-8-16`.
- [ ] The response sequence of the Mac OSX / iPhone example produces
      `65535_2-1-3-1-1-8-4-0-0_1460_6_1-2-4-8-16-32-12`.
- [ ] The response sequence of the HP ILO example produces
      `5840_2_1460_00_3-6-12-24-48-60-60-60-60-60`.
- [ ] The response sequence of the Epson Printer example produces
      `28960_2-4-8-1-3_1460_3_1-4-8-16`.
- [ ] The response sequence of the Ubiquiti Router example produces
      `43440_2-4-8-1-3_1460_12_1-2-4-8-17`.
- [ ] The responses of the F5 Big IP example produce `4380_2-4-8_1460_00_3-6-12`, and not
      the published `4380_2-4-8_1460_0_3-6-12`.
- [ ] A SYN-ACK that carries two End of Option List bytes produces a part b that ends with
      `0-0`.
- [ ] A retransmission 1.5 seconds after the SYN-ACK writes the delay `2`.
- [ ] A response sequence of one SYN-ACK produces four parts and no part e.
- [ ] A scan value and the passive JA4TS value of the same SYN-ACK hold the same part a to
      part d.
- [ ] A target whose first response carries RST produces `0_rst-ack`.
- [ ] A target whose first response carries RST and ACK with a window of 512 produces
      `0_rst-ack`.
- [ ] A target that answers the SYN with an ICMP message produces no result.
- [ ] The state table holds at most 10000 targets under a fake scan of 20000 targets.

## Out of scope

- `--lookup` on a scan result. `ja4plus/data/ja4plus-mapping.csv` holds a `ja4tscan`
  column, and a later issue may read it.
- More than one port in one scan. The FoxIO wrapper scans one port.
- IPv6. The maintainer ruled IPv4 alone on 2026-09-30.
- JA4TScan inside `Processor`, `ja4plus analyze` or `ja4plus watch`.
- Windows. Live capture already excludes it.

## Open questions

None. The maintainer ruled on the four questions this page held on 2026-09-30, and
`## The rulings on the four open questions` above quotes the ruling.

Verified against: https://man7.org/linux/man-pages/man8/iptables-extensions.8.html (`--tcp-flags` and `--dport` of the `tcp` match, retrieved 2026-09-30)
Verified against: `man pf.conf` of macOS 27.0 (`quick`, `flags <a>/<b>`, and the `pass out` example that keeps state, read 2026-09-30)
