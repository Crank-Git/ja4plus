# JA4TScan

JA4TScan fingerprints the TCP stack of a server. It sends one TCP SYN to the server, and
it reads the SYN-ACK and every retransmission of it. The value states how the stack
answers and how it retransmits.

**JA4TScan is the one method that sends packets.** Every other method reads traffic that
already exists. The `ja4plus scan` subcommand runs it, and the `ja4plus.scan` package holds
it. No fingerprinter and no function of `ja4plus.__all__` can send a packet.

## The facts

| Item | Value |
|---|---|
| The command | `ja4plus scan TARGET` |
| The installation | `pip install ja4plus[scan]` |
| The `type` value of an output line | `ja4tscan` |
| The value writer | `ja4tscan_value` of `ja4plus.scan.value` |
| The `raw` field | Always `null` |
| The `raw_original_order` field | Always `null` |
| The hash rule | None. The method hashes no part. |
| The FoxIO source | `module_ja4tscan.c` of `FoxIO-LLC/ja4tscan` |

## The command

<!-- sample: skip the block states the synopsis of the command, and it runs nothing -->
```bash
ja4plus scan TARGET [--port PORT] [--rate RATE] [--retransmit {yes,no}]
                    [--format {table,json,csv}] [--output FILE] [--force]
```

| Option | Default | What it sets |
|---|---|---|
| `TARGET` | None | One IPv4 address, one IPv4 network in CIDR form, or a file of IPv4 addresses, one on each line. |
| `--port` | 80 | The one TCP port the scanner sends to. |
| `--rate` | 10 | The SYN count for each second. |
| `--retransmit` | `yes` | `yes` reads every retransmission for 120 seconds after each SYN. `no` reads the first response alone for 8 seconds. |

Each option name and each default comes from the FoxIO wrapper. The scanner reads IPv4
alone, so an IPv6 target stops the scan before the first SYN.

**The scanner needs the privilege to open a raw socket.** Linux grants it through the
`CAP_NET_RAW` capability, and macOS grants it through write access to the `/dev/bpf*`
devices. Without it, the scanner sends nothing and exits with the status 1.

<!-- sample: skip the command sends a packet to a host of the network -->
```bash
sudo ja4plus scan 203.0.113.0/28 --port 443 --format json
```

## The firewall rules

**The scanner changes no firewall state.** The kernel of the scanning host holds no socket
for the connection, so it answers each SYN-ACK with a RST. The RST stops the
retransmissions that part e reads. Before the first SYN, the scanner therefore writes the
rules that drop the SYN-ACK to standard error. The operator adds them before the scan and
removes them after it.

On Linux, the scanner writes the four rules of the FoxIO wrapper and the four commands
that remove them.

```
iptables -t filter -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -t filter -A INPUT -p icmp -j ACCEPT
iptables -t filter -A INPUT -i lo -j ACCEPT
iptables -t filter -A INPUT -j DROP
```

On macOS, the scanner writes the pf equivalent.

```
pass out all
pass in quick inet proto icmp all
pass in quick on lo0 all
block drop in all
```

**Warning: the last rule drops every other inbound packet until you remove it.** An
established connection, ICMP and loopback traffic still pass.

**The rules work because the scanner sends each SYN as a link-layer frame.** The
connection tracker of the host then holds no state for the SYN, and the last rule drops
the SYN-ACK. #776 measured both paths on Linux on 2026-09-30. A SYN from a raw IP socket
produced a kernel RST under the same rules.

The scanner writes one warning line for each target that sends one SYN-ACK and no later
response. That shape usually means the rules are absent. `--retransmit no` writes no rule
and no warning, because that mode reads the first response alone.

## The output format

```
<window size>_<option kinds>_<mss>_<window scale>
<window size>_<option kinds>_<mss>_<window scale>_<delays>
0_rst-ack
```

`ja4plus/scan/value.py` builds the value.

## The parts

| Part | What it holds |
|---|---|
| Window size | The TCP window size of the first SYN-ACK, as a decimal number. |
| Option kinds | The kind number of each TCP option of the first SYN-ACK, in wire order, joined with a hyphen. It is `00` when the packet carries no option. |
| MSS | The maximum segment size of the first SYN-ACK, as at least two digits. It is `00` when the packet carries no MSS option. |
| Window scale | The window scale of the first SYN-ACK. It is `00` when the scale is zero. |
| Delays | The count of seconds between each response and the response before it, joined with a hyphen. A RST writes `R` before its delay, and it ends the list. |

**Part a to part d equal the parts of the [JA4TS](ja4ts.md) value of the same SYN-ACK.**
The maintainer ruled that form on 2026-09-30, in #775. Part e reads ten retransmissions
and no more, and a delay of one half second past a whole second rounds up.

**A target whose first response carries RST produces `0_rst-ack`.** The FoxIO wrapper
publishes that value for such a target. An ICMP message or no answer produces no value.

## The examples

The FoxIO scanner publishes eight values against named systems, and it publishes no
capture. `tests/test_ja4tscan_value.py` builds the responses of each one.

| System | Value |
|---|---|
| Windows 10 | `64240_2-1-3-1-1-4_1460_8_1-2-4-8-R6` |
| Windows 2003 | `16384_2-1-3-1-1-8-1-1-4_1460_00_2-7` |
| Amazon AWS Linux 2 | `62727_2-4-8-1-3_8961_7_1-2-4-8-16` |
| Mac OSX / iPhone | `65535_2-1-3-1-1-8-4-0-0_1460_6_1-2-4-8-16-32-12` |
| HP ILO | `5840_2_1460_00_3-6-12-24-48-60-60-60-60-60` |
| Epson Printer | `28960_2-4-8-1-3_1460_3_1-4-8-16` |
| Ubiquiti Router | `43440_2-4-8-1-3_1460_12_1-2-4-8-17` |
| F5 Big IP | `4380_2-4-8_1460_00_3-6-12` |

**The F5 Big IP value departs from the published `4380_2-4-8_1460_0_3-6-12`.** This project
writes a zero window scale as `00`, the JA4TS rule. The `Divergence register` of
`docs/specs/spec.md` holds the three places where the scanner differs from the FoxIO module.

## Where to read more

- `docs/specs/features/12-active-scan.md` states every requirement of the scanner.
- `docs/specs/foxio/JA4TScan.md` transcribes the FoxIO scanner.
- [The output schema](../output-schema.md) states the shape of each output line.
