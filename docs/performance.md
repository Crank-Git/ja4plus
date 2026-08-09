# Packet throughput

`throughput` of the `## Terms` table of `docs/specs/spec.md` names the count of packets
one processor reads for each second of elapsed time. The count belongs to one named packet
run on one named host. This page publishes that count. #415 measured it.

**This page states no target.** `Non-goals` of `docs/specs/spec.md` states that
wire-speed performance is out of scope, and that this project measures throughput and
reports it. A reader decides what a rate is worth against a use, and no continuous-integration
job fails on a number here.

**These measurements become no floor.** A floor derived from this measurement cannot
detect a fault in this measurement, because the same program produced both. A later issue
may state a floor, and it derives that floor from a second measurement, taken by another
method on a named host.

## How to reproduce a measurement

<!-- sample: skip the run costs 498 seconds, and it reads the repository working directory -->
```bash
python tests/throughput_run.py --packets 1000000 --connections 100000
python tests/throughput_run.py --captures
```

The program writes one JSON object. `tests/test_throughput.py` reads it.

**The clock covers `process_packet` and nothing else.** The program builds the traffic,
or parses the capture, outside the clock. The seconds scapy spends to build a packet
belong to scapy. A run that timed the traffic builder as well would report the speed of
scapy under the name of this package.

## The three controls

A timing case that measures the wrong thing reads as a fast package. Three controls close
the three ways this measurement fails while it still reports a number.

| Control | What it proves | The case that holds it |
|---|---|---|
| Packet count | The run fed the packet count the case states. A shorter run reads a shorter elapsed time. | `test_the_run_fed_the_packet_count_the_case_states` |
| Work | Twice the packets reports a longer elapsed time. A clock on the process start does not rise. | `test_the_double_run_reports_a_longer_elapsed_time` |
| Result | The run produced fingerprints. A processor that produced nothing reads the highest rate of all. | `test_the_run_produced_more_than_zero_fingerprints` |

#415 injected one defect for each control and read the control turn red, then restored the
file and read it turn green. The pull request of #415 holds the transcript.

## The synthetic run

The run feeds `ceiling_traffic` of `tests/test_memory_bounds.py`, so this measurement and
the memory ceiling of #279 describe the same packet run.

| Host | Python | Commit | Packets | Connections | Fingerprints | Seconds | Packets per second |
|---|---|---|---|---|---|---|---|
| this laptop | 3.14.3 | `be91cc4` | 1000000 | 100000 | 400000 | 498.39 | 2006 |

The laptop is an Apple silicon host that reports `macOS-26.6.1-arm64-arm-64bit-Mach-O`.

**The measurement ran beside a mutation sweep, so read the rate as a lower bound.** The
load average read 8.88 before the run and 12.78 after it, on a ten-core host. A quiet host
reads a higher rate.

**The one-million-packet synthetic run has one host only, and the reason is the host.**
`bigboy` is the Linux host of #410. It is shared: it carries an Elasticsearch node and
continuous-integration runners, and #410 already spent a memory ceiling run on it. The
project manager decided on 2026-08-09 that the capture run alone goes there. **No Linux
figure for the synthetic run exists, and this page claims none.**

## The capture run

Each row states one capture on one host. The run reads each capture once, and one
processor reads one capture. A processor shared across captures would carry the state of
an earlier capture into a later one.

**The set is every capture under `tests/foxio_vectors/`.** #415 read the directory against
`tests/foxio_vector_manifest.json`, and the two hold the same 38 names. The manifest is
therefore complete, and the two counts agree.

| Host | Python | Commit | Captures | Packets | Fingerprints | Seconds | Packets per second |
|---|---|---|---|---|---|---|---|
| `bigboy` | 3.12.7 | `be91cc4` | 38 | 9062 | 777 | 4.881 | 1857 |
| this laptop | 3.14.3 | `be91cc4` | 38 | 9062 | 777 | 4.152 | 2183 |

**The two hosts read the same 9062 packets and produced the same 777 fingerprints.** The
elapsed time differs and the result does not. That is the result a throughput measurement
must show.

`bigboy` reports `Linux-6.11.0-29-generic-x86_64-with-glibc2.40`. Its load average read
1.79 before the run and 1.90 after it.

### One row for each capture

| Capture | Host | Python | Commit | Packets | Fingerprints | Seconds | Packets per second |
|---|---|---|---|---|---|---|---|
| `CVE-2018-6794.pcap` | bigboy | 3.12.7 | `be91cc4` | 33 | 14 | 0.0137 | 2413 |
| `CVE-2018-6794.pcap` | this laptop | 3.14.3 | `be91cc4` | 33 | 14 | 0.0095 | 3465 |
| `alpn-condition.pcap` | bigboy | 3.12.7 | `be91cc4` | 7 | 7 | 0.0046 | 1513 |
| `alpn-condition.pcap` | this laptop | 3.14.3 | `be91cc4` | 7 | 7 | 0.0029 | 2414 |
| `badcurveball.pcap` | bigboy | 3.12.7 | `be91cc4` | 12 | 8 | 0.0055 | 2196 |
| `badcurveball.pcap` | this laptop | 3.14.3 | `be91cc4` | 12 | 8 | 0.0042 | 2889 |
| `browsers-x509.pcapng` | bigboy | 3.12.7 | `be91cc4` | 179 | 24 | 0.0848 | 2112 |
| `browsers-x509.pcapng` | this laptop | 3.14.3 | `be91cc4` | 179 | 24 | 0.0582 | 3076 |
| `chrome-cloudflare-quic-with-secrets.pcapng` | bigboy | 3.12.7 | `be91cc4` | 83 | 11 | 0.0381 | 2181 |
| `chrome-cloudflare-quic-with-secrets.pcapng` | this laptop | 3.14.3 | `be91cc4` | 83 | 11 | 0.0283 | 2938 |
| `dhcp.pcapng` | bigboy | 3.12.7 | `be91cc4` | 4 | 4 | 0.0055 | 732 |
| `dhcp.pcapng` | this laptop | 3.14.3 | `be91cc4` | 4 | 4 | 0.0027 | 1507 |
| `dhcpv6.pcap` | bigboy | 3.12.7 | `be91cc4` | 12 | 6 | 0.0049 | 2440 |
| `dhcpv6.pcap` | this laptop | 3.14.3 | `be91cc4` | 12 | 6 | 0.0026 | 4560 |
| `gre-erspan-vxlan.pcap` | bigboy | 3.12.7 | `be91cc4` | 7 | 4 | 0.0058 | 1200 |
| `gre-erspan-vxlan.pcap` | this laptop | 3.14.3 | `be91cc4` | 7 | 4 | 0.0034 | 2076 |
| `gre-sample.pcap` | bigboy | 3.12.7 | `be91cc4` | 40 | 6 | 0.0178 | 2247 |
| `gre-sample.pcap` | this laptop | 3.14.3 | `be91cc4` | 40 | 6 | 0.0134 | 2992 |
| `http-empty-useragent.pcap` | bigboy | 3.12.7 | `be91cc4` | 16 | 7 | 0.0059 | 2721 |
| `http-empty-useragent.pcap` | this laptop | 3.14.3 | `be91cc4` | 16 | 7 | 0.0038 | 4205 |
| `http1-with-cookies.pcapng` | bigboy | 3.12.7 | `be91cc4` | 12 | 6 | 0.0051 | 2331 |
| `http1-with-cookies.pcapng` | this laptop | 3.14.3 | `be91cc4` | 12 | 6 | 0.0031 | 3818 |
| `http1.pcapng` | bigboy | 3.12.7 | `be91cc4` | 184 | 56 | 0.2440 | 754 |
| `http1.pcapng` | this laptop | 3.14.3 | `be91cc4` | 184 | 56 | 0.1816 | 1013 |
| `http2-with-cookies.pcapng` | bigboy | 3.12.7 | `be91cc4` | 1607 | 7 | 1.3336 | 1205 |
| `http2-with-cookies.pcapng` | this laptop | 3.14.3 | `be91cc4` | 1607 | 7 | 1.1714 | 1372 |
| `https-connect.pcap` | bigboy | 3.12.7 | `be91cc4` | 18 | 8 | 0.0064 | 2798 |
| `https-connect.pcap` | this laptop | 3.14.3 | `be91cc4` | 18 | 8 | 0.0049 | 3662 |
| `https3-301-get.pcap` | bigboy | 3.12.7 | `be91cc4` | 23 | 8 | 0.0075 | 3068 |
| `https3-301-get.pcap` | this laptop | 3.14.3 | `be91cc4` | 23 | 8 | 0.0056 | 4139 |
| `ipv6.pcapng` | bigboy | 3.12.7 | `be91cc4` | 9 | 8 | 0.0036 | 2508 |
| `ipv6.pcapng` | this laptop | 3.14.3 | `be91cc4` | 9 | 8 | 0.0030 | 3021 |
| `latest.pcapng` | bigboy | 3.12.7 | `be91cc4` | 209 | 44 | 0.0691 | 3025 |
| `latest.pcapng` | this laptop | 3.14.3 | `be91cc4` | 209 | 44 | 0.0666 | 3140 |
| `macos_tcp_flags.pcap` | bigboy | 3.12.7 | `be91cc4` | 43 | 7 | 0.0187 | 2302 |
| `macos_tcp_flags.pcap` | this laptop | 3.14.3 | `be91cc4` | 43 | 7 | 0.0162 | 2655 |
| `quic-tls-handshake.pcapng` | bigboy | 3.12.7 | `be91cc4` | 1 | 1 | 0.0006 | 1619 |
| `quic-tls-handshake.pcapng` | this laptop | 3.14.3 | `be91cc4` | 1 | 1 | 0.0005 | 2145 |
| `quic-with-several-tls-frames.pcapng` | bigboy | 3.12.7 | `be91cc4` | 1 | 1 | 0.0006 | 1646 |
| `quic-with-several-tls-frames.pcapng` | this laptop | 3.14.3 | `be91cc4` | 1 | 1 | 0.0004 | 2602 |
| `single-packets.pcap` | bigboy | 3.12.7 | `be91cc4` | 9 | 8 | 0.0072 | 1246 |
| `single-packets.pcap` | this laptop | 3.14.3 | `be91cc4` | 9 | 8 | 0.0338 | 266 |
| `socks-https-example.pcap` | bigboy | 3.12.7 | `be91cc4` | 93 | 24 | 0.0357 | 2606 |
| `socks-https-example.pcap` | this laptop | 3.14.3 | `be91cc4` | 93 | 24 | 0.0293 | 3178 |
| `socks4-https.pcap` | bigboy | 3.12.7 | `be91cc4` | 16 | 7 | 0.0076 | 2110 |
| `socks4-https.pcap` | this laptop | 3.14.3 | `be91cc4` | 16 | 7 | 0.0048 | 3344 |
| `ssh-r.pcap` | bigboy | 3.12.7 | `be91cc4` | 1852 | 23 | 0.8969 | 2065 |
| `ssh-r.pcap` | this laptop | 3.14.3 | `be91cc4` | 1852 | 23 | 0.7342 | 2522 |
| `ssh-scp-1050.pcap` | bigboy | 3.12.7 | `be91cc4` | 1000 | 9 | 0.7348 | 1361 |
| `ssh-scp-1050.pcap` | this laptop | 3.14.3 | `be91cc4` | 1000 | 9 | 0.6226 | 1606 |
| `ssh.pcapng` | bigboy | 3.12.7 | `be91cc4` | 318 | 1 | 0.1485 | 2141 |
| `ssh.pcapng` | this laptop | 3.14.3 | `be91cc4` | 318 | 1 | 0.1301 | 2444 |
| `ssh2-malformed.pcap` | bigboy | 3.12.7 | `be91cc4` | 22 | 5 | 0.0081 | 2714 |
| `ssh2-malformed.pcap` | this laptop | 3.14.3 | `be91cc4` | 22 | 5 | 0.0072 | 3064 |
| `ssh2-moloch-crash.pcap` | bigboy | 3.12.7 | `be91cc4` | 22 | 5 | 0.0079 | 2769 |
| `ssh2-moloch-crash.pcap` | this laptop | 3.14.3 | `be91cc4` | 22 | 5 | 0.0075 | 2950 |
| `ssh2.pcapng` | bigboy | 3.12.7 | `be91cc4` | 1391 | 75 | 0.3924 | 3545 |
| `ssh2.pcapng` | this laptop | 3.14.3 | `be91cc4` | 1391 | 75 | 0.3886 | 3580 |
| `sshv1.pcap` | bigboy | 3.12.7 | `be91cc4` | 161 | 6 | 0.0430 | 3746 |
| `sshv1.pcap` | this laptop | 3.14.3 | `be91cc4` | 161 | 6 | 0.0364 | 4424 |
| `tcpdump-geneve.pcap` | bigboy | 3.12.7 | `be91cc4` | 39 | 5 | 0.0228 | 1713 |
| `tcpdump-geneve.pcap` | this laptop | 3.14.3 | `be91cc4` | 39 | 5 | 0.0199 | 1957 |
| `tls-alpn-h2.pcap` | bigboy | 3.12.7 | `be91cc4` | 9 | 8 | 0.0040 | 2236 |
| `tls-alpn-h2.pcap` | this laptop | 3.14.3 | `be91cc4` | 9 | 8 | 0.0030 | 3002 |
| `tls-handshake.pcapng` | bigboy | 3.12.7 | `be91cc4` | 193 | 194 | 0.1931 | 999 |
| `tls-handshake.pcapng` | this laptop | 3.14.3 | `be91cc4` | 193 | 194 | 0.1240 | 1556 |
| `tls-non-ascii-alpn.pcapng` | bigboy | 3.12.7 | `be91cc4` | 2 | 2 | 0.0022 | 904 |
| `tls-non-ascii-alpn.pcapng` | this laptop | 3.14.3 | `be91cc4` | 2 | 2 | 0.0013 | 1594 |
| `tls-sni.pcapng` | bigboy | 3.12.7 | `be91cc4` | 84 | 84 | 0.0646 | 1300 |
| `tls-sni.pcapng` | this laptop | 3.14.3 | `be91cc4` | 84 | 84 | 0.0525 | 1600 |
| `tls12.pcap` | bigboy | 3.12.7 | `be91cc4` | 1 | 1 | 0.0008 | 1177 |
| `tls12.pcap` | this laptop | 3.14.3 | `be91cc4` | 1 | 1 | 0.0005 | 2205 |
| `tls3.pcapng` | bigboy | 3.12.7 | `be91cc4` | 1189 | 77 | 0.3894 | 3053 |
| `tls3.pcapng` | this laptop | 3.14.3 | `be91cc4` | 1189 | 77 | 0.3356 | 3543 |
| `v6.pcap` | bigboy | 3.12.7 | `be91cc4` | 161 | 6 | 0.0462 | 3487 |
| `v6.pcap` | this laptop | 3.14.3 | `be91cc4` | 161 | 6 | 0.0385 | 4185 |

## What this page does not state

Two statements about throughput are not checkable. This page marks each one, and it
reports neither as true.

1. **No check tells a slow package from a slow host.** A rate is a measurement of one host
   at one moment, and this project holds no second instrument. The two hosts above differ
   in processor, in operating system and in interpreter, so the difference between their
   rates names no cause.
2. **No check states whether a rate is adequate.** Adequacy is a decision the user makes
   against a use, and `Non-goals` states no target.
