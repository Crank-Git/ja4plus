---
id: live-capture
feature: Live capture
epic: "Epic 6: Live capture"
status: issued
issues: [17, 53, 54, 55, 56, 320, 423]
mockups: []
---

## Purpose

`ja4plus live` exists. It builds ten fingerprinters, hands each packet to all of
them, and never calls `cleanup_connection`. A monitor started on a busy interface
grows until the host stops it.

`examples/monitoring_daemon.py` showed an operator what a real monitor needs. An
example is not a supported mode: nothing tested it, and nothing kept it working. #56
removed the file, and `docs/usage.md` documents the command in its place.

This feature set makes a long-running monitor a supported mode.

## User stories

- As a monitor operator, I want the monitor to run for a week without growing, so
  that I do not schedule a restart.
- As a monitor operator, I want a clean shutdown on a termination signal, so that
  my output file is complete.
- As a monitor operator, I want to see how many packets the monitor read and how
  many it dropped, so that I know whether I am losing traffic.

## Functional requirements

FR-live-capture-1 — The command `ja4plus watch <interface>` reads packets from an
interface until it is stopped.

FR-live-capture-2 — The command evicts a connection that has sent no packet for
longer than the configured age.

FR-live-capture-3 — The `--max-connections` option sets the maximum number of
tracked connections.

FR-live-capture-4 — The `--connection-timeout` option sets the maximum connection
age in seconds.

FR-live-capture-5 — The command exits cleanly when it receives `SIGINT`.

FR-live-capture-6 — The command exits cleanly when it receives `SIGTERM`.

FR-live-capture-7 — The command flushes its output before it exits.

FR-live-capture-8 — The command reports statistics on exit.

FR-live-capture-9 — The `--stats-interval` option makes the command report
statistics on a schedule.

FR-live-capture-10 — The command writes statistics to standard error.

FR-live-capture-11 — The `--bpf` option applies a capture filter.

FR-live-capture-12 — The command reports a clear error when it lacks the privilege
to open the interface.

FR-live-capture-13 — The command works on Linux and on macOS.

FR-live-capture-14 — The command `ja4plus live` remains as an alias of
`ja4plus watch`.

FR-live-capture-15 — The `dropped` field of the statistics line reports the drop
count of the capture socket the command opened.

FR-live-capture-16 — The `dropped` field reads `null` where the capture layer
reports no drop count.

## User flows

**An operator starts a monitor.**

1. The operator runs `sudo ja4plus watch eth0 --format json --output /var/log/ja4.jsonl`.
2. The command opens the interface and reports that capture started, on standard
   error.
3. The command writes one JSON object per fingerprint to the file.
4. Every 60 seconds the command writes a statistics line to standard error.

**An operator stops a monitor.**

1. The operator sends `SIGTERM`.
2. The command stops reading packets.
3. The command flushes the output file.
4. The command writes a final statistics line.
5. The command exits with status zero.

**A monitor sheds an idle connection.**

1. A connection sends packets and then stops.
2. The connection age passes the configured timeout.
3. The next eviction pass removes its state from every fingerprinter.
4. The tracked-connection count falls.

## Screens & states

| Screen | Purpose | States |
|---|---|---|
| Statistics line | Tell the operator what the monitor is doing. | Starting; running; at capacity; stopping. |
| Error message | Tell the operator why the monitor did not start. | No privilege; unknown interface; invalid filter. |

The statistics line, written to standard error:

```
[ja4plus] packets=1284302 fingerprints=48211 connections=8134 evicted=112094 dropped=0 uptime=3600s
```

## Behaviour rules

- The command builds one `Processor`. It does not build fingerprinters itself.
- The command owns the connection table. It records the last-seen time per
  connection and calls `Processor.cleanup_connection` on eviction.
- Eviction runs on packet arrival. The command starts no timer thread for
  eviction.
- The statistics thread is the only thread the command starts, and it starts only
  when `--stats-interval` is passed.
- A signal handler sets a flag. It does not call `sys.exit`, because a signal may
  arrive while the output buffer is half written.
- The command reads the flag after each packet and after each poll interval, so an
  interface that carries no traffic stops the monitor within one second of the signal.
- The command opens the capture socket and holds it open across the `sniff` calls, so
  it loses no packet between two calls.
- The privilege check uses a failed capture attempt, not `os.geteuid`. A Linux host
  may grant the capability without granting the user identity zero.
- The drop count comes from the capture socket where the capture layer reports one,
  and the field reads `null` where it reports none.
- The default connection timeout is 300 seconds. The default maximum connection
  count is 10000. These match the library defaults.

## Data touched

- Changed file `ja4plus/cli.py`.
- New file `ja4plus/watch.py`, holding the monitor loop and the connection table.
- Removed file `examples/monitoring_daemon.py`, replaced by documentation of the
  supported command.
- New file `tests/test_watch.py`.
- New file `tests/test_watch_stop.py`, holding the stop on an interface that carries no
  traffic.
- New file `tests/test_watch_drop_count.py`, holding the drop count of the capture
  socket.

## Interfaces

The monitor reads packets through `scapy`. Four entry points matter.

| What | Call | Note |
|---|---|---|
| Open the socket | `resolve_iface(name).l2listen()(type=ETH_P_ALL, iface=name, filter=...)` | The command opens the socket, in the order `AsyncSniffer._run` holds. `libpcap` compiles the filter here. |
| Read from an interface | `scapy.all.sniff(prn=..., store=0, opened_socket=..., timeout=...)` | `store=0` is required. Without it `scapy` keeps every packet. |
| Stop reading | `sniff(stop_filter=...)`, and the loop that reads the flag | The stop filter reads the flag after a packet. The loop reads it after each timeout, because `scapy` applies the filter to a packet and to nothing else. |
| List the interfaces | `scapy.all.get_if_list()` | The call needs no privilege, so an error message reads the list. |

`AsyncSniffer._run` closes the sockets it opened itself and no other socket, so a socket
the command opened stays open across the `sniff` calls and the host buffer holds every
packet that arrives between two calls. #320 records the reading.

Verified against: https://scapy.readthedocs.io/en/latest/api/scapy.sendrecv.html
(scapy 2.6, retrieved 2026-08-06). The `opened_socket` reading comes from `scapy` 2.7.0,
at `scapy/sendrecv.py:1268`, `scapy/sendrecv.py:1331` and `scapy/sendrecv.py:1391`, read
on 2026-08-08.

Opening a capture interface needs elevated privileges. On Linux the capability is
`CAP_NET_RAW`. On macOS the operator needs read access to the `/dev/bpf*` devices.

`scapy` 2.7.0 reports three failures, and each one carries its own class and text. #56
records the four line numbers.

| Failure | Class | Text | Source |
|---|---|---|---|
| The host refuses the `/dev/bpf` device. | `Scapy_Exception` | `Permission denied: could not open /dev/bpf0. ...` | `scapy/arch/bpf/core.py:59` |
| The host holds no such interface. | `ValueError` | `Interface 'nosuchif0' not found !` | `scapy/interfaces.py:434` |
| `libpcap` refuses the filter. | `Scapy_Exception` | `Failed to compile filter expression tcp port (-1)` | `scapy/arch/common.py:129` |
| A socket wraps the filter failure. | `Scapy_Exception` | `Cannot set filter: ...` | `scapy/arch/bpf/supersocket.py:218` and `scapy/arch/linux/__init__.py:232` |

The Linux socket calls raise `OSError` and `scapy` wraps neither. `EPERM` and `EACCES`
name a refused privilege, and `ENODEV` names an interface the host does not hold.

## Edge cases & failures

| Case | What happens |
|---|---|
| The operator lacks the capture privilege. | The command exits with status 1 and names the privilege the host needs. |
| The named interface does not exist. | The command exits with status 1 and lists the interfaces it found. |
| The capture filter is invalid. | The command exits with status 1 and reports the filter error. |
| The output file cannot be opened. | The command exits with status 1 before it opens the interface. |
| The connection table reaches its maximum. | The least recently used connection is evicted, and the eviction count rises. |
| `SIGTERM` arrives while a line is half written. | The handler sets the flag. The loop finishes the line, then exits. |
| The interface produces no traffic. | The command reports statistics with zero counts and keeps waiting. |
| `SIGTERM` arrives while the interface produces no traffic. | The loop reads the flag after the poll interval, and the command exits within one second. |
| A packet arrives as one poll interval expires. | The host buffers it on the open socket, and the next `sniff` call reports it. |
| The disk fills while writing the output file. | The command reports the error on standard error and exits with status 1. |
| The command runs on Windows. | The command reports that Windows is not supported and exits with status 1. |

## Acceptance criteria

- [ ] `ja4plus watch --help` documents every option this feature lists.
- [ ] A test that feeds packets through the monitor loop for 100000 packets across
      50000 connections holds the tracked-connection count at or below
      `--max-connections`.
- [ ] A connection that stops sending is absent from the connection table after
      `--connection-timeout` seconds of capture time.
- [ ] Sending `SIGTERM` to the monitor produces exit status zero.
- [ ] A monitor on an interface that carries no traffic exits within one second of
      `SIGTERM`.
- [ ] The monitor loses no packet that arrives at the boundary of two `sniff` calls.
- [ ] The output file written before `SIGTERM` holds every fingerprint the monitor
      reported.
- [ ] The final statistics line reports the packet count, the fingerprint count,
      the connection count and the eviction count.
- [ ] `--stats-interval 1` writes a statistics line every second.
- [ ] A monitor on macOS reports a whole number in the `dropped` field, read from a
      real capture socket of the host.
- [ ] The `dropped` field reads `null` where the capture layer reports no drop count.
- [ ] Running without capture privilege exits with status 1 and names the required
      privilege.
- [ ] Naming a nonexistent interface exits with status 1 and lists the available
      interfaces.
- [ ] `ja4plus live eth0` behaves the same as `ja4plus watch eth0`.
- [ ] `examples/monitoring_daemon.py` is absent, and the documentation covers the
      command instead.

## Out of scope

- Windows support.
- Reading from a capture interface without elevated privileges.
- Delivery to a remote collector.
- A packet-per-second rate limit.
- Multi-process sharding. The library gives the operator `get_shard_key`, and the
  operator builds the topology.

## Open questions

- Whether `scapy` reports a drop count on Linux. On Linux `scapy` defines
  `PACKET_STATISTICS = 6` at `scapy/arch/linux/__init__.py:95` and calls `getsockopt`
  with that option nowhere, so the field reads `null` there. That is a reading of the
  `scapy` source, and no Linux host ran it. #326 owns the Linux measurement.

## The macOS drop count

**#423 closed the macOS half of the question above, and it took the reading from a real
capture socket of the development host.** The `dropped` field holds a whole number on
macOS.

`open_capture_socket` opens an `_L2bpfSocket`, `read_interface` attaches that socket to a
`CaptureDropCount`, and `MonitorStats` calls that object for each statistics line.
`_L2bpfSocket.get_stats` reads the `BIOCGSTATS` ioctl at
`scapy/arch/bpf/supersocket.py:297`, and it returns the received count and the drop
count. `AsyncSniffer._run` holds the socket it opens in a local name at
`scapy/sendrecv.py:1205`, so a caller reaches the socket through the `opened_socket`
argument alone.

**The `BIOCGSTATS` ioctl resets neither counter**, so the monitor reports the count of
the socket and it accumulates nothing. Two reads of one socket returned 29910 drops and
then 59910 drops.

**A count of 0 on a clean capture proves nothing**, because a field no code writes reads
the same way. `tests/test_watch_drop_count.py` therefore fills the kernel buffer of a
real capture socket and reads a count above zero.

The measurements ran on macOS 26.6.1, build 25G76, against `scapy` 2.7.0, on 2026-08-10.
**Where no `/dev/bpf` node opens, each live case of that file skips and none of them
passes.**
