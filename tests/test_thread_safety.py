"""The concurrency contract of `Processor`, FR-concurrency-safety-1 to -6.

Every case here forces the race it measures. A case that starts several threads and
hopes for an interleaving measures nothing: #42 reported 0 failures out of 30 runs both
with and without its lock before it was replaced. Each forced case below holds one
thread inside the guarded section with an `threading.Event`, so a run against unguarded
code fails every time.

`docs/specs/features/03-concurrency-safety.md` states the requirements.
"""

import os
import threading
import time
import types
from pathlib import Path

import pytest
from scapy.all import IP, TCP, Ether, rdpcap

from ja4plus.fingerprinters import base
from ja4plus.fingerprinters.base import NULL_LOCK, BaseFingerprinter, NullLock
from ja4plus.fingerprinters.ja4l import JA4LFingerprinter
from ja4plus.fingerprinters.ja4ts import JA4TSFingerprinter
from ja4plus.processor import Processor

VECTORS = Path(__file__).parent / "foxio_vectors"

# The soak capture. It holds 209 packets over several connections, and one pass costs
# well under a second, so the case repeats the whole experiment many times.
SOAK_CAPTURE = "latest.pcapng"

# The window capture. JA4SSH emits one value for every 200 SSH packets, so this capture
# measures a method that holds state across many packets.
WINDOW_CAPTURE = "ssh2.pcapng"

# The captures the contract cases replay. The five carry TCP, TLS, HTTP, SSH, X.509 and
# QUIC traffic, and together they hold 2047 packets and 309 values.
CONTRACT_CAPTURES = [
    "latest.pcapng",
    "ssh2.pcapng",
    "browsers-x509.pcapng",
    "http1.pcapng",
    "tls-sni.pcapng",
]

# The seconds the soak case runs. The acceptance criterion of #40 states 60 seconds, and
# a 60-second case in the unit suite costs every later run of that suite. The default
# holds the case cheap, and the pull request records one run at 60.
SOAK_SECONDS = float(os.environ.get("JA4PLUS_THREAD_SOAK_SECONDS", "2.0"))

THREAD_COUNT = 8

# The seconds a case waits for a thread. A case that hangs reports nothing, so every
# wait states a limit.
JOIN_TIMEOUT = 60


@pytest.fixture(scope="module")
def soak_packets():
    """Return the packets of the soak capture."""
    return list(rdpcap(str(VECTORS / SOAK_CAPTURE)))


@pytest.fixture(scope="module")
def window_packets():
    """Return the packets of the JA4SSH window capture."""
    return list(rdpcap(str(VECTORS / WINDOW_CAPTURE)))


def one_thread_values(packets):
    """Return every fingerprint one thread produces from the packets, sorted."""
    processor = Processor()
    values = []
    for packet in packets:
        values.extend(result.fingerprint for result in processor.process_packet(packet))
    values.extend(result["fingerprint"] for result in processor.close_open_windows())
    return sorted(values)


def eight_thread_values(packets, partition_by_connection=True):
    """Return every fingerprint eight threads produce from the packets, and any error.

    Args:
        packets: The packets to feed.
        partition_by_connection: True sends every packet of one connection to one
            thread, which is the arrangement `get_shard_key` exists for. False sends
            the packets round-robin, which puts two threads on one connection.

    Returns:
        A tuple of the sorted fingerprint list and the list of exceptions the threads
        raised.
    """
    processor = Processor()
    buckets = [[] for _ in range(THREAD_COUNT)]
    for index, packet in enumerate(packets):
        if partition_by_connection:
            buckets[hash(processor.get_shard_key(packet)) % THREAD_COUNT].append(packet)
        else:
            buckets[index % THREAD_COUNT].append(packet)

    values = []
    errors = []
    collect = threading.Lock()

    def feed(bucket):
        mine = []
        try:
            for packet in bucket:
                mine.extend(result.fingerprint for result in processor.process_packet(packet))
        except Exception as error:  # noqa: BLE001 — the case reports every failure shape.
            errors.append(error)
        with collect:
            values.extend(mine)

    threads = [threading.Thread(target=feed, args=(bucket,)) for bucket in buckets]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(JOIN_TIMEOUT)
    values.extend(result["fingerprint"] for result in processor.close_open_windows())
    return sorted(values), errors


def read_capture(name):
    """Return the packets of one capture. Each call reads the file again.

    A caller that moves a packet timestamp changes the packet object, so a cached list
    would carry that change into the next case.
    """
    return list(rdpcap(str(VECTORS / name)))


def concatenate(names, one_timeline):
    """Return the packets of several captures, in the order the names state.

    The five captures were recorded across 183 days, so a concatenation of them jumps
    the packet timestamp by months. `BoundedStateTable` evicts on the timestamp of the
    most recent packet, so that jump ages out entries the next capture still needs.

    Args:
        names: The capture file names, in the order to read them.
        one_timeline: True moves each capture so that it starts one second after the
            capture before it, which gives the whole list one timeline. False holds the
            timestamp each capture carries.

    Returns:
        A list of packets.
    """
    packets = []
    offset = 0.0
    for name in names:
        block = read_capture(name)
        if one_timeline:
            base = min(float(packet.time) for packet in block)
            for packet in block:
                packet.time = float(packet.time) - base + offset
            offset = max(float(packet.time) for packet in block) + 1.0
        packets.extend(block)
    return packets


def handshake(client_ip, client_port, server_ip="10.0.0.1", server_port=443, start=1000.0):
    """Return the three packets of one TCP handshake, with capture timestamps.

    JA4L reports `JA4L-S` on the SYN-ACK packet and `JA4L-C` on the ACK packet, so this
    handshake drives both halves of the JA4L state.

    Args:
        client_ip: The client address.
        client_port: The client port.
        server_ip: The server address.
        server_port: The server port.
        start: The capture timestamp of the SYN packet, in seconds.

    Returns:
        A list of the SYN, the SYN-ACK and the ACK packet, in that order.
    """
    syn = (
        Ether()
        / IP(src=client_ip, dst=server_ip, ttl=64)
        / TCP(sport=client_port, dport=server_port, flags="S", seq=1000)
    )
    syn.time = start
    syn_ack = (
        Ether()
        / IP(src=server_ip, dst=client_ip, ttl=128)
        / TCP(sport=server_port, dport=client_port, flags="SA", seq=5000, ack=1001)
    )
    syn_ack.time = start + 0.010
    ack = (
        Ether()
        / IP(src=client_ip, dst=server_ip, ttl=64)
        / TCP(sport=client_port, dport=server_port, flags="A", seq=1001, ack=5001)
    )
    ack.time = start + 0.020
    return [syn, syn_ack, ack]


class BlockingList(list):
    """A list that holds the first callers of `append` until the case releases them.

    The case uses it to stop one thread inside `JA4LFingerprinter.process_packet`,
    between the read of `len(self.fingerprints)` and the append that follows it.
    """

    def __init__(self, items=()):
        super().__init__(items)
        self.entered = threading.Event()
        self.release = threading.Event()

    def append(self, item):
        self.entered.set()
        self.release.wait(timeout=JOIN_TIMEOUT)
        super().append(item)


class FailOnAcquire:
    """A lock that raises when a caller acquires it.

    `threading.RLock` returns this object while a case holds `threading` replaced, so a
    processor that acquires a lock fails and a processor that acquires none does not.
    """

    def acquire(self, *args, **kwargs):
        raise AssertionError("the fingerprinter acquired a lock")

    def release(self):
        raise AssertionError("the fingerprinter released a lock")

    __enter__ = acquire

    def __exit__(self, exc_type, exc_value, traceback):
        return False


class OverlapProbe:
    """Count the threads that run inside one guarded region at the same time.

    The probe parks the first caller and records the highest count it sees. A region
    that one lock guards reports 1, and an unguarded region reports 2.
    """

    def __init__(self):
        self.inside = 0
        self.peak = 0
        self.entered = threading.Event()
        self.release = threading.Event()
        self._parked = False
        self._guard = threading.Lock()

    def wrap(self, real):
        """Return a callable that counts its callers and then calls `real`."""

        def probe(*args, **kwargs):
            with self._guard:
                self.inside += 1
                self.peak = max(self.peak, self.inside)
                park = not self._parked
                self._parked = True
            if park:
                self.entered.set()
                self.release.wait(timeout=JOIN_TIMEOUT)
            try:
                return real(*args, **kwargs)
            finally:
                with self._guard:
                    self.inside -= 1

        return probe


def hook_state_table(attribute):
    """Return an installer that probes `on_packet` of one state table."""

    def install(fingerprinter, probe):
        table = fingerprinter
        for step in attribute.split("."):
            table = getattr(table, step)
        table.on_packet = probe.wrap(table.on_packet)

    return install


def hook_value_list(fingerprinter, probe):
    """Probe the append that a fingerprinter runs inside its guarded region."""

    class ProbedList(list):
        append = probe.wrap(list.append)

    fingerprinter.fingerprints = ProbedList(fingerprinter.fingerprints)


# One row for each fingerprinter that holds a lock of its own. The packet index names a
# packet of `latest.pcapng` that reaches the guarded region of that fingerprinter, and
# the hook names one callable that region runs. `tests/foxio_vectors/latest.pcapng`
# carries TCP, TLS, HTTP and QUIC traffic, so one capture reaches all seven.
GUARDED_REGIONS = [
    ("ja4", 9, hook_value_list),
    ("ja4s", 2, hook_state_table("_quic_dcids")),
    ("ja4h", 9, hook_state_table("consumed_seq")),
    ("ja4l", 0, hook_state_table("connections")),
    ("ja4x", 9, hook_state_table("processed_certs")),
    ("ja4ssh", 0, hook_state_table("connections")),
    ("ja4ts", 7, hook_state_table("syn_ack_times.times")),
]


class TestOneFingerprinterAdmitsOneThread:
    """Each fingerprinter guards its own state, and a direct caller reads that guard.

    `Processor.process_packet` holds the lock of a fingerprinter across every call it
    makes, so a case that goes through the processor measures the processor and not the
    fingerprinter. Each case here calls `process_packet` on the fingerprinter itself,
    which is how a caller that builds one fingerprinter uses it.
    """

    @pytest.mark.parametrize("name, packet_index, install", GUARDED_REGIONS)
    def test_a_second_thread_waits_at_the_guarded_region(
        self, name, packet_index, install, soak_packets
    ):
        fingerprinter = Processor().fingerprinters[name]
        packet = soak_packets[packet_index]
        probe = OverlapProbe()
        install(fingerprinter, probe)

        def feed():
            fingerprinter.process_packet(packet)

        first = threading.Thread(target=feed)
        first.start()
        assert probe.entered.wait(timeout=JOIN_TIMEOUT), f"{name} never reached its region"

        second = threading.Thread(target=feed)
        second.start()
        # The second thread now runs against a fingerprinter whose first thread sits
        # inside the guarded region. It waits for the lock for this whole interval.
        time.sleep(0.25)
        release_peak = probe.peak
        probe.release.set()

        first.join(JOIN_TIMEOUT)
        second.join(JOIN_TIMEOUT)

        assert release_peak == 1, f"{name} admitted {release_peak} threads at once"


class TestTheThreadSafeArgument:
    """`Processor.__init__` accepts the argument, FR-concurrency-safety-1 and -2."""

    def test_the_processor_accepts_a_thread_safe_argument(self):
        assert Processor(thread_safe=True).thread_safe is True
        assert Processor(thread_safe=False).thread_safe is False

    def test_the_thread_safe_argument_defaults_to_true(self):
        assert Processor().thread_safe is True

    def test_the_processor_passes_thread_safe_to_every_fingerprinter(self):
        """Every one of the ten fingerprinters reads the value, FR-concurrency-safety-6."""
        processor = Processor(thread_safe=False)
        assert len(processor.fingerprinters) == 10
        for name, fingerprinter in processor.fingerprinters.items():
            assert fingerprinter.thread_safe is False, name
            assert isinstance(fingerprinter.lock, NullLock), name

        processor = Processor()
        assert len(processor.fingerprinters) == 10
        for name, fingerprinter in processor.fingerprinters.items():
            assert fingerprinter.thread_safe is True, name
            assert isinstance(fingerprinter.lock, type(threading.RLock())), name

    def test_each_fingerprinter_holds_its_own_lock(self):
        """Ten locks let ten threads work at once on ten methods."""
        processor = Processor()
        locks = [id(fingerprinter.lock) for fingerprinter in processor.fingerprinters.values()]
        assert len(set(locks)) == 10

    def test_the_lock_admits_the_thread_that_already_holds_it(self):
        """`process_packet` holds the lock and calls `add_fingerprint`, which holds it."""
        fingerprinter = BaseFingerprinter()
        with fingerprinter.lock:
            with fingerprinter.lock:
                assert True

    def test_the_null_lock_admits_every_caller(self):
        with NULL_LOCK:
            with NULL_LOCK:
                assert repr(NULL_LOCK) == "NullLock()"


class TestTheProcessorAcquiresNoLockWhenThreadSafeIsFalse:
    """`thread_safe=False` acquires no lock, FR-concurrency-safety-5.

    The pair of cases below replaces `threading.RLock` with a class whose instance
    raises when a caller acquires it. The first case proves the promise. The second is
    the control that proves the first case can fail.
    """

    @staticmethod
    def failing_rlock(monkeypatch):
        """Make `base.threading.RLock` return an object that fails when acquired.

        The patch replaces the name `threading` inside `ja4plus.fingerprinters.base`
        alone, so the real `threading` module keeps its own `RLock` for every other
        thread in the process.
        """
        monkeypatch.setattr(base, "threading", types.SimpleNamespace(RLock=FailOnAcquire))

    def test_a_processor_that_promises_one_thread_acquires_no_lock(self, monkeypatch, soak_packets):
        self.failing_rlock(monkeypatch)
        processor = Processor(thread_safe=False)
        for packet in soak_packets:
            processor.process_packet(packet)
        processor.close_open_windows()
        processor.reset()
        processor.cleanup_connection("10.0.0.2", 40000, "10.0.0.1", 443, "tcp")

    def test_a_thread_safe_processor_acquires_the_lock(self, monkeypatch, soak_packets):
        """The control. It proves the case above measures the lock and not nothing."""
        self.failing_rlock(monkeypatch)
        processor = Processor(thread_safe=True)
        with pytest.raises(AssertionError, match="the fingerprinter acquired a lock"):
            for packet in soak_packets:
                processor.process_packet(packet)


class TestEightThreadsFeedingOneProcessor:
    """Eight threads share one processor, FR-concurrency-safety-3."""

    def test_eight_threads_produce_the_fingerprints_one_thread_produces(self, soak_packets):
        """The soak case. Every repetition matches the single-thread result exactly.

        Each thread owns whole connections, which is the arrangement `get_shard_key`
        exists for. The state of one connection then advances in capture order, and the
        result is comparable against one thread.
        """
        expected = one_thread_values(soak_packets)
        assert expected, "the capture produced no fingerprint, so the case cannot fail"

        rounds = 0
        deadline = time.monotonic() + SOAK_SECONDS
        while time.monotonic() < deadline:
            values, errors = eight_thread_values(soak_packets)
            rounds += 1
            assert errors == [], f"round {rounds} raised {errors!r}"
            assert values == expected, f"round {rounds} produced a different fingerprint list"
        assert rounds >= 1

    def test_eight_threads_produce_the_window_values_one_thread_produces(self, window_packets):
        """JA4SSH holds a window across 200 packets, and the window survives the threads."""
        expected = one_thread_values(window_packets)
        assert expected
        values, errors = eight_thread_values(window_packets)
        assert errors == []
        assert values == expected

    def test_eight_threads_on_one_connection_raise_no_exception(self, soak_packets, caplog):
        """Round-robin puts two threads inside one connection, and nothing raises.

        The processor logs a fingerprinter failure at DEBUG and returns, so an exception
        never reaches the caller. The case reads the log for that reason. A case that
        asserted on the return value alone could not fail.
        """
        with caplog.at_level("DEBUG", logger="ja4plus.processor"):
            _, errors = eight_thread_values(soak_packets, partition_by_connection=False)
        assert errors == []
        failures = [record.message for record in caplog.records if "failed" in record.message]
        assert failures == [], f"a fingerprinter raised: {failures[:5]}"


class TestTheProcessorPairsEachRawFormWithItsOwnFingerprint:
    """The processor reads `last_raw` after the call that writes it.

    The read and the call form one operation, so `Processor.process_packet` holds the
    lock of the fingerprinter across both. A second thread that runs between the two
    replaces `last_raw`, and the caller then receives the raw form of another packet
    beside this fingerprint.
    """

    # The two packets of `latest.pcapng` that carry a TLS ClientHello with a different
    # JA4 value. Packet 9 reports `t13d1516h2` and packet 74 reports `t12d190800`.
    FIRST = 9
    SECOND = 74

    def test_a_second_thread_replaces_no_raw_form_of_the_first(self, soak_packets):
        first = soak_packets[self.FIRST]
        second = soak_packets[self.SECOND]

        expected = {}
        for packet in (first, second):
            alone = Processor()
            results = [r for r in alone.process_packet(packet) if r.type == "ja4"]
            assert len(results) == 1, "the packet produced no JA4 value, so nothing measures"
            expected[id(packet)] = (results[0].fingerprint, results[0].raw)
        assert expected[id(first)] != expected[id(second)], "the two packets must differ"

        processor = Processor()
        fingerprinter = processor.fingerprinters["ja4"]
        real_process_packet = fingerprinter.process_packet
        entered = threading.Event()
        release = threading.Event()

        def blocking_process_packet(packet):
            # The real method returns and releases the lock of the fingerprinter. The
            # processor reads `last_raw` after this point, so a thread parked here
            # measures whether the processor still holds that lock.
            value = real_process_packet(packet)
            if packet is first:
                entered.set()
                release.wait(timeout=JOIN_TIMEOUT)
            return value

        fingerprinter.process_packet = blocking_process_packet
        collected = {}

        def feed(name, packet):
            collected[name] = [r for r in processor.process_packet(packet) if r.type == "ja4"]

        try:
            slow = threading.Thread(target=feed, args=("first", first))
            slow.start()
            assert entered.wait(timeout=JOIN_TIMEOUT), "the first thread never parked"

            fast = threading.Thread(target=feed, args=("second", second))
            fast.start()
            # The second thread now runs against a processor whose first thread sits
            # past the fingerprinter call. It waits for the lock for this whole interval.
            time.sleep(0.25)
            release.set()

            slow.join(JOIN_TIMEOUT)
            fast.join(JOIN_TIMEOUT)
        finally:
            del fingerprinter.process_packet

        assert len(collected["first"]) == 1
        got = (collected["first"][0].fingerprint, collected["first"][0].raw)
        assert got == expected[id(first)], (
            "the first thread received the raw form of another packet"
        )


class TestResetWhileEightThreadsProcessPackets:
    """`reset` corrupts no state table another thread reads, FR-concurrency-safety-4."""

    def test_reset_beside_eight_threads_raises_no_exception(self, soak_packets, caplog):
        """One thread resets while eight feed packets, and no fingerprinter raises.

        The case reads the log, because `Processor.process_packet` catches every
        exception a fingerprinter raises and logs it at DEBUG.
        """
        processor = Processor()
        stop = threading.Event()
        errors = []

        def feed():
            try:
                while not stop.is_set():
                    for packet in soak_packets:
                        processor.process_packet(packet)
                        if stop.is_set():
                            return
            except Exception as error:  # noqa: BLE001
                errors.append(error)

        def clear():
            try:
                while not stop.is_set():
                    processor.reset()
                    time.sleep(0.001)
            except Exception as error:  # noqa: BLE001
                errors.append(error)

        with caplog.at_level("DEBUG", logger="ja4plus.processor"):
            threads = [threading.Thread(target=feed) for _ in range(THREAD_COUNT)]
            threads.append(threading.Thread(target=clear))
            for thread in threads:
                thread.start()
            time.sleep(1.0)
            stop.set()
            for thread in threads:
                thread.join(JOIN_TIMEOUT)

        assert errors == []
        failures = [record.message for record in caplog.records if "failed" in record.message]
        assert failures == [], f"a fingerprinter raised: {failures[:5]}"

    def test_reset_waits_for_the_thread_that_writes_a_stored_index(self):
        """The forced case. `reset` cannot empty the list a writer already indexed.

        `ja4l.py` stores the position of the client entry of a connection and overwrites
        that position on a later packet. `reset` rebinds `self.fingerprints` to an empty
        list, so a `reset` between the read of the index and the write raises
        `IndexError`. The case holds the writer between the two with an `Event`.
        """
        fingerprinter = JA4LFingerprinter()
        for packet in handshake("10.0.0.2", 40000):
            fingerprinter.process_packet(packet)
        assert fingerprinter.connections.values()[0]["client_entry"] == 1

        # The SYN and the SYN-ACK of the second handshake run before the patch. Each of
        # the two calls `packet_endpoints` and neither reads the stored index, so a
        # writer parked on one of them measures nothing.
        second_handshake = handshake("10.0.0.2", 40000, start=1002.0)
        for packet in second_handshake[:2]:
            fingerprinter.process_packet(packet)

        entered = threading.Event()
        release = threading.Event()
        real_endpoints = ja4l_packet_endpoints()

        def blocking_endpoints(packet):
            entered.set()
            release.wait(timeout=JOIN_TIMEOUT)
            return real_endpoints(packet)

        errors = []

        def write():
            try:
                # The ACK reports `JA4L-C`, so it reads the stored index and writes at
                # that position. `packet_endpoints` runs between the two.
                fingerprinter.process_packet(second_handshake[2])
            except Exception as error:  # noqa: BLE001
                errors.append(error)

        def clear():
            try:
                fingerprinter.reset()
            except Exception as error:  # noqa: BLE001
                errors.append(error)

        import ja4plus.fingerprinters.ja4l as ja4l_module

        ja4l_module.packet_endpoints = blocking_endpoints
        try:
            writer = threading.Thread(target=write)
            writer.start()
            assert entered.wait(timeout=JOIN_TIMEOUT), "the writer never reached the guard"

            clearer = threading.Thread(target=clear)
            clearer.start()
            # The clearer now runs against a fingerprinter whose writer sits inside the
            # guarded section. It waits for the lock for this whole interval.
            time.sleep(0.25)
            release.set()

            writer.join(JOIN_TIMEOUT)
            clearer.join(JOIN_TIMEOUT)
        finally:
            ja4l_module.packet_endpoints = real_endpoints

        assert errors == [], f"the writer raised {errors!r}"

    def test_two_threads_never_store_one_index_for_two_connections(self):
        """The forced case. Two connections never share one entry of the value list.

        `ja4l.py` reads `len(self.fingerprints)` and appends after it. A second thread
        that appends between the two gives both connections the same stored position,
        and the later value of one connection then overwrites the value of the other.
        The case holds the first thread inside `append` with an `Event`.
        """
        fingerprinter = JA4LFingerprinter()
        # Both connections exist and report `JA4L-S` before the race starts, so the two
        # threads race on the client entry alone.
        for packet in handshake("10.0.0.2", 40000)[:2]:
            fingerprinter.process_packet(packet)
        for packet in handshake("10.0.0.3", 40001, start=1001.0)[:2]:
            fingerprinter.process_packet(packet)
        assert len(fingerprinter.fingerprints) == 2

        blocking = BlockingList(fingerprinter.fingerprints)
        fingerprinter.fingerprints = blocking

        errors = []

        def feed(client_ip, client_port, start):
            try:
                fingerprinter.process_packet(handshake(client_ip, client_port, start=start)[2])
            except Exception as error:  # noqa: BLE001
                errors.append(error)

        first = threading.Thread(target=feed, args=("10.0.0.2", 40000, 1000.0))
        first.start()
        assert blocking.entered.wait(timeout=JOIN_TIMEOUT), "the first thread never appended"

        second = threading.Thread(target=feed, args=("10.0.0.3", 40001, 1001.0))
        second.start()
        # The second thread now runs against a fingerprinter whose first thread sits
        # inside `append`. It waits for the lock for this whole interval.
        time.sleep(0.25)
        blocking.release.set()

        first.join(JOIN_TIMEOUT)
        second.join(JOIN_TIMEOUT)

        assert errors == []
        stored = sorted(
            connection["client_entry"] for connection in fingerprinter.connections.values()
        )
        assert stored == [2, 3], f"two connections stored the positions {stored}"


class TestTheConcurrencyContract:
    """The contract `README.md` states, measured, FR-concurrency-safety-15.

    The contract is narrower than "thread safe", and the three cases below measure each
    clause of it.

    1. A caller who gives each thread whole connections reads the value set one thread
       reads. `Processor.get_shard_key` exists for that arrangement.
    2. Clause 1 holds across several captures too, as long as every packet shares one
       timeline.
    3. A caller who feeds one processor two clocks reads a different value set, and one
       thread reads a different set as well. The cause is the age eviction pass and not
       a race, so the case runs on one thread.

    #40 read the third case as a consequence of the entry count bound. A re-measurement
    for #43 disproves that reading: the age bound alone causes it. With the age bound
    raised and the entry count bound as shipped, eight sharded threads match one thread
    on 5 of 5 runs. The entry count bound still evicts 168 entries of
    `ja4x.scan_offsets` on that run.

    Warning: no case in this class measures a lock. #43 removed every fingerprinter lock
    and ran this class 20 times, and 0 of 20 runs failed. It removed the lock of
    `Processor.process_packet` and read 1 of 20. The reason is the arrangement itself.
    A thread that owns whole connections touches keys no other thread touches, so the
    lock guards nothing that these cases read. `TestOneFingerprinterAdmitsOneThread` and
    the two forced cases of `TestResetWhileEightThreadsProcessPackets` measure the locks,
    and round 84 records 20 of 20 for each one.

    The two removals that do fail this class name what it measures.

    - The direction sort of `Processor.get_shard_key` removed: 20 of 20 runs fail, and 4
      of the 7 cases fail on each run. Clause 1 and clause 2 measure that one connection
      reaches one thread.
    - The age eviction pass of `BoundedStateTable.evict_aged` removed: 20 of 20 runs
      fail. Clause 3 measures the age bound.
    """

    @pytest.mark.parametrize("name", CONTRACT_CAPTURES)
    def test_eight_sharded_threads_read_the_set_one_thread_reads(self, name):
        """Clause 1. Each thread owns whole connections, and the two lists are equal."""
        packets = read_capture(name)
        expected = one_thread_values(packets)
        assert expected, f"{name} produced no fingerprint, so the case cannot fail"

        values, errors = eight_thread_values(packets)
        assert errors == []
        assert values == expected

    def test_eight_sharded_threads_read_one_timeline_the_way_one_thread_reads_it(self):
        """Clause 2. Five captures on one timeline hold the equality of clause 1."""
        packets = concatenate(CONTRACT_CAPTURES, one_timeline=True)
        expected = one_thread_values(packets)
        assert expected

        values, errors = eight_thread_values(packets)
        assert errors == []
        assert values == expected

    def test_one_processor_that_reads_two_clocks_produces_a_shorter_value_set(self):
        """Clause 3. A timestamp jump ages out state the next capture still needs.

        The case runs on one thread, so no interleaving reaches the result. It compares
        the same five captures against themselves, and the only difference between the
        two lists is the packet timestamp. `BoundedStateTable.evict_aged` reads that
        timestamp, so the concatenation that jumps 183 days loses a value.

        A caller therefore feeds one processor the packets of one timeline. This case
        guards the paragraph of `README.md` that states it. If the library later reads a
        clock for each connection, this case fails and the contract needs a new reading.
        """
        jumping = one_thread_values(concatenate(CONTRACT_CAPTURES, one_timeline=False))
        continuous = one_thread_values(concatenate(CONTRACT_CAPTURES, one_timeline=True))

        assert jumping != continuous, (
            "the two clocks produced one value set, so the age pass reads no timestamp"
        )
        assert len(jumping) < len(continuous), (
            f"the jump produced {len(jumping)} values and one timeline produced "
            f"{len(continuous)}, so the jump lost no value"
        )


class TestTheAgeClockOfOneShard:
    """A packet of one shard ages out no state of another shard, FR-concurrency-safety-15.

    #461 measured the failure on `SynAckTracker.times`. That table holds a maximum age of
    120 seconds and it runs one age pass on every packet. The pass read one clock for
    every thread, so a thread that stood 132 seconds further along the one timeline
    evicted the connection of a slower thread. The retransmission of that connection then
    found no entry, and it wrote four parts where one thread wrote five.

    The reading that #461 records is
    `'64240_2-1-1-4-1-3_1460_7' != '64240_2-1-1-4-1-3_1460_7_0'` on
    `('184.150.157.177', 80, '172.16.225.48', 57380)` of `latest.pcapng`. The two SYN-ACK
    packets of that connection sit 5.8 milliseconds apart, and the packet that evicted
    the entry sits at 151.678 seconds of the concatenated timeline.

    Each case below builds its own packets, so it states every timestamp it reads. Each
    one forces the interleaving rather than hoping for it.
    """

    def test_a_packet_of_another_shard_holds_the_retransmission_field(self):
        """The second SYN-ACK writes part e after another thread reads a later packet."""
        fingerprinter = JA4TSFingerprinter()

        assert fingerprinter.process_packet(syn_ack(1000.0)) == "64240_2-1-3_1460_7"

        # 1132.0 stands 132 seconds after the first SYN-ACK, and the maximum age of
        # `SynAckTracker.times` is 120 seconds. The packet names another connection, so
        # `get_shard_key` sends it to another thread.
        on_another_thread(
            fingerprinter.process_packet, syn_ack(1132.0, client_port=40001, window=65535)
        )

        assert fingerprinter.process_packet(syn_ack(1000.4)) == "64240_2-1-3_1460_7_0"

    def test_one_shard_that_reads_past_the_maximum_age_writes_no_retransmission_field(self):
        """The same thread ages the connection out, so the case above can fail.

        Clause 3 of `TestTheConcurrencyContract` states the behaviour this case pins: an
        entry that receives no packet for its maximum age leaves the table. The case
        above holds that behaviour for one shard, and this case proves it still runs.
        """
        fingerprinter = JA4TSFingerprinter()

        assert fingerprinter.process_packet(syn_ack(1000.0)) == "64240_2-1-3_1460_7"
        assert (
            fingerprinter.process_packet(syn_ack(1132.0, client_port=40001, window=65535))
            == "65535_2-1-3_1460_7"
        )

        assert fingerprinter.process_packet(syn_ack(1000.4)) == "64240_2-1-3_1460_7"


def syn_ack(when, server_ip="10.0.0.1", server_port=80, client_port=40000, window=64240):
    """Return one SYN-ACK packet with a capture timestamp.

    The option list writes part b as `2-1-3`, the maximum segment size writes part c as
    `1460`, and the window scale writes part d as `7`.

    Args:
        when: The capture timestamp, in seconds.
        server_ip: The server address.
        server_port: The server port.
        client_port: The client port, which names the connection.
        window: The TCP window size, which part a writes.

    Returns:
        One SYN-ACK packet.
    """
    packet = (
        Ether()
        / IP(src=server_ip, dst="10.0.0.2", ttl=64)
        / TCP(
            sport=server_port,
            dport=client_port,
            flags="SA",
            seq=5000,
            ack=1001,
            window=window,
            options=[("MSS", 1460), ("NOP", None), ("WScale", 7)],
        )
    )
    packet.time = when
    return packet


def on_another_thread(call, *args):
    """Run one call on a second thread, and return what it returned.

    A state table reads the clock of the thread that announces a packet, so a case that
    measures two shards needs two threads.

    Args:
        call: The callable to run.
        args: The arguments to pass to it.

    Returns:
        The value the callable returned.
    """
    returned = []
    thread = threading.Thread(target=lambda: returned.append(call(*args)))
    thread.start()
    thread.join(JOIN_TIMEOUT)
    assert not thread.is_alive(), "the second thread did not finish"
    return returned[0]


def ja4l_packet_endpoints():
    """Return the `packet_endpoints` function `ja4l.py` calls today."""
    import ja4plus.fingerprinters.ja4l as ja4l_module

    return ja4l_module.packet_endpoints
