"""
JA4SSH SSH Traffic Fingerprinting implementation.

JA4SSH analyzes SSH traffic patterns to identify session types
even when the content is encrypted. Also includes HASSH support.
"""

import hashlib
import logging
import re
from collections import Counter
from scapy.all import TCP, Raw, IP, IPv6
import time

from ja4plus.utils.ssh_utils import (
    SSHMessageTracker,
    is_ssh_packet,
    parse_ssh_packet,
    extract_hassh,
)
from ja4plus.fingerprinters.base import BaseFingerprinter
from ja4plus.utils.packet_utils import accepts_a_connection, opens_a_connection, packet_seconds
from ja4plus.utils.state_table import BoundedStateTable

logger = logging.getLogger(__name__)

# FoxIO emits one fingerprint for every 200 SSH packets. `technical_details/JA4SSH.png`
# states it verbatim: `(runs every 200 SSH packets by default)`. A smaller window
# produces a fingerprint that no reference implementation matches.
DEFAULT_PACKET_COUNT = 200

# The port FoxIO reads a bare ACK on. `python/ja4.py` tracks a connection for JA4SSH
# only when one endpoint uses this port.
SSH_PORT = 22

# A bare ACK carries the ACK flag alone. FoxIO counts one only when the TCP flags equal
# `0x0010`, so a SYN+ACK, a FIN+ACK and a RST+ACK never reach the bare-ACK counter.
ACK_FLAG = 0x10

# A connection closes with a packet that carries the FIN flag and the ACK flag. FoxIO
# runs `finalize_ja4ssh` on such a packet, which emits the window the connection holds
# open.
FIN_FLAG = 0x01

# A monitor reads a SYN for every TCP connection on the wire, and few of those carry
# SSH. The handshake table therefore holds a maximum entry count, and it drops the
# oldest half when it fills.
MAX_HANDSHAKE_CONNECTIONS = 1000

# The form of one JA4SSH part. A part names its client value after the `c` prefix and its
# server value after the `s` separator, and it holds ASCII digits alone. `re.ASCII` binds
# `\d` to the ten ASCII digits, because `int()` reads any Unicode digit and `c٦s36` then
# reports a client packet size of 6. Issue #186 records the readings.
JA4SSH_PART = re.compile(r"c(\d+)s(\d+)", re.ASCII)


class JA4SSHFingerprinter(BaseFingerprinter):
    """
    JA4SSH SSH Traffic Fingerprinting implementation.

    JA4SSH fingerprints SSH traffic patterns to identify session types.
    Also supports HASSH fingerprinting for client/server identification.
    """

    def __init__(self, packet_count=DEFAULT_PACKET_COUNT, thread_safe=True):
        """Build the fingerprinter.

        Args:
            packet_count: The number of SSH packets in one window. A bare ACK is not an
                SSH packet, and it does not advance the window.
            thread_safe: True makes the fingerprinter guard its own state with a lock.
        """
        super().__init__(thread_safe=thread_safe)
        self.connections = BoundedStateTable()
        # The count of connections this fingerprinter opened. Each entry stores the
        # value it read at its own start, and two readers publish in that order.
        self._arrivals = 0
        self.packet_count = packet_count
        self.hassh_fingerprints = []
        # The endpoint pair of one connection -> the client endpoint the TCP handshake
        # names. The handshake arrives before any SSH data, and the connection entry
        # does not exist yet, so the answer waits here until the first SSH packet.
        self._handshake_clients = BoundedStateTable(max_connections=MAX_HANDSHAKE_CONNECTIONS)

    def process_packet(self, packet):
        """
        Process a packet and track SSH session patterns.

        Args:
            packet: A network packet to analyze

        Returns:
            The extracted fingerprint if a new one is generated, None otherwise
        """
        # The body of this method runs past fifty lines. The lock guards it from here,
        # so the body keeps the indentation the reader already knows.
        with self._lock:
            return self._process_packet(packet)

    def _process_packet(self, packet):
        """Return the JA4SSH value this packet completes, or None.

        The caller holds the lock of this fingerprinter.

        Args:
            packet: A network packet to analyze

        Returns:
            The extracted fingerprint if a new one is generated, None otherwise
        """
        if not (packet.haslayer(TCP) and (packet.haslayer(IP) or packet.haslayer(IPv6))):
            return None

        # The two tables age against the capture clock, so every packet announces its
        # own timestamp. A table that reads the wall clock evicts state a replay needs.
        seconds = packet_seconds(packet)
        self.connections.on_packet(seconds)
        self._handshake_clients.on_packet(seconds)

        # Check if this packet contains SSH data
        has_ssh_data = False
        if packet.haslayer(Raw):
            payload = bytes(packet[Raw])
            has_ssh_data = is_ssh_packet(payload)

        tcp = packet[TCP]
        from ja4plus.utils.packet_utils import get_ip_layer

        ip = get_ip_layer(packet)

        # Create connection key
        src_ip = ip.src
        dst_ip = ip.dst
        src_port = tcp.sport
        dst_port = tcp.dport

        ssh_port = SSH_PORT

        # The handshake names the two endpoints, and it arrives before any SSH data.
        # The record happens before the guard below returns, because a SYN on a
        # non-standard port carries no SSH data and creates no connection.
        self._record_handshake(tcp, src_ip, src_port, dst_ip, dst_port)

        client_ip, client_port, server_ip, server_port, decided_by = self._decide_endpoints(
            src_ip, src_port, dst_ip, dst_port
        )

        # Connection key for tracking
        conn_key = f"{client_ip}:{client_port}-{server_ip}:{server_port}"
        # An eviction from the handshake table would otherwise move the decision, and
        # the connection would split into two entries. The connection that already
        # exists keeps the endpoints it started with.
        reversed_key = f"{server_ip}:{server_port}-{client_ip}:{client_port}"
        if conn_key not in self.connections and reversed_key in self.connections:
            conn_key = reversed_key

        # A bare ACK carries the ACK flag alone and no payload. FoxIO counts one only
        # when the TCP flags equal 0x0010, which excludes a SYN+ACK, a FIN+ACK and a
        # RST+ACK.
        is_bare_ack = int(tcp.flags) == ACK_FLAG and not packet.haslayer(Raw)

        # The ACK of the TCP handshake is a bare ACK, and it arrives before the first
        # SSH packet. FoxIO counts it, so the state table needs the connection before
        # any SSH data reaches it. `ssh-r.pcap`, `ssh-scp-1050.pcap` and `ssh2.pcapng`
        # each report one more client ACK than a state table built on SSH data alone.
        opens_on_ssh_port = is_bare_ack and ssh_port in (src_port, dst_port)

        # Skip packets that aren't SSH data AND don't belong to a known SSH connection
        if not has_ssh_data and not opens_on_ssh_port and conn_key not in self.connections:
            return None

        # Initialize connection if needed
        if conn_key not in self.connections:
            self.connections[conn_key] = {
                "client_ip": client_ip,
                "client_port": client_port,
                "server_ip": server_ip,
                "server_port": server_port,
                "server_decided_by": decided_by,
                "ssh_packets": {"client": [], "server": []},
                "message_tracker": {
                    "client": SSHMessageTracker(),
                    "server": SSHMessageTracker(),
                },
                "bare_acks": {"client": 0, "server": 0},
                "hassh": None,
                "hasshServer": None,
                "client_id": None,
                "server_id": None,
                "start_time": time.time(),
                "arrival": self._arrivals,
            }
            self._arrivals += 1

        conn = self.connections[conn_key]

        # The connection holds the endpoints it started with, so the direction of this
        # packet reads from the connection and not from a fresh decision. A handshake
        # that arrives late would otherwise count one packet in the wrong direction.
        is_client_to_server = (src_ip, src_port) == (conn["client_ip"], conn["client_port"])

        # Check for SSH version banner
        if packet.haslayer(Raw):
            payload = bytes(packet[Raw])
            direction = "client" if is_client_to_server else "server"

            # The tracker follows the message boundary, so it reads every payload
            # segment of the direction, not only the segments the window counts. It
            # reads the sequence number too, because a retransmission repeats bytes the
            # tracker already read, and an out-of-order segment arrives before the
            # segment it follows.
            completed = conn["message_tracker"][direction].add_segment(payload, int(tcp.seq))

            # Extract SSH banner
            if payload.startswith(b"SSH-"):
                version_string = payload.decode("utf-8", errors="ignore").strip()
                if is_client_to_server:
                    conn["client_id"] = version_string
                else:
                    conn["server_id"] = version_string

            # Extract HASSH from KEXINIT
            ssh_info = parse_ssh_packet(payload)
            if ssh_info and ssh_info.get("type") == "kexinit":
                hassh_value = extract_hassh(payload)
                if hassh_value:
                    if is_client_to_server:
                        conn["hassh"] = hassh_value
                    else:
                        conn["hasshServer"] = hassh_value

            # Track SSH data packets. FoxIO counts the packets `tshark` labels `ssh`,
            # and `tshark` labels only the segment that completes an SSH message. A
            # segment that holds part of a message is one TCP segment, not one SSH
            # packet. A count of that segment moves every later window boundary.
            if completed and (is_ssh_packet(payload) or conn["client_id"] or conn["server_id"]):
                conn["ssh_packets"][direction].extend(completed)

        elif is_bare_ack:
            if is_client_to_server:
                conn["bare_acks"]["client"] += 1
            else:
                conn["bare_acks"]["server"] += 1

        # The window counts the SSH packets of both directions. The FoxIO image lists
        # the SSH packet counts and the bare ACK counts as separate fields, so a bare
        # ACK does not advance the window.
        total_packets = len(conn["ssh_packets"]["client"]) + len(conn["ssh_packets"]["server"])

        if total_packets >= self.packet_count:
            return self._close_window(conn_key)

        # A connection that closes emits the window it holds open. FoxIO states the
        # rule above `finalize_ja4ssh`: `If the SSH connection is not terminated or the
        # last sample is less than 200 the finalize function just cleans up and prints
        # the last JA4SSH hash`.
        if int(tcp.flags) & FIN_FLAG and int(tcp.flags) & ACK_FLAG:
            return self._close_window(conn_key)

        return None

    @staticmethod
    def _endpoint_pair_key(src_ip, src_port, dst_ip, dst_port):
        """Return the key that names one connection in either direction.

        Args:
            src_ip: The source address of the packet.
            src_port: The source port of the packet.
            dst_ip: The destination address of the packet.
            dst_port: The destination port of the packet.

        Returns:
            One string. The two directions of one connection give one key.
        """
        first, second = sorted(((src_ip, src_port), (dst_ip, dst_port)))
        return f"{first[0]}:{first[1]}-{second[0]}:{second[1]}"

    def _record_handshake(self, tcp, src_ip, src_port, dst_ip, dst_port):
        """Record the client endpoint that the TCP handshake of one connection names.

        The SYN sender is the client. The SYN+ACK sender is the server, so its
        destination is the client. A capture that starts after the SYN still holds the
        SYN+ACK.

        The method records nothing when one endpoint uses port 22, because the port
        decides that connection and the table would hold an entry nothing reads.

        Args:
            tcp: The TCP layer of the packet.
            src_ip: The source address of the packet.
            src_port: The source port of the packet.
            dst_ip: The destination address of the packet.
            dst_port: The destination port of the packet.
        """
        if SSH_PORT in (src_port, dst_port):
            return
        if opens_a_connection(tcp, "tcp"):
            client = (src_ip, src_port)
        elif accepts_a_connection(tcp, "tcp"):
            client = (dst_ip, dst_port)
        else:
            return
        key = self._endpoint_pair_key(src_ip, src_port, dst_ip, dst_port)
        # The table holds the entry count and the entry age, and it evicts the least
        # recently read entry on its own.
        self._handshake_clients[key] = client

    def _decide_endpoints(self, src_ip, src_port, dst_ip, dst_port):
        """Return the client endpoint, the server endpoint, and how the two were decided.

        Three rules decide, in this order:

        1. An endpoint on port 22 is the server. FoxIO tracks a connection for JA4SSH
           only when one endpoint uses that port.
        2. The TCP handshake names the client, because the SYN sender opens the
           connection.
        3. The lower port is the server. The result is a guess, because two ephemeral
           ports carry no meaning.

        The first SSH banner decides nothing. RFC 4253 section 4.2 has both endpoints
        send an identification string, and a client that does not wait sends first. The
        banner arrives from the client in 4 of the 11 streams of `tests/foxio_vectors/`
        whose SYN names a side.

        Args:
            src_ip: The source address of the packet.
            src_port: The source port of the packet.
            dst_ip: The destination address of the packet.
            dst_port: The destination port of the packet.

        Returns:
            A tuple of the client address, the client port, the server address, the
            server port, and one of `port`, `handshake` or `guess`.
        """
        if dst_port == SSH_PORT:
            return src_ip, src_port, dst_ip, dst_port, "port"
        if src_port == SSH_PORT:
            return dst_ip, dst_port, src_ip, src_port, "port"

        client = self._handshake_clients.get(
            self._endpoint_pair_key(src_ip, src_port, dst_ip, dst_port)
        )
        if client == (src_ip, src_port):
            return src_ip, src_port, dst_ip, dst_port, "handshake"
        if client == (dst_ip, dst_port):
            return dst_ip, dst_port, src_ip, src_port, "handshake"

        if dst_port < src_port:
            return src_ip, src_port, dst_ip, dst_port, "guess"
        return dst_ip, dst_port, src_ip, src_port, "guess"

    def _connections_in_arrival_order(self):
        """Return the connection pairs, in the order the capture opened them.

        The state table orders its keys by the last read, because its entry count bound
        evicts the least recently read entry. The published order of the windows and of
        the HASSH values reads the capture instead, so two runs of one capture agree.

        The pass reads `items`, which holds no entry against either bound. A report of
        the state renews no connection.

        Returns:
            A list of (connection key, connection) pairs, earliest first.
        """
        return sorted(self.connections.items(), key=lambda pair: pair[1]["arrival"])

    def close_open_windows(self):
        """Emit the window every connection holds open, and return the new entries.

        The caller runs this method when the packet source ends. A connection that
        never sends a FIN+ACK packet holds its last window open, and no other rule
        emits it. `rust/ja4/src/ssh.rs:45-55` and `zeek/ja4ssh/main.zeek:160-164` both
        emit that window, and the two agree on its value for `ssh2.pcapng`. #214 holds
        the decision.

        A window that holds no SSH packet emits nothing, because `_close_window`
        declines it. #97 declines the same value in the FoxIO Python reference.

        The method reads the connections in the order the capture opened them, and it
        evicts no entry. A repeated call therefore emits nothing, because
        `_close_window` clears the counters of the window it emits.

        Returns:
            A list of the fingerprint entries the call appended to `self.fingerprints`.
        """
        with self._lock:
            emitted = []
            for conn_key, _ in self._connections_in_arrival_order():
                if self._close_window(conn_key) is not None:
                    emitted.append(self.fingerprints[-1])
            return emitted

    def _close_window(self, conn_key):
        """Emit the open window of one connection, and start a new window.

        Args:
            conn_key: The connection key of the window.

        Returns:
            The JA4SSH fingerprint, or None when the window holds no SSH packet. A
            fingerprint of an empty window describes no traffic. Three connection
            states reach this guard: the second FIN packet of a close finds the window
            the first FIN packet emptied, a connection that closes right after a full
            window holds no SSH packet either, and the end of a capture reaches a
            connection of bare ACKs alone.
        """
        conn = self.connections[conn_key]
        if not conn["ssh_packets"]["client"] and not conn["ssh_packets"]["server"]:
            return None

        fingerprint = self._generate_ja4ssh(conn_key)

        self.fingerprints.append(
            {
                "fingerprint": fingerprint,
                "connection": conn_key,
                "timestamp": time.time(),
                # A consumer reads a measured side and a guessed side differently, so
                # the source of the decision reaches the result.
                "server_decided_by": conn["server_decided_by"],
            }
        )

        conn["ssh_packets"]["client"] = []
        conn["ssh_packets"]["server"] = []
        conn["bare_acks"]["client"] = 0
        conn["bare_acks"]["server"] = 0

        return fingerprint

    def _generate_ja4ssh(self, conn_key):
        """Generate JA4SSH fingerprint for a connection."""
        if conn_key not in self.connections:
            return None

        conn = self.connections[conn_key]

        # Part A: Common packet sizes
        client_packets = conn["ssh_packets"]["client"]
        server_packets = conn["ssh_packets"]["server"]

        # Find most common packet size for client and server
        client_mode = self._mode(client_packets) if client_packets else 0
        server_mode = self._mode(server_packets) if server_packets else 0

        part_a = f"c{client_mode}s{server_mode}"

        # Part B: SSH packet counts (raw counts per FoxIO spec)
        client_ssh_count = len(client_packets)
        server_ssh_count = len(server_packets)
        part_b = f"c{client_ssh_count}s{server_ssh_count}"

        # Part C: ACK counts (raw counts per FoxIO spec)
        client_ack_count = conn["bare_acks"]["client"]
        server_ack_count = conn["bare_acks"]["server"]
        part_c = f"c{client_ack_count}s{server_ack_count}"

        # Combine all parts
        ja4ssh = f"{part_a}_{part_b}_{part_c}"

        return ja4ssh

    def _mode(self, values):
        """Find the most common value in a list (deterministic).

        Per FoxIO PR #281, when multiple values tie for the highest frequency,
        the LOWEST value wins. This guarantees deterministic JA4SSH output
        regardless of the iteration order of the underlying Counter.
        """
        if not values:
            return 0

        counter = Counter(values)
        max_count = max(counter.values())
        # Among values with the top frequency, pick the smallest.
        return min(v for v, c in counter.items() if c == max_count)

    def get_hassh_fingerprints(self):
        """
        Get all collected HASSH fingerprints.

        Returns:
            List of HASSH fingerprints
        """
        with self._lock:
            hassh_fps = []
            for conn_key, conn in self._connections_in_arrival_order():
                if conn.get("hassh"):
                    hassh_fps.append(
                        {
                            "fingerprint": conn["hassh"],
                            "banner": conn.get("client_id"),
                            "type": "client",
                        }
                    )
                if conn.get("hasshServer"):
                    hassh_fps.append(
                        {
                            "fingerprint": conn["hasshServer"],
                            "banner": conn.get("server_id"),
                            "type": "server",
                        }
                    )
            return hassh_fps

    def reset(self):
        """Reset fingerprinter state."""
        with self._lock:
            super().reset()
            self.hassh_fingerprints = []
            self.connections = BoundedStateTable()
            self._arrivals = 0
            self._handshake_clients = BoundedStateTable(max_connections=MAX_HANDSHAKE_CONNECTIONS)

    def cleanup_connection(self, src_ip, src_port, dst_ip, dst_port, proto):
        """Remove stored SSH session state for the given connection."""
        with self._lock:
            # JA4SSH stores state as client:port-server:port (client is higher port)
            fwd = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
            rev = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"
            self.connections.pop(fwd, None)
            self.connections.pop(rev, None)
            # The handshake table outlives the connection otherwise, because the
            # processor evicts a connection that a later packet of the pair rebuilds.
            self._handshake_clients.pop(
                self._endpoint_pair_key(src_ip, src_port, dst_ip, dst_port), None
            )

    def interpret_fingerprint(self, fingerprint):
        """
        Return the session type that a JA4SSH fingerprint describes.

        Args:
            fingerprint: A JA4SSH fingerprint string.

        Returns:
            A dictionary that holds the session type, the description and the details.
            A malformed fingerprint returns a dictionary that holds the key `error`. A
            value that is not a string is a malformed fingerprint, and None, bytes and
            bytearray each return the error dictionary.
        """
        try:
            parts = fingerprint.split("_")
            if len(parts) != 3:
                return {"error": "Invalid JA4SSH format"}

            packet_sizes = parts[0]  # c36s36
            ssh_ratio = parts[1]  # c55s75
            ack_ratio = parts[2]  # c70s0

            # One regular expression reads every part, because an earlier parser removed
            # the first character and split on `s` without a check. A part that carries
            # no prefix, a wrong prefix, a second separator, or a character that is not
            # an ASCII digit then reported a number the fingerprint does not hold.
            # Issue #182 records the prefix, and issue #186 records the other three.
            # `fullmatch` is the comparison, because `$` matches before a line feed and
            # `c70s30\n` passes an anchored `match`.
            values = []
            for part in (packet_sizes, ssh_ratio, ack_ratio):
                match = JA4SSH_PART.fullmatch(part)
                if match is None:
                    return {"error": "Invalid JA4SSH format"}
                values.append((int(match.group(1)), int(match.group(2))))

            (c_size, s_size), (c_ssh, s_ssh), (c_ack, s_ack) = values

            # Interpret session type
            session_type = "Unknown"
            description = ""

            # Interactive SSH session
            if c_size == 36 and s_size == 36 and c_ack > 60:
                session_type = "Interactive SSH Session"
                description = "Normal interactive terminal session, client typing commands"

            # Reverse SSH session
            elif c_size > 70 and s_size > 70 and s_ack > 60:
                session_type = "Reverse SSH Session"
                description = "Double-padded SSH tunnel, server side typing commands"

            # File transfer
            elif s_size > 1000 and c_ssh < 20 and s_ssh > 80:
                session_type = "SSH File Transfer"
                description = "Server sending large packets to client (download)"

            elif c_size > 1000 and c_ssh > 80 and s_ssh < 20:
                session_type = "SSH File Transfer (Upload)"
                description = "Client sending large packets to server (upload)"

            return {
                "session_type": session_type,
                "description": description,
                "details": {
                    "packet_sizes": {"client": c_size, "server": s_size},
                    "ssh_ratio": {"client": c_ssh, "server": s_ssh},
                    "ack_ratio": {"client": c_ack, "server": s_ack},
                },
            }

        # `AttributeError` names a value that is not a string, and `_close_window`
        # returns None, so a caller reaches this method with None. `TypeError` names a
        # value of type bytes or bytearray, which holds a `split` method that denies the
        # separator `"_"`. It also names a part of type bytes, which the string pattern
        # of the part guard denies. Issue #262 records the decision. A value of the wrong
        # type is a malformed fingerprint, and the method answers None that way already.
        # `ValueError` names a part that holds more than 4300 digits, which
        # matches the pattern and exceeds the CPython limit on an integer conversion.
        # `IndexError` reaches this handler from no input the part guard admits, and it
        # stays because #36 and the correctness audit set the handler to the parse errors
        # this method expects. A wider handler would report a defect inside this project
        # as a malformed fingerprint, and the caller would read a wrong answer instead of
        # a stack trace.
        except (AttributeError, IndexError, TypeError, ValueError) as e:
            return {"error": f"Failed to interpret: {str(e)}"}

    def lookup_hassh(self, hassh_value):
        """
        Look up a HASSH fingerprint from a known database.

        Args:
            hassh_value: A HASSH fingerprint string

        Returns:
            Dict containing information about the fingerprint if known
        """
        # Common HASSH fingerprints and their corresponding clients/servers
        hassh_db = {
            "8a8ae540028bf433cd68356c1b9e8d5b": "CyberDuck Version 6.7.1",
            "b5752e36ba6c5979a575e43178908adf": "Paramiko 2.4.1 (Metasploit)",
            "16f898dd8ed8279e1055350b4e20666c": "Dropbear 2012.55 (IoT)",
            "06046964c022c6407d15a27b12a6a4fb": "OpenSSH 7.6",
            "de30354b88bae4c2810426614e1b6976": "Renci.SshNet.SshClient (PowerShell/Empire)",
            "fafc45381bfde997b6305c4e1600f1bf": "Ruby/Net::SSH 5.0.2 (Metasploit)",
            "c1c596caaeb93c566b8ecf3cae9b5a9e": "Dropbear 2016.74 (Server)",
            "d93f46d063c4382b6232a4d77db532b2": "Dropbear 2016.72 (Server)",
            "2dd9a9b3dbebfaeec8b8aabd689e75d2": "AWSCodeCommit (Server)",
            "696e7f84ac571fdf8fa5073e64ee2dc8": "SSH-2.0-FTP (Server)",
        }

        if hassh_value in hassh_db:
            return {
                "fingerprint": hassh_value,
                "identified_as": hassh_db[hassh_value],
                "source": "JA4+ built-in database",
            }

        return {"fingerprint": hassh_value, "identified_as": "Unknown", "source": None}


def generate_ja4ssh(packet, conn=None):
    """
    Generate a simplified JA4SSH fingerprint for a single packet.

    Note: Real JA4SSH requires analyzing multiple packets in a session.
    This function will also try to extract HASSH if present.

    Args:
        packet: A network packet
        conn: Connection tracking data (ignored in this implementation)

    Returns:
        A JA4SSH or HASSH fingerprint if applicable, None otherwise
    """
    # First try to extract HASSH if this is a KEXINIT packet
    if packet.haslayer(Raw):
        payload = bytes(packet[Raw])
        if is_ssh_packet(payload):
            ssh_info = parse_ssh_packet(payload)
            if ssh_info and ssh_info.get("type") == "kexinit":
                hassh_value = extract_hassh(payload)
                if hassh_value:
                    # Indicate if this is client or server HASSH
                    direction = "server" if packet[TCP].sport == 22 else "client"
                    return f"hassh-{direction}_{hassh_value}"

    # Fall back to simplified JA4SSH
    fingerprinter = JA4SSHFingerprinter(packet_count=1)
    return fingerprinter.process_packet(packet)
