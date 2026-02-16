#!/usr/bin/env python3
"""
JA4+ Fingerprinting Demo

Demonstrates all 8 fingerprinters using constructed packets.
No PCAP file or live capture required.

Usage:
    python examples/demo_fingerprints.py
"""

import hashlib
import time
import datetime

from scapy.all import IP, TCP, UDP, Raw, Ether

from ja4plus.fingerprinters.ja4 import JA4Fingerprinter
from ja4plus.fingerprinters.ja4s import JA4SFingerprinter
from ja4plus.fingerprinters.ja4h import JA4HFingerprinter
from ja4plus.fingerprinters.ja4l import JA4LFingerprinter
from ja4plus.fingerprinters.ja4t import JA4TFingerprinter
from ja4plus.fingerprinters.ja4ts import JA4TSFingerprinter
from ja4plus.fingerprinters.ja4x import JA4XFingerprinter
from ja4plus.fingerprinters.ja4ssh import JA4SSHFingerprinter, generate_ja4ssh


SEPARATOR = "=" * 60


def banner(title):
    print(f"\n{SEPARATOR}")
    print(f"  {title}")
    print(SEPARATOR)


# ---------------------------------------------------------------------------
# Packet builders
# ---------------------------------------------------------------------------

def build_client_hello(sni="example.com"):
    """Build a realistic TLS 1.3 ClientHello."""
    ch = bytearray()
    ch += b"\x03\x03"        # ClientHello version (TLS 1.2 on wire)
    ch += b"\x00" * 32       # Random
    ch += b"\x00"             # Session ID length

    # Cipher suites: TLS_AES_128_GCM, TLS_AES_256_GCM, TLS_CHACHA20, ECDHE-RSA-AES128
    ciphers = [0x1301, 0x1302, 0x1303, 0xC02F, 0xC030, 0xCCA9]
    cs = bytearray()
    for c in ciphers:
        cs += c.to_bytes(2, "big")
    ch += len(cs).to_bytes(2, "big") + cs
    ch += b"\x01\x00"  # Compression

    ext = bytearray()

    # SNI (0x0000)
    host = sni.encode()
    sni_entry = b"\x00" + len(host).to_bytes(2, "big") + host
    sni_list = len(sni_entry).to_bytes(2, "big") + sni_entry
    ext += b"\x00\x00" + len(sni_list).to_bytes(2, "big") + sni_list

    # supported_versions (0x002b) -> TLS 1.3, TLS 1.2
    sv = b"\x04\x03\x04\x03\x03"
    ext += b"\x00\x2b" + len(sv).to_bytes(2, "big") + sv

    # ALPN (0x0010) -> h2, http/1.1
    alpn_protos = b"\x02h2\x08http/1.1"
    alpn_list = len(alpn_protos).to_bytes(2, "big") + alpn_protos
    ext += b"\x00\x10" + len(alpn_list).to_bytes(2, "big") + alpn_list

    # signature_algorithms (0x000d)
    sig_algs = b"\x00\x08\x04\x03\x08\x04\x04\x01\x05\x01"
    ext += b"\x00\x0d" + len(sig_algs).to_bytes(2, "big") + sig_algs

    # ec_point_formats (0x000b)
    ext += b"\x00\x0b\x00\x00"

    # supported_groups (0x000a)
    ext += b"\x00\x0a\x00\x00"

    ch += len(ext).to_bytes(2, "big") + ext

    hs = b"\x01" + len(ch).to_bytes(3, "big") + bytes(ch)
    record = b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs
    return bytes(record)


def build_server_hello():
    """Build a TLS 1.3 ServerHello."""
    sh = bytearray()
    sh += b"\x03\x03"        # TLS 1.2 on wire
    sh += b"\x00" * 32       # Random
    sh += b"\x00"             # Session ID length
    sh += b"\x13\x01"        # TLS_AES_128_GCM_SHA256
    sh += b"\x00"             # Compression

    ext = bytearray()
    # supported_versions -> TLS 1.3
    ext += b"\x00\x2b\x00\x02\x03\x04"
    # key_share (0x0033)
    ext += b"\x00\x33\x00\x00"

    sh += len(ext).to_bytes(2, "big") + ext

    hs = b"\x02" + len(sh).to_bytes(3, "big") + bytes(sh)
    record = b"\x16\x03\x03" + len(hs).to_bytes(2, "big") + hs
    return bytes(record)


def build_http_request():
    """Build a realistic HTTP/1.1 GET request."""
    return (
        b"GET /api/v1/data HTTP/1.1\r\n"
        b"Host: api.example.com\r\n"
        b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
        b"Accept: application/json\r\n"
        b"Accept-Language: en-US,en;q=0.9\r\n"
        b"Accept-Encoding: gzip, deflate, br\r\n"
        b"Cookie: session=abc123def456; theme=dark\r\n"
        b"Referer: https://example.com/dashboard\r\n"
        b"Connection: keep-alive\r\n"
        b"\r\n"
    )


def make_test_certificate():
    """Generate a self-signed test certificate."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.serialization import Encoding

    key = rsa.generate_private_key(65537, 2048, default_backend())
    now = datetime.datetime.now(datetime.UTC)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Inc"),
        x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("example.com")]),
            critical=False,
        )
        .sign(key, hashes.SHA256(), default_backend())
    )
    return cert.public_bytes(Encoding.DER)


# ---------------------------------------------------------------------------
# Demo sections
# ---------------------------------------------------------------------------

def demo_ja4():
    banner("JA4 - TLS Client Hello Fingerprint")
    print("Identifies TLS clients by their ClientHello message.\n")

    fp = JA4Fingerprinter()
    raw = build_client_hello("example.com")
    packet = (
        IP(src="192.168.1.100", dst="93.184.216.34")
        / TCP(sport=54321, dport=443)
        / Raw(load=raw)
    )

    result = fp.process_packet(packet)
    print(f"  JA4 = {result}")

    parts = result.split("_")
    proto_ver = parts[0]
    print(f"\n  Part A breakdown: {proto_ver}")
    print(f"    Protocol:     {proto_ver[0]}  (t=TCP, q=QUIC, d=DTLS)")
    print(f"    TLS Version:  {proto_ver[1:3]}")
    print(f"    SNI:          {proto_ver[3]}  (d=domain present, i=IP/absent)")
    print(f"    Cipher count: {proto_ver[4:6]}")
    print(f"    Ext count:    {proto_ver[6:8]}")
    print(f"    ALPN:         {proto_ver[8:10]}")
    print(f"  Part B (cipher hash): {parts[1]}")
    print(f"  Part C (ext hash):    {parts[2]}")

    # Also show raw fingerprint
    raw_fp = fp.get_raw_fingerprint(packet)
    print(f"\n  Raw: {raw_fp}")


def demo_ja4s():
    banner("JA4S - TLS Server Hello Fingerprint")
    print("Identifies TLS servers by their ServerHello response.\n")

    fp = JA4SFingerprinter()
    raw = build_server_hello()
    packet = (
        IP(src="93.184.216.34", dst="192.168.1.100")
        / TCP(sport=443, dport=54321)
        / Raw(load=raw)
    )

    result = fp.process_packet(packet)
    print(f"  JA4S = {result}")

    parts = result.split("_")
    print(f"\n  Part A: {parts[0]}")
    print(f"    Protocol+Version: {parts[0][:3]}")
    print(f"    Extension count:  {parts[0][3:5]}")
    print(f"    ALPN:             {parts[0][5:7]}")
    print(f"  Selected cipher: 0x{parts[1]}")
    print(f"  Extension hash:  {parts[2]}")


def demo_ja4h():
    banner("JA4H - HTTP Request Fingerprint")
    print("Identifies HTTP clients by request structure.\n")

    fp = JA4HFingerprinter()
    packet = (
        IP(src="192.168.1.100", dst="93.184.216.34")
        / TCP(sport=54321, dport=80)
        / Raw(load=build_http_request())
    )

    result = fp.process_packet(packet)
    print(f"  JA4H = {result}")

    parts = result.split("_")
    pa = parts[0]
    print(f"\n  Part A: {pa}")
    print(f"    Method:       {pa[:2]}")
    print(f"    HTTP version: {pa[2:4]}")
    print(f"    Has cookie:   {pa[4]}  (c=yes, n=no)")
    print(f"    Has referer:  {pa[5]}  (r=yes, n=no)")
    print(f"    Header count: {pa[6:8]}")
    print(f"    Language:     {pa[8:]}")
    print(f"  Headers hash:       {parts[1]}")
    print(f"  Cookie names hash:  {parts[2]}")
    print(f"  Cookie values hash: {parts[3]}")


def demo_ja4t_ja4ts():
    banner("JA4T / JA4TS - TCP Fingerprints")
    print("JA4T: client SYN   |   JA4TS: server SYN-ACK\n")

    ja4t = JA4TFingerprinter()
    ja4ts = JA4TSFingerprinter()

    syn = IP(src="192.168.1.100", dst="93.184.216.34") / TCP(
        sport=54321, dport=443, flags="S", window=65535,
        options=[("MSS", 1460), ("NOP", None), ("WScale", 7),
                 ("SAckOK", ""), ("Timestamp", (0, 0))],
    )
    synack = IP(src="93.184.216.34", dst="192.168.1.100") / TCP(
        sport=443, dport=54321, flags="SA", window=14600,
        options=[("MSS", 1460), ("NOP", None), ("WScale", 0),
                 ("SAckOK", b""), ("NOP", None), ("NOP", None)],
    )

    t_fp = ja4t.process_packet(syn)
    ts_fp = ja4ts.process_packet(synack)

    print(f"  JA4T  = {t_fp}")
    print(f"  JA4TS = {ts_fp}")

    parts = t_fp.split("_")
    print(f"\n  Format: <window>_<options>_<mss>_<wscale>")
    print(f"  Client window:  {parts[0]}")
    print(f"  TCP options:    {parts[1]}  (2=MSS,1=NOP,3=WScale,4=SAckOK,8=Timestamp)")
    print(f"  MSS:            {parts[2]}")
    print(f"  Window scale:   {parts[3]}")


def demo_ja4l():
    banner("JA4L - Light Distance / Latency Fingerprint")
    print("Estimates physical distance from TCP handshake timing.\n")

    fp = JA4LFingerprinter()

    syn = IP(src="192.168.1.100", dst="93.184.216.34", ttl=128) / TCP(
        sport=54321, dport=443, flags="S"
    )
    fp.process_packet(syn)
    time.sleep(0.005)  # Simulate ~5ms network delay

    synack = IP(src="93.184.216.34", dst="192.168.1.100", ttl=56) / TCP(
        sport=443, dport=54321, flags="SA"
    )
    server_fp = fp.process_packet(synack)
    time.sleep(0.005)

    ack = IP(src="192.168.1.100", dst="93.184.216.34", ttl=128) / TCP(
        sport=54321, dport=443, flags="A"
    )
    client_fp = fp.process_packet(ack)

    print(f"  Server: {server_fp}")
    print(f"  Client: {client_fp}")

    # Interpret
    if server_fp:
        latency_str = server_fp.split("=")[1].split("_")[0]
        ttl_str = server_fp.split("_")[1]
        latency = int(latency_str)
        print(f"\n  Server one-way latency: {latency} us")
        print(f"  Server TTL: {ttl_str}")
        print(f"  Estimated OS: {fp.estimate_os(int(ttl_str))}")
        print(f"  Hop count: ~{fp.estimate_hop_count(int(ttl_str))}")
        print(f"  Distance: ~{fp.calculate_distance(latency):.0f} miles / ~{fp.calculate_distance_km(latency):.0f} km")


def demo_ja4x():
    banner("JA4X - X.509 Certificate Fingerprint")
    print("Fingerprints X.509 certificates by OID structure.\n")

    cert_data = make_test_certificate()
    fp = JA4XFingerprinter()
    result = fp.fingerprint_certificate(cert_data)

    print(f"  JA4X = {result}")

    parts = result.split("_")
    print(f"\n  Issuer hash:    {parts[0]}")
    print(f"  Subject hash:   {parts[1]}")
    print(f"  Extension hash: {parts[2]}")

    # Show the OIDs being hashed
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    cert = x509.load_der_x509_certificate(cert_data, default_backend())
    details = fp.get_cert_details(cert)
    print(f"\n  Issuer OIDs:    {','.join(details['issuer_rdns'])}")
    print(f"  Subject OIDs:   {','.join(details['subject_rdns'])}")
    print(f"  Extension OIDs: {','.join(details['extensions'])}")


def demo_ja4ssh():
    banner("JA4SSH - SSH Traffic Fingerprint")
    print("Identifies SSH session types from traffic patterns.\n")

    fp = JA4SSHFingerprinter(packet_count=10)

    # Simulate an interactive SSH session
    client_ip, server_ip = "192.168.1.100", "192.168.1.200"

    # Banners
    fp.process_packet(
        Ether() / IP(src=client_ip, dst=server_ip)
        / TCP(sport=52416, dport=22)
        / Raw(load=b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n")
    )
    fp.process_packet(
        Ether() / IP(src=server_ip, dst=client_ip)
        / TCP(sport=22, dport=52416)
        / Raw(load=b"SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2\r\n")
    )

    # Interactive traffic (small packets both directions)
    result = None
    for i in range(20):
        fp.process_packet(
            Ether() / IP(src=client_ip, dst=server_ip)
            / TCP(sport=52416, dport=22)
            / Raw(load=b"SSH-2.0-" + b"A" * 28)
        )
        r = fp.process_packet(
            Ether() / IP(src=server_ip, dst=client_ip)
            / TCP(sport=22, dport=52416)
            / Raw(load=b"SSH-2.0-" + b"B" * 28)
        )
        if r:
            result = r

    if result:
        print(f"  JA4SSH = {result}")
        interp = fp.interpret_fingerprint(result)
        print(f"  Session type: {interp['session_type']}")
        print(f"  Description:  {interp.get('description', 'N/A')}")

    # HASSH extraction
    print("\n  HASSH (SSH client/server identification):")
    kex_packet = (
        Ether() / IP(src=client_ip, dst=server_ip)
        / TCP(sport=52416, dport=22)
        / Raw(load=b"\x00\x00\x05\xdc\x06\x14AAAAAAAAAASSH_MSG_KEXINIT"
                    b"curve25519-sha256@libssh.org,ecdh-sha2-nistp256;"
                    b"chacha20-poly1305@openssh.com,aes128-ctr,aes256-ctr;"
                    b"hmac-sha2-256,hmac-sha1;"
                    b"none,zlib@openssh.com")
    )
    hassh_fp = generate_ja4ssh(kex_packet)
    if hassh_fp:
        print(f"    {hassh_fp}")

    # Known HASSH lookup
    print("\n  Known HASSH database lookups:")
    for hassh, expected in [
        ("8a8ae540028bf433cd68356c1b9e8d5b", "CyberDuck"),
        ("06046964c022c6407d15a27b12a6a4fb", "OpenSSH 7.6"),
        ("16f898dd8ed8279e1055350b4e20666c", "Dropbear"),
    ]:
        info = fp.lookup_hassh(hassh)
        print(f"    {hassh[:16]}... -> {info['identified_as']}")


def demo_summary():
    banner("Summary")
    print("""
  JA4+ is a suite of network fingerprinting methods by FoxIO-LLC:

  Fingerprint | What it identifies
  ------------|----------------------------------------------------
  JA4         | TLS client (from ClientHello)
  JA4S        | TLS server (from ServerHello)
  JA4H        | HTTP client (from request headers/cookies)
  JA4T        | TCP client (from SYN options/window)
  JA4TS       | TCP server (from SYN-ACK options/window)
  JA4L        | Physical distance (from handshake latency)
  JA4X        | X.509 certificate (from OID structure)
  JA4SSH      | SSH session type (from traffic patterns)

  For PCAP analysis, use: python examples/pcap_analysis.py <file.pcap>
""")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("\n" + "=" * 60)
    print("        JA4+ Network Fingerprinting Demo")
    print("=" * 60)

    demo_ja4()
    demo_ja4s()
    demo_ja4h()
    demo_ja4t_ja4ts()
    demo_ja4l()
    demo_ja4x()
    demo_ja4ssh()
    demo_summary()


if __name__ == "__main__":
    main()
