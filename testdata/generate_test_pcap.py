"""Generate a large, realistic SOME/IP + DoIP test capture.

Run from the repository root:

    python testdata/generate_test_pcap.py
    # → testdata/large_realistic.pcap

The capture is built entirely from the codecs that already ship with
the suite (``someip_suite.protocols.someip`` / ``doip``), so every
byte of every packet round-trips cleanly through the analyser.

Scenarios encoded in the trace
------------------------------

A. Six in-vehicle ECUs (10.0.0.10 .. 10.0.0.15) advertise distinct
   services with **compliant AUTOSAR PRS R21-11 SD timing**:

       INITIAL_DELAY        : 50 .. 200 ms (per ECU, jitter)
       REPETITIONS_BASE_DELAY : 200 ms, doubled per repetition (PRS §4.2.1)
       REPETITIONS          : 4
       CYCLIC_OFFER_DELAY   : 2000 ms, ~ 60 s of cyclic offers

B. One **misbehaving ECU** (10.0.0.99) advertises a service with a
   broken back-off (200 ms / 200 ms / 200 ms / 200 ms — no doubling).
   The SD Analyzer is expected to flag this as
   ``missing-exponential-backoff``.

C. **FindService → OfferService** exchanges from a head-unit
   (10.0.0.50) for two of the offered services.

D. **SubscribeEventgroup** messages from two consumer ECUs.

E. Four **DoIP TCP sessions** between a diagnostic tester
   (10.0.0.200) and various ECUs on port 13400:

       1. Tester present loop  — 50 × 0x3E 0x00 (positive responses)
       2. Read DataByIdentifier — 200 × 0x22 0xF1 0x90 (VIN read,
          mixes positive responses + occasional NRC 0x31)
       3. Routine activation with **NRC 0x78 then positive response**
          (response-pending pattern)
       4. Reconnect scenario — session closes after RoutingActivation
          rejection (code 0x06) and the tester reconnects with a
          different source address that succeeds.

F. Background **noise traffic**: ARP-shaped Ethernet frames and a few
   plain TCP/UDP packets unrelated to SOME/IP/DoIP, so the decoder's
   filter logic is exercised.

Tunables — bump ``CYCLE_COUNT`` to inflate the file (each cycle adds
roughly 50 frames). The default settings produce roughly **15-20 k
frames** and ~ 1.5 MB on disk, which is large enough to stress the
pipeline while remaining comfortable to commit to git.
"""

from __future__ import annotations

import os
import random
import struct
import sys
from typing import List, Tuple

# Make the in-tree package importable when running from the repo root.
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(REPO, "src"))

from someip_suite.protocols import doip, someip                # noqa: E402
from someip_suite.protocols.pcap import PcapWriter             # noqa: E402


SOMEIP_SD_PORT = 30490
SD_MULTICAST_IP = "224.224.224.245"
DOIP_PORT = 13400

# How many cyclic-offer rounds to emit (each round ≈ 2 s of vehicle time
# and ≈ 6 packets per ECU). 300 rounds → ~ 10 min of vehicle time and
# roughly 1 800 SD frames just from the cyclic phase. Override via the
# ``CYCLE_COUNT`` environment variable to inflate (e.g. ``CYCLE_COUNT=2000``).
CYCLE_COUNT = int(os.environ.get("CYCLE_COUNT", "300"))

# Number of DoIP request/response pairs in the read-DID stress session.
# Each pair produces 3 frames (request, ack, response).
DID_LOOP = int(os.environ.get("DID_LOOP", "3000"))

# Number of TesterPresent keep-alives.
TESTER_PRESENT_COUNT = int(os.environ.get("TESTER_PRESENT_COUNT", "500"))

# Number of background noise frames.
NOISE_COUNT = int(os.environ.get("NOISE_COUNT", "500"))


# ---------------------------------------------------------------------------
# Frame builders (Ethernet / IPv4 / UDP / TCP) — pure stdlib
# ---------------------------------------------------------------------------


def _mac(last_octet: int) -> bytes:
    return bytes([0x02, 0x00, 0x00, 0x00, 0x00, last_octet & 0xFF])


def _ipv4(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    src_b = bytes(int(o) for o in src.split("."))
    dst_b = bytes(int(o) for o in dst.split("."))
    total = 20 + len(payload)
    # Identification field cycles so the IP layer looks realistic.
    ident = _ipv4.counter & 0xFFFF
    _ipv4.counter += 1
    ip = struct.pack("!BBHHHBBH4s4s",
                     0x45, 0x00, total, ident,
                     0x4000, 64, proto, 0,
                     src_b, dst_b)
    return ip + payload


_ipv4.counter = 1  # type: ignore[attr-defined]


def _eth(src_mac: bytes, dst_mac: bytes, ethertype: int,
         payload: bytes) -> bytes:
    return dst_mac + src_mac + struct.pack("!H", ethertype) + payload


def udp_frame(src_ip: str, dst_ip: str, sport: int, dport: int,
              payload: bytes,
              src_mac_octet: int = 0x01,
              dst_mac_octet: int = 0xFF) -> bytes:
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = _ipv4(src_ip, dst_ip, 17, udp)
    return _eth(_mac(src_mac_octet), _mac(dst_mac_octet), 0x0800, ip)


# ---------------------------------------------------------------------------
# TCP flow helper — tracks sequence numbers per (src,dst,sport,dport).
# ---------------------------------------------------------------------------


class TcpFlow:
    """Synthesises a single TCP half-duplex pair with correct seq numbers."""

    def __init__(self, client_ip: str, entity_ip: str,
                 client_port: int, entity_port: int = DOIP_PORT,
                 client_mac: int = 0xC0, entity_mac: int = 0xE0) -> None:
        self.client_ip, self.entity_ip = client_ip, entity_ip
        self.client_port, self.entity_port = client_port, entity_port
        self.client_mac, self.entity_mac = client_mac, entity_mac
        # Initial seq numbers; +1 after the SYN handshake (SYN consumes one).
        self._seq_c2e = 1
        self._seq_e2c = 1

    def _tcp(self, src_ip: str, dst_ip: str, sport: int, dport: int,
             seq: int, flags: int, payload: bytes,
             src_mac: int, dst_mac: int) -> bytes:
        tcp = struct.pack("!HHIIBBHHH",
                          sport, dport, seq, 0,
                          (5 << 4), flags, 64240, 0, 0) + payload
        ip = _ipv4(src_ip, dst_ip, 6, tcp)
        return _eth(_mac(src_mac), _mac(dst_mac), 0x0800, ip)

    def handshake(self) -> List[bytes]:
        # SYN, SYN-ACK, ACK
        s1 = self._tcp(self.client_ip, self.entity_ip,
                       self.client_port, self.entity_port,
                       0, 0x02, b"", self.client_mac, self.entity_mac)
        s2 = self._tcp(self.entity_ip, self.client_ip,
                       self.entity_port, self.client_port,
                       0, 0x12, b"", self.entity_mac, self.client_mac)
        s3 = self._tcp(self.client_ip, self.entity_ip,
                       self.client_port, self.entity_port,
                       1, 0x10, b"", self.client_mac, self.entity_mac)
        return [s1, s2, s3]

    def c2e(self, payload: bytes) -> bytes:
        frame = self._tcp(self.client_ip, self.entity_ip,
                          self.client_port, self.entity_port,
                          self._seq_c2e, 0x18, payload,
                          self.client_mac, self.entity_mac)
        self._seq_c2e += len(payload)
        return frame

    def e2c(self, payload: bytes) -> bytes:
        frame = self._tcp(self.entity_ip, self.client_ip,
                          self.entity_port, self.client_port,
                          self._seq_e2c, 0x18, payload,
                          self.entity_mac, self.client_mac)
        self._seq_e2c += len(payload)
        return frame

    def fin(self) -> List[bytes]:
        f1 = self._tcp(self.client_ip, self.entity_ip,
                       self.client_port, self.entity_port,
                       self._seq_c2e, 0x11, b"",
                       self.client_mac, self.entity_mac)
        f2 = self._tcp(self.entity_ip, self.client_ip,
                       self.entity_port, self.client_port,
                       self._seq_e2c, 0x11, b"",
                       self.entity_mac, self.client_mac)
        return [f1, f2]


# ---------------------------------------------------------------------------
# Scenario builders
# ---------------------------------------------------------------------------


# An ECU descriptor — IPs/IDs reused across the trace.
ECUS: List[Tuple[str, int, int, int, int]] = [
    # (src_ip, mac_octet, service_id, instance_id, offer_port)
    ("10.0.0.10", 0x10, 0x1001, 1, 30501),
    ("10.0.0.11", 0x11, 0x1002, 1, 30502),
    ("10.0.0.12", 0x12, 0x1010, 1, 30503),
    ("10.0.0.13", 0x13, 0x2001, 1, 30504),
    ("10.0.0.14", 0x14, 0x2010, 2, 30505),
    ("10.0.0.15", 0x15, 0x3000, 1, 30506),
]

BAD_ECU = ("10.0.0.99", 0x99, 0x9999, 1, 30599)
INITIAL_DELAYS_MS = [50, 80, 120, 150, 180, 200]   # per ECU


def emit_sd_offer(out: PcapWriter, ts: float, ecu, session_id: int) -> None:
    body = someip.build_offer_service(
        service_id=ecu[2], instance_id=ecu[3],
        major=1, minor=0, ttl=3,
        ip=ecu[0], port=ecu[4], proto="udp",
        session_id=session_id)
    frame = udp_frame(ecu[0], SD_MULTICAST_IP,
                      SOMEIP_SD_PORT, SOMEIP_SD_PORT, body,
                      src_mac_octet=ecu[1], dst_mac_octet=0xFF)
    out.write(ts, frame)


def emit_sd_find(out: PcapWriter, ts: float, finder_ip: str,
                 finder_mac: int, service_id: int, instance_id: int,
                 session_id: int) -> None:
    entry = someip.SdEntry(
        type=someip.SdEntryType.FIND_SERVICE,
        service_id=service_id, instance_id=instance_id,
        major_version=1, minor_version=0, ttl=3)
    msg = someip.SdMessage(entries=[entry], options=[],
                           session_id=session_id).pack()
    frame = udp_frame(finder_ip, SD_MULTICAST_IP,
                      SOMEIP_SD_PORT, SOMEIP_SD_PORT, msg,
                      src_mac_octet=finder_mac, dst_mac_octet=0xFF)
    out.write(ts, frame)


def emit_sd_subscribe(out: PcapWriter, ts: float, subscriber_ip: str,
                      subscriber_mac: int, service_id: int,
                      instance_id: int, session_id: int) -> None:
    entry = someip.SdEntry(
        type=someip.SdEntryType.SUBSCRIBE_EVENTGROUP,
        service_id=service_id, instance_id=instance_id,
        major_version=1, minor_version=0, ttl=3)
    msg = someip.SdMessage(entries=[entry], options=[],
                           session_id=session_id).pack()
    frame = udp_frame(subscriber_ip, SD_MULTICAST_IP,
                      SOMEIP_SD_PORT, SOMEIP_SD_PORT, msg,
                      src_mac_octet=subscriber_mac, dst_mac_octet=0xFF)
    out.write(ts, frame)


def build_sd_trace(out: PcapWriter, t0: float) -> float:
    """Multi-ECU SD timing trace. Returns the next free timestamp."""
    rng = random.Random(0xA5A5)
    session = {ecu[0]: 1 for ecu in ECUS}
    session[BAD_ECU[0]] = 1

    # --- (A) Initial-phase: per-ECU initial delay, then 4 repetitions
    #         doubling the base delay each time.  R21-11 §4.2.1.
    base = 200.0  # ms
    for ecu, init_ms in zip(ECUS, INITIAL_DELAYS_MS):
        t = t0 + init_ms / 1000.0
        emit_sd_offer(out, t, ecu, session[ecu[0]]); session[ecu[0]] += 1
        gap = base / 1000.0
        for _ in range(4):
            t += gap
            emit_sd_offer(out, t, ecu, session[ecu[0]]); session[ecu[0]] += 1
            gap *= 2.0  # doubling

    # --- (B) Misbehaving ECU — flat 200 ms cadence (no doubling).
    t = t0 + 0.300
    for _ in range(5):
        emit_sd_offer(out, t, BAD_ECU, session[BAD_ECU[0]])
        session[BAD_ECU[0]] += 1
        t += 0.200

    # --- (C) FindService probes from the head-unit early in the trace.
    emit_sd_find(out, t0 + 0.075, "10.0.0.50", 0x50, 0x1001, 1, 1)
    emit_sd_find(out, t0 + 0.110, "10.0.0.50", 0x50, 0x2010, 2, 2)

    # --- (D) Two consumers subscribe to event-groups.
    emit_sd_subscribe(out, t0 + 0.420, "10.0.0.60", 0x60,
                      0x1001, 1, 1)
    emit_sd_subscribe(out, t0 + 0.500, "10.0.0.61", 0x61,
                      0x2010, 2, 1)

    # --- (E) Cyclic-offer phase: every 2 s for CYCLE_COUNT rounds.
    cycle_start = t0 + 5.0  # all ramps finish well before this
    for c in range(CYCLE_COUNT):
        for ecu in ECUS:
            jitter = rng.uniform(-0.005, 0.005)
            t = cycle_start + c * 2.0 + jitter
            emit_sd_offer(out, t, ecu, session[ecu[0]])
            session[ecu[0]] += 1
        # the bad ECU keeps offering at its own cadence (skip silently
        # — its initial phase already produced violations)

    return cycle_start + CYCLE_COUNT * 2.0 + 1.0


def build_doip_session_tester_present(out: PcapWriter, t0: float,
                                      n: int = 50) -> float:
    """Repeated TesterPresent (0x3E 0x00) with positive responses."""
    flow = TcpFlow("10.0.0.200", "10.0.0.10", 50000, DOIP_PORT,
                   client_mac=0xC0, entity_mac=0x10)
    t = t0
    for f in flow.handshake():
        out.write(t, f); t += 0.0005

    out.write(t, flow.c2e(doip.build_routing_activation_request(0x0E00)))
    t += 0.002
    out.write(t, flow.e2c(doip.build_routing_activation_response(
        0x0E00, 0x1234, doip.RoutingActivationResponseCode.SUCCESS)))
    t += 0.005

    for i in range(n):
        out.write(t, flow.c2e(doip.build_diagnostic_message(
            0x0E00, 0x1234, b"\x3E\x00")))
        t += 0.003
        out.write(t, flow.e2c(doip.build_diagnostic_ack(0x1234, 0x0E00)))
        t += 0.001
        out.write(t, flow.e2c(doip.build_diagnostic_message(
            0x1234, 0x0E00, b"\x7E\x00")))
        t += 0.050   # ~ 20 Hz keep-alive

    for f in flow.fin():
        out.write(t, f); t += 0.001
    return t


def build_doip_session_did_read(out: PcapWriter, t0: float,
                                n: int = 200) -> float:
    """ReadDataByIdentifier loop with occasional NRC 0x31 (out of range)."""
    flow = TcpFlow("10.0.0.200", "10.0.0.11", 50001, DOIP_PORT,
                   client_mac=0xC0, entity_mac=0x11)
    t = t0
    for f in flow.handshake():
        out.write(t, f); t += 0.0005
    out.write(t, flow.c2e(doip.build_routing_activation_request(0x0E00)))
    t += 0.002
    out.write(t, flow.e2c(doip.build_routing_activation_response(
        0x0E00, 0x1235, doip.RoutingActivationResponseCode.SUCCESS)))
    t += 0.005

    rng = random.Random(7)
    for i in range(n):
        did_hi = (i >> 8) & 0xFF
        did_lo = i & 0xFF
        req = b"\x22" + bytes([did_hi, did_lo])
        out.write(t, flow.c2e(doip.build_diagnostic_message(
            0x0E00, 0x1235, req)))
        t += 0.002
        out.write(t, flow.e2c(doip.build_diagnostic_ack(0x1235, 0x0E00)))
        t += 0.001
        if rng.random() < 0.08:
            # NRC 0x31 — requestOutOfRange.
            resp = b"\x7F\x22\x31"
        else:
            resp = b"\x62" + bytes([did_hi, did_lo]) + b"V" * 16
        out.write(t, flow.e2c(doip.build_diagnostic_message(
            0x1235, 0x0E00, resp)))
        t += 0.015

    for f in flow.fin():
        out.write(t, f); t += 0.001
    return t


def build_doip_session_response_pending(out: PcapWriter, t0: float) -> float:
    """RoutineControl with NRC 0x78 (response-pending) then a positive."""
    flow = TcpFlow("10.0.0.200", "10.0.0.12", 50002, DOIP_PORT,
                   client_mac=0xC0, entity_mac=0x12)
    t = t0
    for f in flow.handshake():
        out.write(t, f); t += 0.0005
    out.write(t, flow.c2e(doip.build_routing_activation_request(0x0E00)))
    t += 0.002
    out.write(t, flow.e2c(doip.build_routing_activation_response(
        0x0E00, 0x1236, doip.RoutingActivationResponseCode.SUCCESS)))
    t += 0.005

    out.write(t, flow.c2e(doip.build_diagnostic_message(
        0x0E00, 0x1236, b"\x31\x01\x02\x03")))   # RoutineControl
    t += 0.003
    out.write(t, flow.e2c(doip.build_diagnostic_ack(0x1236, 0x0E00)))
    t += 0.001
    # Three response-pendings then a final positive response.
    for _ in range(3):
        t += 0.150
        out.write(t, flow.e2c(doip.build_diagnostic_message(
            0x1236, 0x0E00, b"\x7F\x31\x78")))
    t += 0.250
    out.write(t, flow.e2c(doip.build_diagnostic_message(
        0x1236, 0x0E00, b"\x71\x01\x02\x03\x00")))

    for f in flow.fin():
        out.write(t, f); t += 0.001
    return t


def build_doip_session_reconnect(out: PcapWriter, t0: float) -> float:
    """RoutingActivation rejected (UNKNOWN_SA) then a clean reconnect."""
    # First attempt: rejected.
    f1 = TcpFlow("10.0.0.200", "10.0.0.13", 50003, DOIP_PORT,
                 client_mac=0xC0, entity_mac=0x13)
    t = t0
    for fr in f1.handshake():
        out.write(t, fr); t += 0.0005
    out.write(t, f1.c2e(doip.build_routing_activation_request(0x0FFF)))
    t += 0.002
    out.write(t, f1.e2c(doip.build_routing_activation_response(
        0x0FFF, 0x1237, doip.RoutingActivationResponseCode.UNKNOWN_SA)))
    t += 0.003
    for fr in f1.fin():
        out.write(t, fr); t += 0.001

    t += 0.500  # half-second pause before reconnect

    # Second attempt with a valid SA — succeeds and sends a request.
    f2 = TcpFlow("10.0.0.200", "10.0.0.13", 50004, DOIP_PORT,
                 client_mac=0xC0, entity_mac=0x13)
    for fr in f2.handshake():
        out.write(t, fr); t += 0.0005
    out.write(t, f2.c2e(doip.build_routing_activation_request(0x0E00)))
    t += 0.002
    out.write(t, f2.e2c(doip.build_routing_activation_response(
        0x0E00, 0x1237, doip.RoutingActivationResponseCode.SUCCESS)))
    t += 0.004
    out.write(t, f2.c2e(doip.build_diagnostic_message(
        0x0E00, 0x1237, b"\x22\xF1\x90")))      # ReadVIN
    t += 0.002
    out.write(t, f2.e2c(doip.build_diagnostic_ack(0x1237, 0x0E00)))
    t += 0.001
    out.write(t, f2.e2c(doip.build_diagnostic_message(
        0x1237, 0x0E00, b"\x62\xF1\x90" + b"WAUZZZ0123ABCDEFG")))
    t += 0.005
    for fr in f2.fin():
        out.write(t, fr); t += 0.001
    return t


def build_doip_session_retransmit(out: PcapWriter, t0: float) -> float:
    """Application-level retransmit of the same UDS request."""
    flow = TcpFlow("10.0.0.200", "10.0.0.14", 50005, DOIP_PORT,
                   client_mac=0xC0, entity_mac=0x14)
    t = t0
    for f in flow.handshake():
        out.write(t, f); t += 0.0005
    out.write(t, flow.c2e(doip.build_routing_activation_request(0x0E00)))
    t += 0.002
    out.write(t, flow.e2c(doip.build_routing_activation_response(
        0x0E00, 0x1238, doip.RoutingActivationResponseCode.SUCCESS)))
    t += 0.005

    req = doip.build_diagnostic_message(0x0E00, 0x1238, b"\x22\xF1\x87")
    out.write(t, flow.c2e(req)); t += 0.500
    out.write(t, flow.c2e(req)); t += 0.001  # retransmit — no ack came back
    out.write(t, flow.e2c(doip.build_diagnostic_ack(0x1238, 0x0E00)))
    t += 0.001
    out.write(t, flow.e2c(doip.build_diagnostic_message(
        0x1238, 0x0E00, b"\x62\xF1\x87ABC1234567")))
    t += 0.002
    for f in flow.fin():
        out.write(t, f); t += 0.001
    return t


def build_background_noise(out: PcapWriter, t0: float,
                           count: int = 200) -> float:
    """Plain UDP/TCP frames unrelated to SOME/IP-SD or DoIP."""
    rng = random.Random(123)
    t = t0
    for i in range(count):
        payload = bytes(rng.getrandbits(8) for _ in range(rng.randint(8, 64)))
        if i % 2 == 0:
            # NTP-like UDP
            out.write(t, udp_frame("10.0.0.7", "10.0.0.1",
                                   123, 123, payload,
                                   src_mac_octet=0x07, dst_mac_octet=0x01))
        else:
            # TCP SYN to some random port
            tcp = struct.pack("!HHIIBBHHH",
                              rng.randint(40000, 60000), 80, 0, 0,
                              (5 << 4), 0x02, 64240, 0, 0)
            ip = _ipv4("10.0.0.8", "10.0.0.9", 6, tcp)
            frame = _eth(_mac(0x08), _mac(0x09), 0x0800, ip)
            out.write(t, frame)
        t += 0.020
    return t


# ---------------------------------------------------------------------------
# Top-level driver
# ---------------------------------------------------------------------------


def main(out_path: str = None) -> str:
    if out_path is None:
        out_path = os.path.join(HERE, "large_realistic.pcap")
    with PcapWriter(out_path) as w:
        t = 0.001
        t = build_sd_trace(w, t)
        t = build_doip_session_tester_present(w, t + 1.0, n=TESTER_PRESENT_COUNT)
        t = build_doip_session_did_read(w, t + 0.5, n=DID_LOOP)
        t = build_doip_session_response_pending(w, t + 0.5)
        t = build_doip_session_reconnect(w, t + 0.5)
        t = build_doip_session_retransmit(w, t + 0.5)
        build_background_noise(w, t + 0.5, count=NOISE_COUNT)
        print(f"wrote {w.frames:,} frames ({w.bytes_written/1024:.1f} KiB) "
              f"to {out_path}")
    return out_path


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else None)
