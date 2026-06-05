"""Tests for the offline SD analyser and DoIP session reconstructor."""

import os
import socket
import struct
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "src"))

from someip_suite.modules import doip_offline, sd_offline
from someip_suite.protocols import doip, pcap, someip
from someip_suite.protocols.decoder import (CaptureDecoder, DOIP_PORT,
                                            SOMEIP_SD_PORT)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _udp_frame(payload, *, ts, sport, dport, src_ip="10.0.0.1",
               dst_ip="10.0.0.2"):
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 20 + len(udp), 0, 0x4000, 64, 17, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    eth = b"\x00" * 12 + b"\x08\x00"
    return pcap.PcapFrame(index=0, ts=ts, linktype=pcap.DLT_EN10MB,
                          data=eth + ip + udp, orig_len=0)


def _tcp_frame(payload, *, ts, seq, flags=0x18, sport, dport,
               src_ip="10.0.0.1", dst_ip="10.0.0.2"):
    tcp = struct.pack(
        "!HHIIBBHHH",
        sport, dport, seq, 0,
        (5 << 4), flags, 64240, 0, 0,
    ) + payload
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 20 + len(tcp), 0, 0x4000, 64, 6, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    eth = b"\x00" * 12 + b"\x08\x00"
    return pcap.PcapFrame(index=0, ts=ts, linktype=pcap.DLT_EN10MB,
                          data=eth + ip + tcp, orig_len=0)


def _set_indexes(frames):
    for i, f in enumerate(frames, start=1):
        f.index = i
    return frames


# ---------------------------------------------------------------------------
# SD offline analyser
# ---------------------------------------------------------------------------


class TestSdOffline(unittest.TestCase):
    def _offer(self, ts, src_ip, sid, inst, ttl=10):
        body = someip.build_offer_service(sid, inst, 1, 0, ttl,
                                          src_ip, 30501)
        return _udp_frame(body, ts=ts,
                          sport=SOMEIP_SD_PORT, dport=SOMEIP_SD_PORT,
                          src_ip=src_ip, dst_ip="224.224.224.245")

    def test_groups_offers_per_ecu_and_service(self):
        frames = _set_indexes([
            self._offer(0.100, "10.0.0.1", 0x1001, 1),
            self._offer(0.300, "10.0.0.1", 0x1001, 1),   # rep #2
            self._offer(0.700, "10.0.0.1", 0x1001, 1),   # rep #3 (doubled)
            self._offer(1.500, "10.0.0.1", 0x1001, 1),   # rep #4 (doubled)
            self._offer(3.500, "10.0.0.1", 0x1001, 1),   # cyclic
            self._offer(5.500, "10.0.0.1", 0x1001, 1),   # cyclic
            self._offer(0.150, "10.0.0.2", 0x2001, 1),   # different ECU
        ])
        msgs = list(CaptureDecoder().decode_pcap(frames))
        report = sd_offline.analyse_sd(msgs)
        self.assertEqual(len(report.timings), 2)
        self.assertEqual(len(report.ecus), 2)
        t1 = next(t for t in report.timings if t.src_ip == "10.0.0.1")
        self.assertEqual(len(t1.offers), 6)
        # First offer at relative t=0
        self.assertEqual(t1.initial_delay_ms, 0.0)
        # First repetition gap ~200ms
        self.assertAlmostEqual(t1.estimated_repetitions_base_ms(), 200.0,
                               places=1)
        # Cyclic ~2000ms
        cyc = t1.estimated_cyclic_offer_ms()
        self.assertIsNotNone(cyc)
        # Cyclic estimator uses median of last 4 gaps; with the ramp included
        # we expect ≥1.4s (gaps tail = [400,800,2000,2000], median=1400).
        self.assertGreaterEqual(cyc, 1400.0)
        self.assertEqual(report.violations, [])

    def test_flags_back_off_violation(self):
        # offers without doubling back-off
        frames = _set_indexes([
            self._offer(0.0, "10.0.0.1", 0x1001, 1),
            self._offer(0.2, "10.0.0.1", 0x1001, 1),    # +200ms
            self._offer(0.4, "10.0.0.1", 0x1001, 1),    # +200ms (no doubling)
            self._offer(0.6, "10.0.0.1", 0x1001, 1),
        ])
        msgs = list(CaptureDecoder().decode_pcap(frames))
        report = sd_offline.analyse_sd(msgs)
        kinds = {v.kind for v in report.violations}
        self.assertIn("missing-exponential-backoff", kinds)

    def test_initial_delay_too_large(self):
        # Force a long initial delay by spacing first offers far apart
        frames = _set_indexes([
            # base ts message — sets the trace zero
            self._offer(0.0, "10.0.0.2", 0x2001, 1),
            # ECU1 first offer at +4s from trace zero
            self._offer(4.0, "10.0.0.1", 0x1001, 1),
        ])
        msgs = list(CaptureDecoder().decode_pcap(frames))
        exp = sd_offline.SdExpectations(initial_delay_max_ms=2000.0)
        report = sd_offline.analyse_sd(msgs, exp)
        self.assertTrue(any(v.kind == "initial-delay-too-large"
                            for v in report.violations))

    def test_subscribes_and_finds_collected(self):
        # craft a SubscribeEventgroup directly
        entry = someip.SdEntry(
            type=someip.SdEntryType.SUBSCRIBE_EVENTGROUP,
            service_id=0x1001, instance_id=1, major_version=1,
            minor_version=0, ttl=10)
        msg = someip.SdMessage(entries=[entry], options=[]).pack()
        frames = _set_indexes([
            _udp_frame(msg, ts=0.0, sport=SOMEIP_SD_PORT, dport=SOMEIP_SD_PORT)
        ])
        report = sd_offline.analyse_sd(CaptureDecoder().decode_pcap(frames))
        self.assertEqual(len(report.subscribes), 1)


# ---------------------------------------------------------------------------
# DoIP offline reconstructor
# ---------------------------------------------------------------------------


class _TcpFlow:
    """Track per-direction sequence numbers so synthetic captures are valid."""

    def __init__(self, client_ip="10.0.0.1", entity_ip="10.0.0.2",
                 client_port=50000, entity_port=DOIP_PORT) -> None:
        self.client = (client_ip, client_port)
        self.entity = (entity_ip, entity_port)
        self.seq_c2e = 1     # next byte to send from client (after SYN consumes 1)
        self.seq_e2c = 1
        self.ts = 0.0
        self.frames = []

    def _tick(self, dt: float) -> float:
        self.ts += dt
        return self.ts

    def syn_c2e(self, dt=0.001):
        self.frames.append(_tcp_frame(
            b"", ts=self._tick(dt), seq=0, flags=0x02,
            sport=self.client[1], dport=self.entity[1],
            src_ip=self.client[0], dst_ip=self.entity[0]))

    def syn_e2c(self, dt=0.001):
        self.frames.append(_tcp_frame(
            b"", ts=self._tick(dt), seq=0, flags=0x02,
            sport=self.entity[1], dport=self.client[1],
            src_ip=self.entity[0], dst_ip=self.client[0]))

    def c2e(self, payload: bytes, dt=0.005):
        self.frames.append(_tcp_frame(
            payload, ts=self._tick(dt), seq=self.seq_c2e,
            sport=self.client[1], dport=self.entity[1],
            src_ip=self.client[0], dst_ip=self.entity[0]))
        self.seq_c2e += len(payload)

    def e2c(self, payload: bytes, dt=0.005):
        self.frames.append(_tcp_frame(
            payload, ts=self._tick(dt), seq=self.seq_e2c,
            sport=self.entity[1], dport=self.client[1],
            src_ip=self.entity[0], dst_ip=self.client[0]))
        self.seq_e2c += len(payload)


def _doip_session_frames():
    """Build a synthetic but realistic DoIP TCP session."""
    f = _TcpFlow()
    f.syn_c2e()
    f.syn_e2c()
    f.c2e(doip.build_routing_activation_request(0x0E00))
    f.e2c(doip.build_routing_activation_response(
        0x0E00, 0x1234, doip.RoutingActivationResponseCode.SUCCESS))
    f.c2e(doip.build_diagnostic_message(0x0E00, 0x1234, b"\x3E\x00"))
    f.e2c(doip.build_diagnostic_ack(0x1234, 0x0E00))
    f.e2c(doip.build_diagnostic_message(0x1234, 0x0E00, b"\x7E\x00"))
    return _set_indexes(f.frames)


class TestDoipOffline(unittest.TestCase):
    def test_reconstructs_session(self):
        msgs = list(CaptureDecoder().decode_pcap(_doip_session_frames()))
        rep = doip_offline.reconstruct_doip(msgs)
        self.assertEqual(len(rep.sessions), 1)
        s = rep.sessions[0]
        self.assertEqual(s.routing_activation_rc,
                         doip.RoutingActivationResponseCode.SUCCESS)
        self.assertIsNotNone(s.routing_activation_latency_ms)
        self.assertEqual(len(s.exchanges), 1)
        e = s.exchanges[0]
        self.assertEqual(e.sa, 0x0E00)
        self.assertEqual(e.ta, 0x1234)
        self.assertEqual(e.sid, 0x3E)
        self.assertIsNotNone(e.ack_frame)
        self.assertIsNotNone(e.response_frame)
        self.assertIsNotNone(e.rtt_ms)
        summary = rep.summary()
        self.assertEqual(summary["sessions"], 1)
        self.assertEqual(summary["uds_exchanges"], 1)
        self.assertEqual(summary["reconnects"], 0)
        self.assertEqual(summary["negative_responses"], 0)

    def test_detects_negative_response(self):
        f = _TcpFlow()
        f.syn_c2e()
        f.syn_e2c()
        f.c2e(doip.build_diagnostic_message(0x0E00, 0x1234, b"\x22\xF1\x90"))
        f.e2c(doip.build_diagnostic_message(0x1234, 0x0E00,
                                            b"\x7F\x22\x31"))
        msgs = list(CaptureDecoder().decode_pcap(_set_indexes(f.frames)))
        rep = doip_offline.reconstruct_doip(msgs)
        self.assertEqual(rep.summary()["negative_responses"], 1)
        e = rep.sessions[0].exchanges[0]
        self.assertEqual(e.nrc, 0x31)

    def test_detects_retransmit(self):
        f = _TcpFlow(client_port=50001)
        f.syn_c2e()
        f.syn_e2c()
        req = doip.build_diagnostic_message(0x0E00, 0x1234, b"\x22\xF1\x90")
        f.c2e(req)
        f.c2e(req)   # application-layer retransmit (no intervening ack/response)
        msgs = list(CaptureDecoder().decode_pcap(_set_indexes(f.frames)))
        rep = doip_offline.reconstruct_doip(msgs)
        self.assertEqual(rep.summary()["retransmits"], 1)


if __name__ == "__main__":
    unittest.main()
