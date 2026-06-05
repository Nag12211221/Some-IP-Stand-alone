"""Tests for the pcap reader/writer and the unified capture decoder."""

import io
import os
import socket
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "src"))

from someip_suite.protocols import doip, l2, pcap, someip
from someip_suite.protocols.decoder import (CaptureDecoder, DOIP_PORT,
                                            SOMEIP_SD_PORT)


# ---------------------------------------------------------------------------
# Helpers — build synthetic frames in memory
# ---------------------------------------------------------------------------


def _eth_ipv4_udp(payload: bytes, src_ip="10.0.0.1", dst_ip="10.0.0.2",
                  sport=40000, dport=SOMEIP_SD_PORT) -> bytes:
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip_total = 20 + len(udp)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, ip_total, 0, 0x4000, 64, 17, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    )
    eth = (b"\x00\x11\x22\x33\x44\x55"
           b"\x66\x77\x88\x99\xaa\xbb"
           b"\x08\x00")
    return eth + ip + udp


def _eth_ipv4_tcp(payload: bytes, *, seq: int, flags: int = 0x18,
                  src_ip="10.0.0.1", dst_ip="10.0.0.2",
                  sport=50000, dport=DOIP_PORT) -> bytes:
    tcp = struct.pack(
        "!HHIIBBHHH",
        sport, dport, seq, 0,
        (5 << 4), flags, 64240, 0, 0,
    ) + payload
    ip_total = 20 + len(tcp)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, ip_total, 0, 0x4000, 64, 6, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    )
    eth = (b"\x00\x11\x22\x33\x44\x55"
           b"\x66\x77\x88\x99\xaa\xbb"
           b"\x08\x00")
    return eth + ip + tcp


def _write_classic_pcap(records):
    buf = io.BytesIO()
    buf.write(struct.pack("<IHHiIII", pcap.PCAP_MAGIC_LE, 2, 4, 0, 0, 65535,
                          pcap.DLT_EN10MB))
    for ts, data in records:
        ts_s = int(ts)
        ts_us = int((ts - ts_s) * 1_000_000)
        buf.write(struct.pack("<IIII", ts_s, ts_us, len(data), len(data)))
        buf.write(data)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# PCAP reader/writer
# ---------------------------------------------------------------------------


class TestPcapClassic(unittest.TestCase):
    def test_reads_back_what_writer_wrote(self):
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
            path = tf.name
        try:
            with pcap.PcapWriter(path) as w:
                w.write(1700_000_000.123456, b"abc")
                w.write(1700_000_000.654321, b"defgh")
            frames = list(pcap.read_pcap(path))
            self.assertEqual(len(frames), 2)
            self.assertEqual(frames[0].data, b"abc")
            self.assertEqual(frames[1].data, b"defgh")
            self.assertEqual(frames[0].index, 1)
            self.assertEqual(frames[1].index, 2)
            self.assertAlmostEqual(frames[0].ts, 1700_000_000.123456, places=4)
        finally:
            os.unlink(path)

    def test_truncated_record_stops_cleanly(self):
        good = _write_classic_pcap([(1700_000_000.0, b"hello")])
        truncated = good + b"\x00\x00\x00\x00\xff\xff"   # partial header
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
            tf.write(truncated)
            path = tf.name
        try:
            frames = list(pcap.read_pcap(path))
            self.assertEqual(len(frames), 1)
        finally:
            os.unlink(path)

    def test_bad_magic_raises(self):
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
            tf.write(b"\xde\xad\xbe\xef" + b"\x00" * 32)
            path = tf.name
        try:
            with self.assertRaises(pcap.PcapError):
                list(pcap.read_pcap(path))
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# L2/L3/L4 decoder
# ---------------------------------------------------------------------------


class TestL2Decoder(unittest.TestCase):
    def test_eth_ipv4_udp_round_trip(self):
        frame = pcap.PcapFrame(
            index=1, ts=0.0, linktype=pcap.DLT_EN10MB,
            data=_eth_ipv4_udp(b"PAYLOAD"), orig_len=0,
        )
        pkt = l2.decode_frame(frame)
        self.assertIsNotNone(pkt)
        self.assertEqual(pkt.transport, "udp")
        self.assertEqual(pkt.src_ip, "10.0.0.1")
        self.assertEqual(pkt.dst_ip, "10.0.0.2")
        self.assertEqual(pkt.dst_port, SOMEIP_SD_PORT)
        self.assertEqual(pkt.payload, b"PAYLOAD")

    def test_eth_ipv4_tcp(self):
        frame = pcap.PcapFrame(
            index=2, ts=1.0, linktype=pcap.DLT_EN10MB,
            data=_eth_ipv4_tcp(b"ABCD", seq=1000), orig_len=0,
        )
        pkt = l2.decode_frame(frame)
        self.assertIsNotNone(pkt)
        self.assertEqual(pkt.transport, "tcp")
        self.assertEqual(pkt.payload, b"ABCD")
        self.assertEqual(pkt.tcp_seq, 1000)

    def test_non_ip_frame_returns_none(self):
        frame = pcap.PcapFrame(
            index=1, ts=0.0, linktype=pcap.DLT_EN10MB,
            data=b"\x00" * 14, orig_len=14,
        )
        self.assertIsNone(l2.decode_frame(frame))


class TestTcpReassembler(unittest.TestCase):
    def _pkt(self, data, seq, flags=0x18):
        return l2.Packet(
            frame_index=0, ts=0.0,
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=50000, dst_port=DOIP_PORT,
            transport="tcp", payload=data,
            tcp_flags=flags, tcp_seq=seq, tcp_ack=0,
        )

    def test_in_order(self):
        r = l2.TcpReassembler()
        # SYN bootstraps state
        r.feed(self._pkt(b"", 999, flags=0x02))
        new, _, _ = r.feed(self._pkt(b"AAA", 1000))
        self.assertEqual(new, b"AAA")
        new, _, _ = r.feed(self._pkt(b"BBB", 1003))
        self.assertEqual(new, b"BBB")

    def test_out_of_order_held_until_predecessor_arrives(self):
        r = l2.TcpReassembler()
        r.feed(self._pkt(b"", 999, flags=0x02))
        new, _, _ = r.feed(self._pkt(b"CCC", 1003))   # out-of-order
        self.assertEqual(new, b"")
        new, _, _ = r.feed(self._pkt(b"AAA", 1000))
        self.assertEqual(new, b"AAACCC")


# ---------------------------------------------------------------------------
# Capture decoder
# ---------------------------------------------------------------------------


class TestCaptureDecoderUdp(unittest.TestCase):
    def test_decodes_someip_sd_offer(self):
        sd_bytes = someip.build_offer_service(
            0x1234, 1, 1, 0, 10, "10.0.0.1", 30501)
        frame = pcap.PcapFrame(
            index=1, ts=42.0, linktype=pcap.DLT_EN10MB,
            data=_eth_ipv4_udp(sd_bytes, sport=SOMEIP_SD_PORT,
                               dport=SOMEIP_SD_PORT),
            orig_len=0,
        )
        msgs = list(CaptureDecoder().decode_pcap([frame]))
        self.assertEqual(len(msgs), 1)
        m = msgs[0]
        self.assertEqual(m.protocol, "someip-sd")
        self.assertIsNotNone(m.sd_message)
        self.assertEqual(m.sd_message.entries[0].service_id, 0x1234)
        self.assertEqual(m.frame_index, 1)
        self.assertEqual(m.ts, 42.0)

    def test_decodes_someip_request(self):
        hdr = someip.SomeIpHeader(
            service_id=0x1001, method_id=0x42, length=8,
            client_id=1, session_id=1,
            message_type=someip.MessageType.REQUEST,
        )
        body = hdr.pack()
        frame = pcap.PcapFrame(
            index=3, ts=1.0, linktype=pcap.DLT_EN10MB,
            data=_eth_ipv4_udp(body, sport=40000, dport=30502),
            orig_len=0,
        )
        msgs = list(CaptureDecoder().decode_pcap([frame]))
        self.assertEqual(len(msgs), 1)
        self.assertEqual(msgs[0].protocol, "someip")
        self.assertEqual(msgs[0].someip_header.service_id, 0x1001)

    def test_ignores_non_someip_udp(self):
        frame = pcap.PcapFrame(
            index=1, ts=0.0, linktype=pcap.DLT_EN10MB,
            data=_eth_ipv4_udp(b"X" * 4, sport=40000, dport=53),
            orig_len=0,
        )
        msgs = list(CaptureDecoder().decode_pcap([frame]))
        self.assertEqual(msgs, [])


class TestCaptureDecoderDoip(unittest.TestCase):
    def test_doip_routing_activation_over_tcp(self):
        body = doip.build_routing_activation_request(0x0E00)
        # send SYN then data
        syn = pcap.PcapFrame(
            index=1, ts=0.0, linktype=pcap.DLT_EN10MB,
            data=_eth_ipv4_tcp(b"", seq=999, flags=0x02), orig_len=0)
        data_frame = pcap.PcapFrame(
            index=2, ts=0.1, linktype=pcap.DLT_EN10MB,
            data=_eth_ipv4_tcp(body, seq=1000), orig_len=0)
        msgs = list(CaptureDecoder().decode_pcap([syn, data_frame]))
        self.assertEqual(len(msgs), 1)
        m = msgs[0]
        self.assertEqual(m.protocol, "doip")
        self.assertEqual(
            m.doip_header.payload_type, doip.PayloadType.ROUTING_ACTIVATION_REQ)

    def test_doip_split_across_two_tcp_segments(self):
        body = doip.build_diagnostic_message(0x0E00, 0x1234, b"\x22\xF1\x90")
        split = 6
        seg1 = body[:split]
        seg2 = body[split:]
        syn = pcap.PcapFrame(
            index=1, ts=0.0, linktype=pcap.DLT_EN10MB,
            data=_eth_ipv4_tcp(b"", seq=99, flags=0x02), orig_len=0)
        f1 = pcap.PcapFrame(
            index=2, ts=0.1, linktype=pcap.DLT_EN10MB,
            data=_eth_ipv4_tcp(seg1, seq=100), orig_len=0)
        f2 = pcap.PcapFrame(
            index=3, ts=0.2, linktype=pcap.DLT_EN10MB,
            data=_eth_ipv4_tcp(seg2, seq=100 + split), orig_len=0)
        msgs = list(CaptureDecoder().decode_pcap([syn, f1, f2]))
        self.assertEqual(len(msgs), 1)
        self.assertEqual(msgs[0].protocol, "doip")
        # first byte came from frame 2 (after SYN)
        self.assertEqual(msgs[0].frame_index, 2)

    def test_doip_two_back_to_back_messages(self):
        a = doip.build_alive_check_request()
        b = doip.build_alive_check_response(0x0E00)
        syn = pcap.PcapFrame(
            index=1, ts=0.0, linktype=pcap.DLT_EN10MB,
            data=_eth_ipv4_tcp(b"", seq=0, flags=0x02), orig_len=0)
        f1 = pcap.PcapFrame(
            index=2, ts=0.1, linktype=pcap.DLT_EN10MB,
            data=_eth_ipv4_tcp(a + b, seq=1), orig_len=0)
        msgs = list(CaptureDecoder().decode_pcap([syn, f1]))
        self.assertEqual(len(msgs), 2)
        self.assertEqual(msgs[0].doip_header.payload_type,
                         doip.PayloadType.ALIVE_CHECK_REQ)
        self.assertEqual(msgs[1].doip_header.payload_type,
                         doip.PayloadType.ALIVE_CHECK_RES)


if __name__ == "__main__":
    unittest.main()
