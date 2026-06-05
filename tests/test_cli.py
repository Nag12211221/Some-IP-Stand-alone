"""End-to-end CLI tests: real pcap file → analyze → HTML report."""
from __future__ import annotations

import io
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "src"))

from someip_suite import cli
from someip_suite.protocols.pcap import PcapWriter


def _eth(src=b"\x02\x00\x00\x00\x00\x01", dst=b"\x02\x00\x00\x00\x00\x02"):
    return dst + src + b"\x08\x00"


def _ipv4_udp(payload: bytes, src=(10, 0, 0, 1), dst=(10, 0, 0, 2),
              sport=30490, dport=30490) -> bytes:
    udp_len = 8 + len(payload)
    udp = struct.pack(">HHHH", sport, dport, udp_len, 0) + payload
    ip_len = 20 + len(udp)
    ip = struct.pack(">BBHHHBBH4s4s",
                     0x45, 0, ip_len, 1, 0, 64, 17, 0,
                     bytes(src), bytes(dst))
    return _eth() + ip + udp


def _someip_sd_offer() -> bytes:
    from someip_suite.protocols import someip
    return someip.build_offer_service(
        service_id=0x1234, instance_id=0x0001, major=1, minor=0,
        ttl=10, ip="10.0.0.1", port=30501, proto="udp")


class TestCli(unittest.TestCase):
    def _make_capture(self, path: str) -> None:
        sd = _someip_sd_offer()
        with PcapWriter(path) as w:
            w.write(ts=1.0, data=_ipv4_udp(sd))
            w.write(ts=1.1, data=_ipv4_udp(sd))
            w.write(ts=1.3, data=_ipv4_udp(sd))
            w.write(ts=1.7, data=_ipv4_udp(sd))

    def test_info_command(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            pcap = os.path.join(td, "trace.pcap")
            self._make_capture(pcap)
            rc = cli.main(["prog", "info", pcap])
            self.assertEqual(rc, 0)

    def test_analyze_with_reports(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            pcap = os.path.join(td, "trace.pcap")
            html = os.path.join(td, "out.html")
            jsn = os.path.join(td, "out.json")
            self._make_capture(pcap)
            rc = cli.main(["prog", "analyze", pcap,
                           "--report", html, "--json", jsn])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.exists(html))
            self.assertTrue(os.path.exists(jsn))
            with open(html, encoding="utf-8") as fh:
                body = fh.read()
            self.assertIn("SOME/IP Diagnostics report", body)
            self.assertIn("0x1234", body)
            with open(jsn, encoding="utf-8") as fh:
                import json
                data = json.load(fh)
            self.assertGreaterEqual(data["sd"]["offers"], 3)


if __name__ == "__main__":
    unittest.main()
