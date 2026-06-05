"""End-to-end tests for the engine modules.

Run with:  python -m unittest discover -s tests
"""

import socket
import time
import unittest

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "src"))

from someip_suite.protocols import someip, doip
from someip_suite.modules import sd_analyzer, doip_monitor, filter_engine


class TestSomeIp(unittest.TestCase):
    def test_header_round_trip(self):
        h = someip.SomeIpHeader(0x1234, 0x0042, 8, 0x0001, 0x0002,
                                message_type=someip.MessageType.REQUEST)
        self.assertEqual(someip.SomeIpHeader.unpack(h.pack()), h)

    def test_sd_offer_round_trip(self):
        buf = someip.build_offer_service(0x1234, 1, 1, 0, 10,
                                         "10.0.0.1", 30501)
        msg = someip.SdMessage.unpack(buf)
        self.assertEqual(len(msg.entries), 1)
        self.assertEqual(len(msg.options), 1)
        self.assertEqual(msg.entries[0].service_id, 0x1234)


class TestDoip(unittest.TestCase):
    def test_header_inverted_check(self):
        b = doip.build(doip.PayloadType.ALIVE_CHECK_REQ, b"")
        h = doip.DoipHeader.unpack(b)
        self.assertEqual(h.payload_type, doip.PayloadType.ALIVE_CHECK_REQ)

    def test_bad_header_rejected(self):
        with self.assertRaises(ValueError):
            doip.DoipHeader.unpack(b"\x02\x02" + b"\x00" * 6)


class TestSdSimulator(unittest.TestCase):
    def test_deterministic(self):
        s1 = sd_analyzer.SdSimulator(sd_analyzer.default_scenario(),
                                     duration_ms=3000, seed=7).run()
        s2 = sd_analyzer.SdSimulator(sd_analyzer.default_scenario(),
                                     duration_ms=3000, seed=7).run()
        self.assertEqual(len(s1.events), len(s2.events))
        self.assertEqual(s1.discovery_latency_ms, s2.discovery_latency_ms)

    def test_no_violations_with_safe_defaults(self):
        rep = sd_analyzer.SdSimulator(sd_analyzer.default_scenario(),
                                      duration_ms=5000, seed=1).run()
        self.assertEqual(rep.summary()["violations"], 0)


class TestFilterEngine(unittest.TestCase):
    def test_wildcard_match(self):
        cf = filter_engine.compile_rules([
            filter_engine.FilterRule("svc1", service_id=0x1001, action="accept"),
            filter_engine.FilterRule("<default>", action="drop"),
        ])
        self.assertEqual(cf.match(0x1001, 1, 2, 0).name, "svc1")
        self.assertEqual(cf.match(0x9999, 1, 2, 0).name, "<default>")

    def test_worker_runs(self):
        cf = filter_engine.compile_rules([
            filter_engine.FilterRule("a", service_id=0x1001, action="accept"),
            filter_engine.FilterRule("<default>", action="drop"),
        ])
        src = filter_engine.SyntheticSource(20_000, 0.2,
                                            [0x1001, 0x2001], [1, 2])
        m = filter_engine.FilterMetrics()
        w = filter_engine.FilterWorker(src, cf, m)
        w.start(); w.join(timeout=5)
        self.assertGreater(m.packets_in, 0)
        self.assertEqual(m.packets_in,
                         m.packets_accepted + m.packets_dropped + m.packets_counted)


def _free_port() -> int:
    s = socket.socket(); s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]; s.close()
    return p


class TestDoipLoopback(unittest.TestCase):
    def test_full_session(self):
        cfg = doip_monitor.FlashConfig(host="127.0.0.1", port=_free_port(),
                                       block_count=8, block_size=64,
                                       processing_time_ms=1,
                                       alive_check_interval_ms=2000)
        srv = doip_monitor.DoipEntityServer(cfg, log=lambda _m: None)
        srv.start(); time.sleep(0.2)
        try:
            metrics = doip_monitor.FlashMetrics()
            t = doip_monitor.DoipFlashTester(cfg, metrics,
                                             log=lambda _m: None)
            t.start(); t.join(timeout=10)
            self.assertEqual(metrics.blocks_acked, 8)
            self.assertEqual(metrics.errors, 0)
        finally:
            srv.stop()

    def test_drop_and_resume(self):
        cfg = doip_monitor.FlashConfig(host="127.0.0.1", port=_free_port(),
                                       block_count=10, block_size=64,
                                       processing_time_ms=1,
                                       drop_after_blocks=5,
                                       alive_check_interval_ms=5000)
        srv = doip_monitor.DoipEntityServer(cfg, log=lambda _m: None)
        srv.start(); time.sleep(0.2)
        try:
            metrics = doip_monitor.FlashMetrics()
            t = doip_monitor.DoipFlashTester(cfg, metrics,
                                             log=lambda _m: None)
            t.start(); t.join(timeout=15)
            self.assertEqual(metrics.blocks_acked, 10)
            self.assertEqual(metrics.reconnects, 1)
        finally:
            srv.stop()


if __name__ == "__main__":
    unittest.main()
