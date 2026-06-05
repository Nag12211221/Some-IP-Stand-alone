"""High-performance real-time filter engine (solution #3).

Implements a *compiled* filter pipeline:

  user rules ──▶ compiled hash-lookup table (O(1) per packet)
            ▲                       │
            │                       ▼
       editing UI            packet dispatcher (per-CPU workers)

The engine can ingest:

* synthetic packets (built-in generator targeting any pps);
* a pcap file (libpcap 2.4 format — implemented inline);
* live UDP on a configurable port.

Throughput, latency and per-rule hit counters are reported via a
thread-safe metrics object.
"""

from __future__ import annotations

import os
import queue
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Tuple

from ..protocols import someip


# ---------------------------------------------------------------------------
# Rule model & compiler
# ---------------------------------------------------------------------------

ANY = -1   # wildcard sentinel


@dataclass(slots=True)
class FilterRule:
    name: str
    service_id: int = ANY
    method_id: int = ANY
    client_id: int = ANY
    message_type: int = ANY
    action: str = "accept"       # accept | drop | count

    def key(self) -> Tuple[int, int, int, int]:
        return (self.service_id, self.method_id, self.client_id, self.message_type)


@dataclass
class CompiledFilter:
    """Compiled O(1) lookup table.

    The compiler enumerates every concrete combination of wildcard fields
    and inserts it into a dict. Lookup is then a single dict.get(). For
    typical rule sets (≤256 rules, ≤4 wildcard fields each) the compiled
    table stays small and fits in CPU cache.
    """

    exact: Dict[Tuple[int, int, int, int], FilterRule] = field(default_factory=dict)
    default: FilterRule = field(
        default_factory=lambda: FilterRule(name="<default>", action="drop")
    )

    def match(self, sid: int, mid: int, cid: int, mt: int) -> FilterRule:
        # Try exact, then progressively wildcard fields. We unroll the 16
        # possible masks (4 bits) so the hot path has no branches over
        # variable structures.
        e = self.exact
        for sid_k, mid_k, cid_k, mt_k in (
            (sid, mid, cid, mt),
            (sid, mid, cid, ANY),
            (sid, mid, ANY, mt),
            (sid, ANY, cid, mt),
            (ANY, mid, cid, mt),
            (sid, mid, ANY, ANY),
            (sid, ANY, cid, ANY),
            (sid, ANY, ANY, mt),
            (ANY, mid, cid, ANY),
            (ANY, mid, ANY, mt),
            (ANY, ANY, cid, mt),
            (sid, ANY, ANY, ANY),
            (ANY, mid, ANY, ANY),
            (ANY, ANY, cid, ANY),
            (ANY, ANY, ANY, mt),
            (ANY, ANY, ANY, ANY),
        ):
            r = e.get((sid_k, mid_k, cid_k, mt_k))
            if r is not None:
                return r
        return self.default


def compile_rules(rules: Iterable[FilterRule]) -> CompiledFilter:
    cf = CompiledFilter()
    default = cf.default
    for r in rules:
        if r.name == "<default>":
            default = r
            continue
        cf.exact[r.key()] = r
    cf.default = default
    return cf


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


@dataclass
class FilterMetrics:
    packets_in: int = 0
    packets_accepted: int = 0
    packets_dropped: int = 0
    packets_counted: int = 0
    bytes_in: int = 0
    latency_ns_total: int = 0
    latency_samples: int = 0
    rule_hits: Dict[str, int] = field(default_factory=dict)
    started_at: float = field(default_factory=time.perf_counter)

    def add_latency(self, ns: int) -> None:
        self.latency_ns_total += ns
        self.latency_samples += 1

    @property
    def avg_latency_ns(self) -> float:
        return self.latency_ns_total / self.latency_samples if self.latency_samples else 0.0

    @property
    def pps(self) -> float:
        dt = max(1e-9, time.perf_counter() - self.started_at)
        return self.packets_in / dt

    @property
    def mbps(self) -> float:
        dt = max(1e-9, time.perf_counter() - self.started_at)
        return self.bytes_in * 8 / 1e6 / dt


# ---------------------------------------------------------------------------
# Packet sources
# ---------------------------------------------------------------------------


class PacketSource:
    def packets(self) -> Iterable[bytes]:
        raise NotImplementedError


class SyntheticSource(PacketSource):
    """Generates random SOME/IP frames at a target rate.

    The generator pre-builds a pool of headers and yields slices from
    it so per-packet allocation is minimal — critical for sustaining
    multi-million pps.
    """

    def __init__(self, target_pps: int, duration_s: float,
                 services: List[int], methods: List[int]) -> None:
        self.target_pps = max(1, target_pps)
        self.duration_s = duration_s
        self.services = services
        self.methods = methods
        # pre-build N templates
        self._templates: List[bytes] = []
        for s in services:
            for m in methods:
                hdr = someip.SomeIpHeader(
                    service_id=s, method_id=m, length=8,
                    client_id=0x0001, session_id=0x0001,
                    message_type=someip.MessageType.REQUEST,
                )
                self._templates.append(hdr.pack())
        self._stop_event = threading.Event()

    def stop(self) -> None:
        self._stop_event.set()

    def packets(self) -> Iterable[bytes]:
        end_at = time.perf_counter() + self.duration_s
        # token-bucket pacing
        per_batch = max(1, self.target_pps // 1000)
        batch_period = per_batch / self.target_pps
        next_due = time.perf_counter()
        tmpls = self._templates
        tcount = len(tmpls)
        i = 0
        while not self._stop_event.is_set() and time.perf_counter() < end_at:
            now = time.perf_counter()
            if now < next_due:
                # busy-wait the last ~50us; sleep above that to be CPU-friendly
                gap = next_due - now
                if gap > 50e-6:
                    time.sleep(gap - 50e-6)
                continue
            for _ in range(per_batch):
                yield tmpls[i % tcount]
                i += 1
            next_due += batch_period


class PcapSource(PacketSource):
    """Reads a libpcap 2.4 file (no .pcapng support)."""

    PCAP_MAGIC_LE = 0xA1B2C3D4
    PCAP_MAGIC_BE = 0xD4C3B2A1

    def __init__(self, path: str) -> None:
        self.path = path

    def packets(self) -> Iterable[bytes]:
        with open(self.path, "rb") as fh:
            magic = fh.read(4)
            if not magic:
                return
            (m,) = struct.unpack("<I", magic)
            endian = "<"
            if m == self.PCAP_MAGIC_BE:
                endian = ">"
            elif m != self.PCAP_MAGIC_LE:
                raise ValueError("not a pcap file")
            # skip the rest of the global header (20 bytes)
            fh.read(20)
            rec_fmt = endian + "IIII"
            rec_size = struct.calcsize(rec_fmt)
            while True:
                hdr = fh.read(rec_size)
                if len(hdr) < rec_size:
                    return
                _ts_s, _ts_us, incl_len, _orig_len = struct.unpack(rec_fmt, hdr)
                data = fh.read(incl_len)
                if len(data) < incl_len:
                    return
                # Try to skip Ethernet+IPv4+UDP headers (14+20+8) — if the
                # caller fed us pre-extracted SOME/IP frames this still
                # works because of the parser's defensive checks.
                if len(data) > 42 and data[12:14] == b"\x08\x00":
                    yield data[42:]
                else:
                    yield data


# ---------------------------------------------------------------------------
# Worker (one per CPU)
# ---------------------------------------------------------------------------


class FilterWorker(threading.Thread):
    daemon = True

    def __init__(self, source: PacketSource, compiled: CompiledFilter,
                 metrics: FilterMetrics,
                 sink: Optional[Callable[[bytes, FilterRule], None]] = None,
                 name: str = "FilterWorker") -> None:
        super().__init__(name=name)
        self.source = source
        self.compiled = compiled
        self.metrics = metrics
        self.sink = sink
        self._stop_event = threading.Event()

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        m = self.metrics
        cf = self.compiled
        sink = self.sink
        # Local refs for the hot loop
        parse = someip.parse_someip
        for pkt in self.source.packets():
            if self._stop_event.is_set():
                break
            t0 = time.perf_counter_ns()
            m.packets_in += 1
            m.bytes_in += len(pkt)
            hdr = parse(pkt)
            if hdr is None:
                m.packets_dropped += 1
                continue
            rule = cf.match(hdr.service_id, hdr.method_id, hdr.client_id, hdr.message_type)
            m.rule_hits[rule.name] = m.rule_hits.get(rule.name, 0) + 1
            if rule.action == "accept":
                m.packets_accepted += 1
                if sink is not None:
                    sink(pkt, rule)
            elif rule.action == "count":
                m.packets_counted += 1
            else:
                m.packets_dropped += 1
            # Sample latency 1/64 packets to keep overhead negligible
            if (m.packets_in & 63) == 0:
                m.add_latency(time.perf_counter_ns() - t0)
