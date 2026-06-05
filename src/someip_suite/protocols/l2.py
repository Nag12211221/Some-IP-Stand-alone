"""Layer 2 / Layer 3 / Layer 4 decoders used by the capture pipeline.

Pure standard library. The goal is to turn a raw frame into a
:class:`Packet` with enough information for SOME/IP and DoIP analysis
without pulling in `scapy` or `dpkt` — both of which would inflate the
EXE by 5–10 MB and pull in numpy in some configurations.

Supported:

* Ethernet II (DLT_EN10MB), optional single VLAN tag (802.1Q)
* Linux SLL (DLT_LINUX_SLL — "any" device captures from tcpdump on Linux)
* Raw IP (DLT_RAW), DLT_IPV4, DLT_IPV6, DLT_NULL (BSD loopback)
* IPv4 (with options) and IPv6 (no extension-header chain — rare in
  automotive traffic; if seen we surface the next-header verbatim)
* UDP and TCP (full header parse, port + payload)

The TCP **reassembler** is a half-stream stitcher tuned for DoIP: it
joins consecutive in-order segments per (src, dst, sport, dport) into
contiguous byte streams so the DoIP/SOME/IP frame parsers above never
see torn headers.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

from .pcap import (DLT_EN10MB, DLT_IPV4, DLT_IPV6, DLT_LINUX_SLL,
                   DLT_NULL, DLT_RAW, PcapFrame)


ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_QINQ = 0x88A8

IPPROTO_TCP = 6
IPPROTO_UDP = 17


@dataclass(slots=True)
class Packet:
    """One decoded L4 packet, ready for SOME/IP / DoIP parsing."""

    frame_index: int
    ts: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    transport: str           # "udp" or "tcp"
    payload: bytes           # L4 payload (already stripped of TCP/UDP hdr)
    vlan: Optional[int] = None
    tcp_flags: int = 0
    tcp_seq: int = 0
    tcp_ack: int = 0

    @property
    def src(self) -> str:
        return f"{self.src_ip}:{self.src_port}"

    @property
    def dst(self) -> str:
        return f"{self.dst_ip}:{self.dst_port}"

    @property
    def flow_key(self) -> Tuple[str, str, int, int, str]:
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port,
                self.transport)


# ---------------------------------------------------------------------------
# L2 → L3
# ---------------------------------------------------------------------------


def _strip_link(frame: PcapFrame) -> Tuple[Optional[int], bytes, Optional[int]]:
    """Return ``(ethertype, l3_bytes, vlan_id)`` or ``(None, b"", None)``."""
    data = frame.data
    lt = frame.linktype
    vlan: Optional[int] = None

    if lt == DLT_EN10MB:
        if len(data) < 14:
            return None, b"", None
        et = struct.unpack_from("!H", data, 12)[0]
        off = 14
        # one VLAN tag, optionally double-tagged
        while et in (ETHERTYPE_VLAN, ETHERTYPE_QINQ) and len(data) >= off + 4:
            tci = struct.unpack_from("!H", data, off)[0]
            vlan = tci & 0x0FFF
            et = struct.unpack_from("!H", data, off + 2)[0]
            off += 4
        return et, data[off:], vlan

    if lt == DLT_LINUX_SLL:
        if len(data) < 16:
            return None, b"", None
        et = struct.unpack_from("!H", data, 14)[0]
        return et, data[16:], None

    if lt == DLT_NULL:
        if len(data) < 4:
            return None, b"", None
        family = struct.unpack("<I", data[:4])[0]
        if family == 2:
            return ETHERTYPE_IPV4, data[4:], None
        if family in (24, 28, 30):
            return ETHERTYPE_IPV6, data[4:], None
        return None, b"", None

    if lt == DLT_RAW or lt == DLT_IPV4:
        return ETHERTYPE_IPV4, data, None
    if lt == DLT_IPV6:
        return ETHERTYPE_IPV6, data, None

    return None, b"", None


# ---------------------------------------------------------------------------
# L3 → L4
# ---------------------------------------------------------------------------


def _decode_ipv4(buf: bytes) -> Optional[Tuple[str, str, int, bytes]]:
    if len(buf) < 20:
        return None
    ver_ihl = buf[0]
    if (ver_ihl >> 4) != 4:
        return None
    ihl = (ver_ihl & 0x0F) * 4
    if ihl < 20 or len(buf) < ihl:
        return None
    total_len = struct.unpack_from("!H", buf, 2)[0]
    # Honor total length when sensible (caps trailers from Ethernet padding)
    end = min(len(buf), total_len) if total_len >= ihl else len(buf)
    proto = buf[9]
    src = socket.inet_ntop(socket.AF_INET, buf[12:16])
    dst = socket.inet_ntop(socket.AF_INET, buf[16:20])
    return src, dst, proto, buf[ihl:end]


def _decode_ipv6(buf: bytes) -> Optional[Tuple[str, str, int, bytes]]:
    if len(buf) < 40:
        return None
    if (buf[0] >> 4) != 6:
        return None
    payload_len = struct.unpack_from("!H", buf, 4)[0]
    nxt = buf[6]
    src = socket.inet_ntop(socket.AF_INET6, buf[8:24])
    dst = socket.inet_ntop(socket.AF_INET6, buf[24:40])
    end = min(len(buf), 40 + payload_len) if payload_len else len(buf)
    return src, dst, nxt, buf[40:end]


def _decode_udp(buf: bytes) -> Optional[Tuple[int, int, bytes]]:
    if len(buf) < 8:
        return None
    sport, dport, length, _csum = struct.unpack_from("!HHHH", buf)
    end = min(len(buf), length) if 8 <= length <= len(buf) else len(buf)
    return sport, dport, buf[8:end]


def _decode_tcp(buf: bytes) -> Optional[Tuple[int, int, bytes, int, int, int]]:
    if len(buf) < 20:
        return None
    sport, dport, seq, ack = struct.unpack_from("!HHII", buf)
    data_off = (buf[12] >> 4) * 4
    flags = buf[13]
    if data_off < 20 or len(buf) < data_off:
        return None
    return sport, dport, buf[data_off:], flags, seq, ack


# ---------------------------------------------------------------------------
# Public pipeline
# ---------------------------------------------------------------------------


def decode_frame(frame: PcapFrame) -> Optional[Packet]:
    """Decode one captured frame into a :class:`Packet`, or ``None``."""
    et, l3, vlan = _strip_link(frame)
    if et == ETHERTYPE_IPV4:
        ip = _decode_ipv4(l3)
    elif et == ETHERTYPE_IPV6:
        ip = _decode_ipv6(l3)
    else:
        return None
    if ip is None:
        return None
    src_ip, dst_ip, proto, l4 = ip

    if proto == IPPROTO_UDP:
        udp = _decode_udp(l4)
        if udp is None:
            return None
        sport, dport, payload = udp
        return Packet(frame_index=frame.index, ts=frame.ts,
                      src_ip=src_ip, dst_ip=dst_ip,
                      src_port=sport, dst_port=dport,
                      transport="udp", payload=payload, vlan=vlan)
    if proto == IPPROTO_TCP:
        tcp = _decode_tcp(l4)
        if tcp is None:
            return None
        sport, dport, payload, flags, seq, ack = tcp
        return Packet(frame_index=frame.index, ts=frame.ts,
                      src_ip=src_ip, dst_ip=dst_ip,
                      src_port=sport, dst_port=dport,
                      transport="tcp", payload=payload, vlan=vlan,
                      tcp_flags=flags, tcp_seq=seq, tcp_ack=ack)
    return None


def decode_frames(frames: Iterable[PcapFrame]) -> Iterator[Packet]:
    """Yield :class:`Packet` objects for every decodable IP/UDP/TCP frame."""
    for f in frames:
        pkt = decode_frame(f)
        if pkt is not None:
            yield pkt


# ---------------------------------------------------------------------------
# TCP reassembly — enough for DoIP
# ---------------------------------------------------------------------------


@dataclass
class _TcpHalfStream:
    base_seq: int = 0
    buf: bytearray = field(default_factory=bytearray)
    initialised: bool = False
    # Frame index of the first byte currently sitting at buf[0], so we can
    # tell the DoIP parser *which* original frame a reassembled message
    # started in.
    first_frame: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0


class TcpReassembler:
    """Per-half-stream byte reassembler keyed on the 5-tuple.

    DoIP messages can straddle TCP segments and even arrive interleaved
    with AliveCheck requests on the same socket. The reassembler stitches
    them into a contiguous byte stream that the DoIP parser can read with
    a simple offset-based loop. Out-of-order segments are buffered and
    re-applied when their predecessor arrives.
    """

    def __init__(self) -> None:
        self._streams: Dict[Tuple[str, str, int, int], _TcpHalfStream] = {}
        self._pending: Dict[Tuple[str, str, int, int], List[Tuple[int, bytes, int, float]]] = {}

    def reset(self, key: Tuple[str, str, int, int]) -> None:
        self._streams.pop(key, None)
        self._pending.pop(key, None)

    def feed(self, pkt: Packet) -> Tuple[bytes, int, float]:
        """Append ``pkt`` to its half-stream and return ``(new_bytes, first_frame, first_ts)``.

        ``new_bytes`` is the freshly-appended contiguous prefix (may be
        empty if the segment is out-of-order). ``first_frame``/``first_ts``
        identify the originating capture frame so error messages and the
        UI can cite a packet number.
        """
        # Handle TCP reset / SYN: reset the half-stream
        if pkt.tcp_flags & 0x04:    # RST
            self.reset((pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port))
            return b"", pkt.frame_index, pkt.ts
        key = (pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port)
        s = self._streams.get(key)
        if pkt.tcp_flags & 0x02:    # SYN
            s = _TcpHalfStream(base_seq=(pkt.tcp_seq + 1) & 0xFFFFFFFF,
                               initialised=True,
                               first_frame=pkt.frame_index,
                               first_ts=pkt.ts, last_ts=pkt.ts)
            self._streams[key] = s
            self._pending.pop(key, None)
            return b"", pkt.frame_index, pkt.ts
        if not pkt.payload:
            return b"", pkt.frame_index, pkt.ts
        if s is None or not s.initialised:
            # Captured mid-stream: bootstrap from this segment's seq.
            s = _TcpHalfStream(base_seq=pkt.tcp_seq, initialised=True,
                               first_frame=pkt.frame_index,
                               first_ts=pkt.ts, last_ts=pkt.ts)
            self._streams[key] = s
        # Expected sequence number for the next byte = base_seq + len(buf).
        expected = (s.base_seq + len(s.buf)) & 0xFFFFFFFF
        seq = pkt.tcp_seq & 0xFFFFFFFF
        s.last_ts = pkt.ts
        if seq == expected:
            if not s.buf:
                s.first_frame = pkt.frame_index
                s.first_ts = pkt.ts
            before = len(s.buf)
            s.buf.extend(pkt.payload)
            new_bytes = bytes(s.buf[before:])
            # Drain anything previously held back that now fits.
            pending = self._pending.get(key, [])
            pending.sort(key=lambda t: t[0])
            progressed = True
            while pending and progressed:
                progressed = False
                head_seq, head_data, _fi, _ts = pending[0]
                head_exp = (s.base_seq + len(s.buf)) & 0xFFFFFFFF
                if head_seq == head_exp:
                    s.buf.extend(head_data)
                    new_bytes += head_data
                    pending.pop(0)
                    progressed = True
                elif (head_seq - head_exp) & 0xFFFFFFFF == 0:
                    pending.pop(0)
                    progressed = True
            if pending:
                self._pending[key] = pending
            else:
                self._pending.pop(key, None)
            return new_bytes, s.first_frame, s.first_ts
        # Out of order or retransmit
        delta = (seq - s.base_seq) & 0xFFFFFFFF
        if delta < len(s.buf):
            # full retransmit — ignore
            return b"", s.first_frame, s.first_ts
        self._pending.setdefault(key, []).append(
            (seq, pkt.payload, pkt.frame_index, pkt.ts))
        return b"", s.first_frame, s.first_ts

    def consume(self, key: Tuple[str, str, int, int], n: int) -> None:
        """Drop ``n`` bytes from the front of a stream after parsing them."""
        s = self._streams.get(key)
        if s is None:
            return
        if n >= len(s.buf):
            s.buf.clear()
        else:
            del s.buf[:n]
        s.base_seq = (s.base_seq + n) & 0xFFFFFFFF

    def buffer(self, key: Tuple[str, str, int, int]) -> bytes:
        s = self._streams.get(key)
        return bytes(s.buf) if s else b""
