"""PCAP and PCAP-NG file readers + writers (pure standard library).

We support the two on-disk formats produced by Wireshark / tcpdump:

* **libpcap 2.4** (legacy classic format, magic ``0xA1B2C3D4``);
* **PCAP-NG** (block-structured, magic ``0x0A0D0D0A``).

For both we yield :class:`PcapFrame` objects containing the link-layer
type (DLT_*), capture timestamp and raw bytes. Higher layers
(:mod:`someip_suite.protocols.l2`) turn those into decoded Ethernet /
IP / UDP / TCP frames.

The writer always emits the simpler libpcap 2.4 format which every
analyzer on earth understands.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass
from typing import BinaryIO, Iterable, Iterator, Optional


# DLT (link-layer type) values from libpcap's bpf.h. We only need a few.
DLT_NULL = 0
DLT_EN10MB = 1          # Ethernet
DLT_RAW = 12            # raw IP (no link layer)
DLT_LINUX_SLL = 113     # Linux "cooked" capture
DLT_IPV4 = 228
DLT_IPV6 = 229

PCAP_MAGIC_LE = 0xA1B2C3D4         # microsecond resolution, little-endian
PCAP_MAGIC_BE = 0xD4C3B2A1
PCAP_NSEC_MAGIC_LE = 0xA1B23C4D    # nanosecond resolution
PCAP_NSEC_MAGIC_BE = 0x4D3CB2A1
PCAPNG_BLOCK_SECTION = 0x0A0D0D0A
PCAPNG_BLOCK_IDB = 0x00000001
PCAPNG_BLOCK_EPB = 0x00000006
PCAPNG_BLOCK_SPB = 0x00000003


@dataclass(slots=True)
class PcapFrame:
    """A single captured frame with its absolute timestamp and link type."""

    index: int          # 1-based frame number (Wireshark convention)
    ts: float           # POSIX epoch seconds (float)
    linktype: int       # DLT_*
    data: bytes         # raw bytes as captured (may be truncated to snaplen)
    orig_len: int       # original on-wire length

    @property
    def caplen(self) -> int:
        return len(self.data)


# ---------------------------------------------------------------------------
# Reader
# ---------------------------------------------------------------------------


class PcapError(ValueError):
    """Raised for malformed or unsupported pcap data."""


def read_pcap(path: str) -> Iterator[PcapFrame]:
    """Yield :class:`PcapFrame` objects from a pcap or pcap-ng file.

    The format is auto-detected from the first 4 bytes. Truncated files
    are tolerated — we simply stop iterating at the first short read,
    which is what Wireshark does.
    """
    with open(path, "rb") as fh:
        head = fh.read(4)
        if len(head) < 4:
            return
        magic = struct.unpack("<I", head)[0]
        fh.seek(0)
        if magic == PCAPNG_BLOCK_SECTION:
            yield from _read_pcapng(fh)
        else:
            yield from _read_pcap_classic(fh)


def _read_pcap_classic(fh: BinaryIO) -> Iterator[PcapFrame]:
    magic_bytes = fh.read(4)
    if len(magic_bytes) < 4:
        return
    (m,) = struct.unpack("<I", magic_bytes)
    if m in (PCAP_MAGIC_LE, PCAP_NSEC_MAGIC_LE):
        endian = "<"
    elif m in (PCAP_MAGIC_BE, PCAP_NSEC_MAGIC_BE):
        endian = ">"
    else:
        raise PcapError(f"unrecognised pcap magic {m:#x}")
    nano = m in (PCAP_NSEC_MAGIC_LE, PCAP_NSEC_MAGIC_BE)

    # rest of global header: version_major(2) version_minor(2)
    # thiszone(4) sigfigs(4) snaplen(4) network(4)
    rest = fh.read(20)
    if len(rest) < 20:
        return
    _, _, _, _, _snaplen, network = struct.unpack(endian + "HHiIII", rest)

    rec_fmt = endian + "IIII"
    rec_size = 16
    idx = 0
    while True:
        hdr = fh.read(rec_size)
        if len(hdr) < rec_size:
            return
        ts_s, ts_frac, incl_len, orig_len = struct.unpack(rec_fmt, hdr)
        data = fh.read(incl_len)
        if len(data) < incl_len:
            return
        idx += 1
        ts = ts_s + (ts_frac / 1e9 if nano else ts_frac / 1e6)
        yield PcapFrame(index=idx, ts=ts, linktype=network,
                        data=data, orig_len=orig_len)


def _read_pcapng(fh: BinaryIO) -> Iterator[PcapFrame]:
    """Minimal pcap-ng reader: SHB, IDB and Enhanced/Simple Packet blocks."""
    # SHB tells us the byte order via its byte-order magic (0x1A2B3C4D).
    endian = "<"
    interfaces = []  # list of (linktype, tsresol)
    idx = 0
    while True:
        head = fh.read(8)
        if len(head) < 8:
            return
        bt = struct.unpack(endian + "I", head[:4])[0]
        blen = struct.unpack(endian + "I", head[4:])[0]
        if blen < 12:
            raise PcapError(f"pcap-ng block length too small: {blen}")
        body = fh.read(blen - 12)
        if len(body) < blen - 12:
            return
        trailer = fh.read(4)
        if len(trailer) < 4:
            return

        if bt == PCAPNG_BLOCK_SECTION:
            # SHB: byte-order magic at offset 0 of body
            bom = struct.unpack("<I", body[:4])[0]
            endian = "<" if bom == 0x1A2B3C4D else ">"
            # re-parse blen with the chosen endian to be safe
            blen = struct.unpack(endian + "I", head[4:])[0]
            # interfaces will be redeclared by IDBs
            interfaces = []
        elif bt == PCAPNG_BLOCK_IDB:
            if len(body) < 8:
                continue
            linktype, _reserved, _snaplen = struct.unpack(
                endian + "HHI", body[:8])
            # Walk options for if_tsresol (code 9)
            tsresol = 6   # microseconds
            opts = body[8:]
            o = 0
            while o + 4 <= len(opts):
                code, olen = struct.unpack(endian + "HH", opts[o:o + 4])
                o += 4
                ovalue = opts[o:o + olen]
                # 4-byte aligned padding
                o += (olen + 3) & ~3
                if code == 0:
                    break
                if code == 9 and len(ovalue) >= 1:
                    raw = ovalue[0]
                    if raw & 0x80:
                        tsresol = -(raw & 0x7F)   # power of 2
                    else:
                        tsresol = raw             # power of 10
            interfaces.append((linktype, tsresol))
        elif bt == PCAPNG_BLOCK_EPB:
            if len(body) < 20 or not interfaces:
                continue
            iface_id, ts_high, ts_low, cap_len, orig_len = struct.unpack(
                endian + "IIIII", body[:20])
            data = body[20:20 + cap_len]
            linktype, tsresol = interfaces[iface_id % len(interfaces)]
            ts = _pcapng_ts(ts_high, ts_low, tsresol)
            idx += 1
            yield PcapFrame(index=idx, ts=ts, linktype=linktype,
                            data=bytes(data), orig_len=orig_len)
        elif bt == PCAPNG_BLOCK_SPB:
            if len(body) < 4 or not interfaces:
                continue
            (orig_len,) = struct.unpack(endian + "I", body[:4])
            data = body[4:]
            linktype, _ = interfaces[0]
            idx += 1
            yield PcapFrame(index=idx, ts=0.0, linktype=linktype,
                            data=bytes(data[:orig_len]), orig_len=orig_len)
        # else: unknown / option block — skip silently


def _pcapng_ts(hi: int, lo: int, tsresol: int) -> float:
    raw = (hi << 32) | lo
    if tsresol >= 0:
        return raw / (10 ** tsresol)
    return raw / (1 << -tsresol)


# ---------------------------------------------------------------------------
# Writer (classic libpcap 2.4, microsecond resolution)
# ---------------------------------------------------------------------------


class PcapWriter:
    """Append-only writer that produces tcpdump-compatible files.

    Used by the live-capture tab to spool frames to a rolling pcap so
    the user can re-open them in Wireshark for deeper analysis.
    """

    def __init__(self, path: str, linktype: int = DLT_EN10MB,
                 snaplen: int = 65535) -> None:
        self.path = path
        self.linktype = linktype
        self.snaplen = snaplen
        self._fh = open(path, "wb")
        self._fh.write(struct.pack(
            "<IHHiIII",
            PCAP_MAGIC_LE, 2, 4, 0, 0, snaplen, linktype,
        ))
        self._frames = 0
        self._bytes = 0

    @property
    def frames(self) -> int:
        return self._frames

    @property
    def bytes_written(self) -> int:
        return self._bytes

    def write(self, ts: float, data: bytes, orig_len: Optional[int] = None) -> None:
        ts_s = int(ts)
        ts_us = int((ts - ts_s) * 1_000_000) & 0xFFFFFFFF
        if orig_len is None:
            orig_len = len(data)
        incl_len = min(len(data), self.snaplen)
        self._fh.write(struct.pack("<IIII", ts_s, ts_us, incl_len, orig_len))
        self._fh.write(data[:incl_len])
        self._frames += 1
        self._bytes += 16 + incl_len

    def close(self) -> None:
        try:
            self._fh.flush()
        finally:
            self._fh.close()

    def __enter__(self) -> "PcapWriter":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def write_pcap(path: str, frames: Iterable[PcapFrame],
               linktype: int = DLT_EN10MB) -> int:
    """Write a sequence of frames to ``path`` and return the count."""
    n = 0
    with PcapWriter(path, linktype=linktype) as w:
        for f in frames:
            w.write(f.ts, f.data, orig_len=f.orig_len)
            n += 1
    return n


# Frame factory used by the live capture path so it stays decoupled
# from the actual capture backend.
def make_frame(index: int, data: bytes, linktype: int = DLT_EN10MB,
               ts: Optional[float] = None) -> PcapFrame:
    if ts is None:
        ts = time.time()
    return PcapFrame(index=index, ts=ts, linktype=linktype,
                     data=bytes(data), orig_len=len(data))
