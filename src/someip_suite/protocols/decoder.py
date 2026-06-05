"""Unified capture decoder — turns L4 packets into SOME/IP and DoIP messages.

This is the single shared decoder used by:

* the **Capture** tab (Open .pcap / live capture) to populate the packet list,
* the **SD Timing** offline analyser,
* the **DoIP Flashing** offline analyser,
* the **Filter Engine** tab (replaces the old synthetic generator),
* the **CLI** (``analyze`` subcommand).

A single Decoder instance maintains TCP-reassembly state so DoIP messages
that straddle multiple TCP segments are surfaced correctly. UDP packets
are decoded one-shot; we attempt to recognise both SOME/IP-SD and
ordinary SOME/IP carried in UDP.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Iterator, List, Optional

from .l2 import Packet, TcpReassembler
from .pcap import PcapFrame
from .l2 import decode_frame
from . import someip, doip


# Well-known UDP port used for SOME/IP-SD multicast (PRS R21-11 §4.1.2)
SOMEIP_SD_PORT = 30490
# Default DoIP TCP/UDP port (ISO 13400-2:2019)
DOIP_PORT = 13400


@dataclass(slots=True)
class DecodedMessage:
    """One high-level message extracted from one or more captured frames."""

    frame_index: int                # first capture frame this message uses
    ts: float
    protocol: str                   # "someip" | "someip-sd" | "doip"
    src: str                        # "ip:port"
    dst: str                        # "ip:port"
    transport: str                  # "udp" | "tcp"
    summary: str                    # one-line human description
    raw: bytes = b""                # raw message bytes
    # Protocol-specific quick-access fields (None if not applicable):
    someip_header: Optional[someip.SomeIpHeader] = None
    sd_message: Optional[someip.SdMessage] = None
    doip_header: Optional[doip.DoipHeader] = None
    doip_payload: bytes = b""


# ---------------------------------------------------------------------------
# Per-packet helpers
# ---------------------------------------------------------------------------


def _someip_summary(hdr: someip.SomeIpHeader) -> str:
    try:
        mt = someip.MessageType(hdr.message_type).name
    except ValueError:
        mt = f"MT=0x{hdr.message_type:02X}"
    try:
        rc = someip.ReturnCode(hdr.return_code).name
    except ValueError:
        rc = f"RC=0x{hdr.return_code:02X}"
    return (f"svc=0x{hdr.service_id:04X} meth=0x{hdr.method_id:04X} "
            f"client=0x{hdr.client_id:04X} sess=0x{hdr.session_id:04X} "
            f"{mt} {rc}")


def _sd_summary(msg: someip.SdMessage) -> str:
    kinds: List[str] = []
    for e in msg.entries:
        try:
            kind = someip.SdEntryType(e.type).name
        except ValueError:
            kind = f"Entry0x{e.type:02X}"
        kinds.append(f"{kind}(0x{e.service_id:04X}.{e.instance_id})")
    flags = []
    if msg.flags & someip.SD_FLAG_REBOOT:
        flags.append("Reboot")
    if msg.flags & someip.SD_FLAG_UNICAST:
        flags.append("Unicast")
    fstr = " [" + ",".join(flags) + "]" if flags else ""
    return f"SD{fstr} entries=" + ",".join(kinds)


def _doip_summary(hdr: doip.DoipHeader, payload: bytes) -> str:
    try:
        pt = doip.PayloadType(hdr.payload_type).name
    except ValueError:
        pt = f"PT=0x{hdr.payload_type:04X}"
    extra = ""
    if hdr.payload_type == doip.PayloadType.DIAGNOSTIC_MESSAGE and len(payload) >= 4:
        sa, ta = payload[0] << 8 | payload[1], payload[2] << 8 | payload[3]
        uds = payload[4:].hex() if len(payload) > 4 else ""
        extra = f" SA=0x{sa:04X} TA=0x{ta:04X} UDS={uds[:32]}"
    elif hdr.payload_type == doip.PayloadType.ROUTING_ACTIVATION_REQ and len(payload) >= 3:
        sa = payload[0] << 8 | payload[1]
        extra = f" SA=0x{sa:04X} type=0x{payload[2]:02X}"
    elif hdr.payload_type == doip.PayloadType.ROUTING_ACTIVATION_RES and len(payload) >= 5:
        sa = payload[0] << 8 | payload[1]
        ta = payload[2] << 8 | payload[3]
        extra = f" SA=0x{sa:04X} TA=0x{ta:04X} rc=0x{payload[4]:02X}"
    return f"DoIP {pt} (len={hdr.payload_length}){extra}"


# ---------------------------------------------------------------------------
# Decoder
# ---------------------------------------------------------------------------


class CaptureDecoder:
    """Stateful decoder for a stream of L4 :class:`Packet` objects.

    Use one decoder per capture session — TCP reassembly state is kept
    inside.
    """

    def __init__(self, *, doip_ports: Optional[Iterable[int]] = None,
                 sd_port: int = SOMEIP_SD_PORT) -> None:
        self._reasm = TcpReassembler()
        self._doip_ports = set(doip_ports) if doip_ports else {DOIP_PORT}
        self._sd_port = sd_port

    # -- bulk helpers ---------------------------------------------------
    def decode_pcap(self, frames: Iterable[PcapFrame]) -> Iterator[DecodedMessage]:
        for f in frames:
            pkt = decode_frame(f)
            if pkt is not None:
                yield from self.feed(pkt)

    def feed_many(self, packets: Iterable[Packet]) -> Iterator[DecodedMessage]:
        for p in packets:
            yield from self.feed(p)

    # -- single-packet API ----------------------------------------------
    def feed(self, pkt: Packet) -> Iterator[DecodedMessage]:
        """Yield zero-or-more decoded messages for a single L4 packet."""
        if pkt.transport == "udp":
            yield from self._decode_udp(pkt)
            return
        # TCP — feed into the reassembler, then peel DoIP frames off the
        # contiguous byte stream as they complete.
        new_bytes, first_frame, first_ts = self._reasm.feed(pkt)
        if not new_bytes:
            return
        key = (pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port)
        looks_like_doip = (pkt.src_port in self._doip_ports or
                           pkt.dst_port in self._doip_ports)
        if not looks_like_doip:
            # Not DoIP — emit a generic SOME/IP-over-TCP attempt and stop
            # caching bytes (no length prefix at the SOME/IP layer means
            # arbitrary reassembly isn't worth the memory).
            hdr = someip.parse_someip(new_bytes)
            if hdr is not None:
                yield DecodedMessage(
                    frame_index=pkt.frame_index, ts=pkt.ts,
                    protocol="someip", transport="tcp",
                    src=pkt.src, dst=pkt.dst,
                    summary=_someip_summary(hdr),
                    raw=new_bytes[:someip.SOMEIP_HEADER_SIZE + max(0, hdr.length - 8)],
                    someip_header=hdr,
                )
            self._reasm.consume(key, len(new_bytes))
            return

        # DoIP: pull as many complete frames as we can from the buffer.
        buf = self._reasm.buffer(key)
        consumed = 0
        while len(buf) - consumed >= doip.DOIP_HEADER_SIZE:
            try:
                hdr = doip.DoipHeader.unpack(buf, consumed)
            except ValueError:
                # Resync: drop one byte and retry. In practice this only
                # happens on truncated/corrupted captures.
                consumed += 1
                continue
            need = doip.DOIP_HEADER_SIZE + hdr.payload_length
            if len(buf) - consumed < need:
                break
            payload = bytes(buf[consumed + doip.DOIP_HEADER_SIZE:consumed + need])
            yield DecodedMessage(
                frame_index=first_frame, ts=first_ts,
                protocol="doip", transport="tcp",
                src=pkt.src, dst=pkt.dst,
                summary=_doip_summary(hdr, payload),
                raw=bytes(buf[consumed:consumed + need]),
                doip_header=hdr, doip_payload=payload,
            )
            # If the DoIP payload is a SOME/IP DiagnosticMessage we don't
            # try to peel a nested header — DoIP carries UDS, not SOME/IP.
            consumed += need
        if consumed:
            self._reasm.consume(key, consumed)

    def _decode_udp(self, pkt: Packet) -> Iterator[DecodedMessage]:
        payload = pkt.payload
        if len(payload) < someip.SOMEIP_HEADER_SIZE:
            # could still be DoIP-over-UDP (announcement / power mode)
            if (pkt.src_port in self._doip_ports
                    or pkt.dst_port in self._doip_ports) \
                    and len(payload) >= doip.DOIP_HEADER_SIZE:
                yield from self._emit_doip_udp(pkt, payload)
            return

        # Try DoIP-over-UDP first if the port matches (it's a different
        # framing from SOME/IP).
        if pkt.src_port in self._doip_ports or pkt.dst_port in self._doip_ports:
            yield from self._emit_doip_udp(pkt, payload)
            return

        hdr = someip.parse_someip(payload)
        if hdr is None:
            return
        # Detect SD: the SD service ID is 0xFFFF and method 0x8100.
        if (hdr.service_id == someip.SOMEIP_SD_SERVICE_ID
                and hdr.method_id == someip.SOMEIP_SD_METHOD_ID):
            try:
                sd = someip.SdMessage.unpack(payload)
            except (ValueError, Exception):    # noqa: BLE001
                sd = None
            yield DecodedMessage(
                frame_index=pkt.frame_index, ts=pkt.ts,
                protocol="someip-sd", transport="udp",
                src=pkt.src, dst=pkt.dst,
                summary=_sd_summary(sd) if sd else "SD (malformed)",
                raw=payload,
                someip_header=hdr, sd_message=sd,
            )
            return
        # Regular SOME/IP message
        wire_len = someip.SOMEIP_HEADER_SIZE + max(0, hdr.length - 8)
        yield DecodedMessage(
            frame_index=pkt.frame_index, ts=pkt.ts,
            protocol="someip", transport="udp",
            src=pkt.src, dst=pkt.dst,
            summary=_someip_summary(hdr),
            raw=payload[:wire_len if wire_len <= len(payload) else len(payload)],
            someip_header=hdr,
        )

    def _emit_doip_udp(self, pkt: Packet, payload: bytes) -> Iterator[DecodedMessage]:
        try:
            hdr = doip.DoipHeader.unpack(payload)
        except ValueError:
            return
        body = payload[doip.DOIP_HEADER_SIZE:
                       doip.DOIP_HEADER_SIZE + hdr.payload_length]
        yield DecodedMessage(
            frame_index=pkt.frame_index, ts=pkt.ts,
            protocol="doip", transport="udp",
            src=pkt.src, dst=pkt.dst,
            summary=_doip_summary(hdr, body),
            raw=payload[:doip.DOIP_HEADER_SIZE + hdr.payload_length],
            doip_header=hdr, doip_payload=body,
        )
