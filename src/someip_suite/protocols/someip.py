"""SOME/IP and SOME/IP-SD wire-format codec.

References
----------
* AUTOSAR_PRS_SOMEIPProtocol (R21-11).
* AUTOSAR_PRS_SOMEIPServiceDiscoveryProtocol (R21-11).

The header layout (big-endian) is::

    +----------------+----------------+
    |   Service ID   |   Method ID    |   4 bytes
    +----------------+----------------+
    |          Length (u32)           |   4 bytes  (covers everything below)
    +----------------+----------------+
    |   Client ID    |   Session ID   |   4 bytes
    +--------+-------+--------+-------+
    |  ProtV |  IfV  |  MsgT  | RetC  |   4 bytes
    +--------+-------+--------+-------+
    |              Payload            |
    +---------------------------------+
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import List, Optional, Tuple

SOMEIP_HEADER_FMT = "!HHIHHBBBB"
SOMEIP_HEADER_SIZE = struct.calcsize(SOMEIP_HEADER_FMT)  # 16 bytes
SOMEIP_PROTOCOL_VERSION = 0x01
SOMEIP_SD_SERVICE_ID = 0xFFFF
SOMEIP_SD_METHOD_ID = 0x8100
SOMEIP_SD_CLIENT_ID = 0x0000
SOMEIP_SD_INTERFACE_VERSION = 0x01


class MessageType(IntEnum):
    REQUEST = 0x00
    REQUEST_NO_RETURN = 0x01
    NOTIFICATION = 0x02
    RESPONSE = 0x80
    ERROR = 0x81


class ReturnCode(IntEnum):
    E_OK = 0x00
    E_NOT_OK = 0x01
    E_UNKNOWN_SERVICE = 0x02
    E_UNKNOWN_METHOD = 0x03
    E_NOT_READY = 0x04
    E_NOT_REACHABLE = 0x05
    E_TIMEOUT = 0x06


@dataclass(slots=True)
class SomeIpHeader:
    service_id: int
    method_id: int
    length: int
    client_id: int
    session_id: int
    protocol_version: int = SOMEIP_PROTOCOL_VERSION
    interface_version: int = 0x01
    message_type: int = MessageType.REQUEST
    return_code: int = ReturnCode.E_OK

    def pack(self) -> bytes:
        return struct.pack(
            SOMEIP_HEADER_FMT,
            self.service_id & 0xFFFF,
            self.method_id & 0xFFFF,
            self.length & 0xFFFFFFFF,
            self.client_id & 0xFFFF,
            self.session_id & 0xFFFF,
            self.protocol_version & 0xFF,
            self.interface_version & 0xFF,
            int(self.message_type) & 0xFF,
            int(self.return_code) & 0xFF,
        )

    @classmethod
    def unpack(cls, buf: bytes, offset: int = 0) -> "SomeIpHeader":
        if len(buf) - offset < SOMEIP_HEADER_SIZE:
            raise ValueError("buffer too short for SOME/IP header")
        (sid, mid, ln, cid, sess, pv, iv, mt, rc) = struct.unpack_from(
            SOMEIP_HEADER_FMT, buf, offset
        )
        return cls(sid, mid, ln, cid, sess, pv, iv, mt, rc)


# ---------------------------------------------------------------------------
# SOME/IP-SD
# ---------------------------------------------------------------------------


class SdEntryType(IntEnum):
    FIND_SERVICE = 0x00
    OFFER_SERVICE = 0x01  # also STOP_OFFER when TTL=0
    SUBSCRIBE_EVENTGROUP = 0x06
    SUBSCRIBE_EVENTGROUP_ACK = 0x07


class SdOptionType(IntEnum):
    CONFIGURATION = 0x01
    LOAD_BALANCING = 0x02
    IPV4_ENDPOINT = 0x04
    IPV6_ENDPOINT = 0x06
    IPV4_MULTICAST = 0x14
    IPV6_MULTICAST = 0x16
    IPV4_SD_ENDPOINT = 0x24
    IPV6_SD_ENDPOINT = 0x26


# SD flag bits in the first payload byte
SD_FLAG_REBOOT = 0x80
SD_FLAG_UNICAST = 0x40
SD_FLAG_EXPLICIT_INITIAL_DATA_CONTROL = 0x20


@dataclass(slots=True)
class SdEntry:
    type: int
    service_id: int
    instance_id: int
    major_version: int
    minor_version: int
    ttl: int
    index1: int = 0
    index2: int = 0
    n_opt1: int = 0
    n_opt2: int = 0

    def pack(self) -> bytes:
        # 16 bytes per entry — layout: type(1) idx1(1) idx2(1) nopt(1)
        # service(2) instance(2) major(1) ttl(3) minor(4)
        b3 = ((self.n_opt1 & 0x0F) << 4) | (self.n_opt2 & 0x0F)
        head = struct.pack(
            "!BBBB",
            self.type & 0xFF,
            self.index1 & 0xFF,
            self.index2 & 0xFF,
            b3,
        )
        body = struct.pack(
            "!HHBBHI",
            self.service_id & 0xFFFF,
            self.instance_id & 0xFFFF,
            self.major_version & 0xFF,
            (self.ttl >> 16) & 0xFF,
            self.ttl & 0xFFFF,
            self.minor_version & 0xFFFFFFFF,
        )
        return head + body

    @classmethod
    def unpack(cls, buf: bytes, offset: int) -> "SdEntry":
        if len(buf) - offset < 16:
            raise ValueError("buffer too short for SD entry")
        t, i1, i2, nopt = struct.unpack_from("!BBBB", buf, offset)
        sid, inst, major, ttl_hi, ttl_lo, minor = struct.unpack_from(
            "!HHBBHI", buf, offset + 4
        )
        ttl = (ttl_hi << 16) | ttl_lo
        return cls(
            type=t,
            service_id=sid,
            instance_id=inst,
            major_version=major,
            minor_version=minor,
            ttl=ttl,
            index1=i1,
            index2=i2,
            n_opt1=(nopt >> 4) & 0x0F,
            n_opt2=nopt & 0x0F,
        )


@dataclass(slots=True)
class SdOption:
    type: int
    data: bytes = b""

    def pack(self) -> bytes:
        # length covers reserved + data, not the length field itself or type
        length = 1 + len(self.data)
        return struct.pack("!HB", length, self.type & 0xFF) + b"\x00" + self.data

    @classmethod
    def unpack(cls, buf: bytes, offset: int) -> Tuple["SdOption", int]:
        if len(buf) - offset < 4:
            raise ValueError("buffer too short for SD option")
        length, otype = struct.unpack_from("!HB", buf, offset)
        # one reserved byte already counted in length
        data = bytes(buf[offset + 4 : offset + 3 + length])
        return cls(type=otype, data=data), offset + 3 + length


def make_ipv4_endpoint_option(ip: str, port: int, proto: str = "udp") -> SdOption:
    """Create an IPv4 endpoint option (0x04)."""
    octets = bytes(int(o) for o in ip.split("."))
    if len(octets) != 4:
        raise ValueError("invalid IPv4 address")
    l4 = {"tcp": 0x06, "udp": 0x11}[proto.lower()]
    # reserved(1) + L4 proto(1) + port(2)
    data = octets + bytes([0x00, l4]) + struct.pack("!H", port & 0xFFFF)
    return SdOption(type=SdOptionType.IPV4_ENDPOINT, data=data)


@dataclass(slots=True)
class SdMessage:
    flags: int = SD_FLAG_UNICAST
    reserved: int = 0
    entries: List[SdEntry] = field(default_factory=list)
    options: List[SdOption] = field(default_factory=list)
    session_id: int = 1
    reboot: bool = False

    def pack(self) -> bytes:
        flags = self.flags | (SD_FLAG_REBOOT if self.reboot else 0)
        head = struct.pack("!BBH", flags, 0, 0)  # flags + reserved24
        ent_bytes = b"".join(e.pack() for e in self.entries)
        ent_block = struct.pack("!I", len(ent_bytes)) + ent_bytes
        opt_bytes = b"".join(o.pack() for o in self.options)
        opt_block = struct.pack("!I", len(opt_bytes)) + opt_bytes
        payload = head + ent_block + opt_block

        hdr = SomeIpHeader(
            service_id=SOMEIP_SD_SERVICE_ID,
            method_id=SOMEIP_SD_METHOD_ID,
            length=8 + len(payload),  # client+session+ver+type+rc = 8
            client_id=SOMEIP_SD_CLIENT_ID,
            session_id=self.session_id & 0xFFFF,
            interface_version=SOMEIP_SD_INTERFACE_VERSION,
            message_type=MessageType.NOTIFICATION,
            return_code=ReturnCode.E_OK,
        )
        return hdr.pack() + payload

    @classmethod
    def unpack(cls, buf: bytes) -> "SdMessage":
        hdr = SomeIpHeader.unpack(buf)
        if hdr.service_id != SOMEIP_SD_SERVICE_ID or hdr.method_id != SOMEIP_SD_METHOD_ID:
            raise ValueError("not a SOME/IP-SD message")
        off = SOMEIP_HEADER_SIZE
        flags, _r0, _r1 = struct.unpack_from("!BBH", buf, off)
        off += 4
        (ent_len,) = struct.unpack_from("!I", buf, off)
        off += 4
        entries = []
        end = off + ent_len
        while off < end:
            entries.append(SdEntry.unpack(buf, off))
            off += 16
        (opt_len,) = struct.unpack_from("!I", buf, off)
        off += 4
        options: List[SdOption] = []
        end = off + opt_len
        while off < end:
            opt, off = SdOption.unpack(buf, off)
            options.append(opt)
        return cls(
            flags=flags,
            entries=entries,
            options=options,
            session_id=hdr.session_id,
            reboot=bool(flags & SD_FLAG_REBOOT),
        )


def build_offer_service(
    service_id: int,
    instance_id: int,
    major: int,
    minor: int,
    ttl: int,
    ip: str,
    port: int,
    proto: str = "udp",
    session_id: int = 1,
    reboot: bool = False,
) -> bytes:
    """Convenience helper used by the SD timing analyser."""
    entry = SdEntry(
        type=SdEntryType.OFFER_SERVICE,
        service_id=service_id,
        instance_id=instance_id,
        major_version=major,
        minor_version=minor,
        ttl=ttl,
        n_opt1=1,
    )
    opt = make_ipv4_endpoint_option(ip, port, proto)
    msg = SdMessage(entries=[entry], options=[opt], session_id=session_id, reboot=reboot)
    return msg.pack()


def parse_someip(buf: bytes) -> Optional[SomeIpHeader]:
    """Best-effort parse, returns ``None`` on malformed input."""
    try:
        return SomeIpHeader.unpack(buf)
    except (struct.error, ValueError):
        return None
