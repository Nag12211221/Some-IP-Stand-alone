"""DoIP (ISO 13400-2:2019) wire-format codec.

Header layout (big-endian, 8 bytes)::

    +---------+----------+
    | ProtoV  | ~ProtoV  |   1 + 1
    +---------+----------+
    |   Payload Type     |   2
    +--------------------+
    | Payload Length u32 |   4
    +--------------------+
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum

DOIP_HEADER_FMT = "!BBHI"
DOIP_HEADER_SIZE = struct.calcsize(DOIP_HEADER_FMT)  # 8

DOIP_PROTOCOL_VERSION_2012 = 0x02
DOIP_PROTOCOL_VERSION_2019 = 0x03


class PayloadType(IntEnum):
    GENERIC_NACK = 0x0000
    VEHICLE_ID_REQ = 0x0001
    VEHICLE_ID_REQ_EID = 0x0002
    VEHICLE_ID_REQ_VIN = 0x0003
    VEHICLE_ANNOUNCEMENT = 0x0004
    ROUTING_ACTIVATION_REQ = 0x0005
    ROUTING_ACTIVATION_RES = 0x0006
    ALIVE_CHECK_REQ = 0x0007
    ALIVE_CHECK_RES = 0x0008
    DOIP_ENTITY_STATUS_REQ = 0x4001
    DOIP_ENTITY_STATUS_RES = 0x4002
    DIAG_POWER_MODE_REQ = 0x4003
    DIAG_POWER_MODE_RES = 0x4004
    DIAGNOSTIC_MESSAGE = 0x8001
    DIAGNOSTIC_MESSAGE_ACK = 0x8002
    DIAGNOSTIC_MESSAGE_NACK = 0x8003


class RoutingActivationResponseCode(IntEnum):
    UNKNOWN_SA = 0x00
    NO_SOCKET = 0x01
    DIFFERENT_SA = 0x02
    SA_ALREADY_REGISTERED = 0x03
    MISSING_AUTH = 0x04
    REJECTED_CONFIRMATION = 0x05
    UNSUPPORTED_ACTIVATION_TYPE = 0x06
    SUCCESS = 0x10
    SUCCESS_REQUIRES_CONFIRMATION = 0x11


class GenericNackCode(IntEnum):
    INCORRECT_PATTERN = 0x00
    UNKNOWN_PAYLOAD_TYPE = 0x01
    MESSAGE_TOO_LARGE = 0x02
    OUT_OF_MEMORY = 0x03
    INVALID_PAYLOAD_LENGTH = 0x04


@dataclass(slots=True)
class DoipHeader:
    protocol_version: int
    payload_type: int
    payload_length: int

    def pack(self) -> bytes:
        pv = self.protocol_version & 0xFF
        return struct.pack(
            DOIP_HEADER_FMT,
            pv,
            (~pv) & 0xFF,
            self.payload_type & 0xFFFF,
            self.payload_length & 0xFFFFFFFF,
        )

    @classmethod
    def unpack(cls, buf: bytes, offset: int = 0) -> "DoipHeader":
        if len(buf) - offset < DOIP_HEADER_SIZE:
            raise ValueError("buffer too short for DoIP header")
        pv, inv, pt, pl = struct.unpack_from(DOIP_HEADER_FMT, buf, offset)
        if (pv ^ inv) & 0xFF != 0xFF:
            raise ValueError(f"DoIP protocol version inverted check failed ({pv:#x}/{inv:#x})")
        return cls(pv, pt, pl)


def build(payload_type: int, payload: bytes,
          version: int = DOIP_PROTOCOL_VERSION_2019) -> bytes:
    hdr = DoipHeader(version, payload_type, len(payload))
    return hdr.pack() + payload


def build_routing_activation_request(source_address: int,
                                     activation_type: int = 0x00,
                                     oem_specific: int = 0) -> bytes:
    payload = struct.pack("!HBII", source_address & 0xFFFF, activation_type & 0xFF,
                          0, oem_specific & 0xFFFFFFFF)
    return build(PayloadType.ROUTING_ACTIVATION_REQ, payload)


def build_routing_activation_response(tester_sa: int, entity_sa: int,
                                      response_code: int) -> bytes:
    payload = struct.pack("!HHBI",
                          tester_sa & 0xFFFF,
                          entity_sa & 0xFFFF,
                          response_code & 0xFF,
                          0) + b"\x00" * 4
    # spec is 13 bytes (SA(2)+SA(2)+code(1)+reserved(4)+oem(4))
    return build(PayloadType.ROUTING_ACTIVATION_RES, payload[:13])


def build_alive_check_request() -> bytes:
    return build(PayloadType.ALIVE_CHECK_REQ, b"")


def build_alive_check_response(source_address: int) -> bytes:
    return build(PayloadType.ALIVE_CHECK_RES, struct.pack("!H", source_address & 0xFFFF))


def build_diagnostic_message(sa: int, ta: int, uds_payload: bytes) -> bytes:
    return build(PayloadType.DIAGNOSTIC_MESSAGE,
                 struct.pack("!HH", sa & 0xFFFF, ta & 0xFFFF) + uds_payload)


def build_diagnostic_ack(sa: int, ta: int, ack_code: int = 0x00,
                         previous_message: bytes = b"") -> bytes:
    return build(PayloadType.DIAGNOSTIC_MESSAGE_ACK,
                 struct.pack("!HHB", sa & 0xFFFF, ta & 0xFFFF, ack_code) + previous_message)


def build_generic_nack(code: int) -> bytes:
    return build(PayloadType.GENERIC_NACK, struct.pack("!B", code & 0xFF))
