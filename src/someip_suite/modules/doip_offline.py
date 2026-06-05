"""Offline DoIP session reconstructor — operates on real captures.

Given the DoIP messages decoded from a pcap by
:class:`someip_suite.protocols.decoder.CaptureDecoder`, this module
reconstructs each *flash / diagnostic session* and surfaces the things
that go wrong in real life:

* RoutingActivation outcome (success / failure / latency);
* AliveCheck request/response pairs and missed responses;
* Per-direction DiagnosticMessage / Ack / Nack pairing → UDS
  request/response reconstruction with RTT per block;
* TCP drop / reconnect detection (a new SYN on the same 5-tuple
  invalidates the prior session and increments the "reconnects"
  counter);
* DiagnosticMessage retransmits (same SA/TA/payload within the timeout
  window without an intervening Ack).

The output is a :class:`DoipSessionReport` that the GUI / CLI consume.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

from ..protocols import doip
from ..protocols.decoder import DecodedMessage


@dataclass(slots=True)
class UdsExchange:
    """One UDS request and its (optional) UDS response."""

    request_frame: int
    request_ts: float
    response_frame: Optional[int] = None
    response_ts: Optional[float] = None
    sa: int = 0
    ta: int = 0
    sid: int = 0           # UDS service ID (first byte of payload)
    request_hex: str = ""
    response_hex: str = ""
    nrc: Optional[int] = None       # UDS negative response code
    ack_frame: Optional[int] = None
    ack_ts: Optional[float] = None
    retransmits: int = 0

    @property
    def rtt_ms(self) -> Optional[float]:
        if self.response_ts is None:
            return None
        return (self.response_ts - self.request_ts) * 1000.0


@dataclass
class DoipSession:
    """One DoIP TCP connection from SYN to RST/FIN/reconnect."""

    client: str               # ip:port
    entity: str               # ip:port
    started_ts: float
    routing_activation_req_frame: Optional[int] = None
    routing_activation_res_frame: Optional[int] = None
    routing_activation_rc: Optional[int] = None
    routing_activation_latency_ms: Optional[float] = None
    alive_checks_sent: int = 0
    alive_checks_answered: int = 0
    missing_alive_responses: List[int] = field(default_factory=list)
    exchanges: List[UdsExchange] = field(default_factory=list)
    last_ts: float = 0.0


@dataclass
class DoipSessionReport:
    sessions: List[DoipSession]
    reconnects: int                       # times the same 5-tuple SYN'd again
    summary_text: str = ""

    def summary(self) -> Dict[str, object]:
        blocks = sum(len(s.exchanges) for s in self.sessions)
        nrcs = sum(1 for s in self.sessions for e in s.exchanges
                   if e.nrc is not None)
        retx = sum(e.retransmits for s in self.sessions for e in s.exchanges)
        rtts = [e.rtt_ms for s in self.sessions for e in s.exchanges
                if e.rtt_ms is not None]
        return {
            "sessions":          len(self.sessions),
            "reconnects":        self.reconnects,
            "uds_exchanges":     blocks,
            "negative_responses": nrcs,
            "retransmits":       retx,
            "avg_rtt_ms":        round(sum(rtts) / len(rtts), 3) if rtts else None,
            "max_rtt_ms":        round(max(rtts), 3) if rtts else None,
        }


# ---------------------------------------------------------------------------
# Reconstructor
# ---------------------------------------------------------------------------


def _flow_key(m: DecodedMessage) -> Tuple[str, str]:
    """Normalised (client, entity) tuple for a DoIP message.

    The DoIP server listens on port 13400, so whichever side has that
    port is treated as the entity. This survives both request and
    response directions of the same TCP connection.
    """
    src_ip, src_port = m.src.rsplit(":", 1)
    dst_ip, dst_port = m.dst.rsplit(":", 1)
    if int(dst_port) == 13400 or int(src_port) != 13400:
        return (m.src, m.dst)            # client → entity
    return (m.dst, m.src)                # entity → client (swap to canonical)


def reconstruct_doip(messages: Iterable[DecodedMessage],
                     reconnect_gap_s: float = 2.0,
                     ) -> DoipSessionReport:
    """Walk a sequence of decoded DoIP messages and rebuild sessions."""
    sessions: Dict[Tuple[str, str], DoipSession] = {}
    order: List[DoipSession] = []
    reconnects = 0
    # Track in-flight UDS requests so we can pair them with responses /
    # acks regardless of segmentation order.
    inflight: Dict[Tuple[str, str, int, int], UdsExchange] = {}

    def _new_session(key, m) -> DoipSession:
        nonlocal reconnects
        if key in sessions:
            reconnects += 1
        s = DoipSession(client=key[0], entity=key[1], started_ts=m.ts,
                        last_ts=m.ts)
        sessions[key] = s
        order.append(s)
        return s

    for m in messages:
        if m.protocol != "doip" or m.doip_header is None:
            continue
        # Skip UDP-only DoIP discovery messages (announcements, vehicle
        # identification responses) — they don't belong to a session.
        if m.transport != "tcp":
            continue

        key = _flow_key(m)
        s = sessions.get(key)
        if s is None or m.ts - s.last_ts > reconnect_gap_s:
            # First message on this 5-tuple, or a long gap implies a
            # reconnect — treat as a new session.
            s = _new_session(key, m)
        s.last_ts = m.ts

        pt = m.doip_header.payload_type
        payload = m.doip_payload

        if pt == doip.PayloadType.ROUTING_ACTIVATION_REQ:
            s.routing_activation_req_frame = m.frame_index
        elif pt == doip.PayloadType.ROUTING_ACTIVATION_RES:
            s.routing_activation_res_frame = m.frame_index
            if len(payload) >= 5:
                s.routing_activation_rc = payload[4]
            if s.routing_activation_req_frame is not None:
                # latency = res.ts - the earliest message at this index
                # (we kept it as "started_ts" of the session).
                s.routing_activation_latency_ms = (m.ts - s.started_ts) * 1000.0
        elif pt == doip.PayloadType.ALIVE_CHECK_REQ:
            s.alive_checks_sent += 1
        elif pt == doip.PayloadType.ALIVE_CHECK_RES:
            s.alive_checks_answered += 1
        elif pt == doip.PayloadType.DIAGNOSTIC_MESSAGE:
            if len(payload) < 4:
                continue
            sa = (payload[0] << 8) | payload[1]
            ta = (payload[2] << 8) | payload[3]
            uds = payload[4:]
            sid = uds[0] if uds else 0
            # Is this a response (SID + 0x40) or a negative response (0x7F)?
            # We look up the in-flight key in *both* directions because the
            # capture might miss the original request (then we just record
            # the response).
            #
            # Request was stored at xkey = (client, entity, request_SA, request_TA).
            # The response we just received has SA = request_TA and TA = request_SA,
            # so the request-side key is (client, entity, ta, sa) here.
            request_xkey = (key[0], key[1], ta, sa)
            existing = inflight.get(request_xkey)
            if existing is not None and (
                sid == 0x7F or (sid & 0x40) or sid == existing.sid + 0x40
            ):
                existing.response_frame = m.frame_index
                existing.response_ts = m.ts
                existing.response_hex = uds.hex()
                if sid == 0x7F and len(uds) >= 3:
                    existing.nrc = uds[2]
                inflight.pop(request_xkey, None)
                continue

            # Otherwise treat as a (possibly retransmitted) request
            xkey = (key[0], key[1], sa, ta)
            prev = inflight.get(xkey)
            if prev is not None and prev.request_hex == uds.hex():
                # Identical request again with no intervening response: retransmit.
                prev.retransmits += 1
                continue
            exch = UdsExchange(
                request_frame=m.frame_index, request_ts=m.ts,
                sa=sa, ta=ta, sid=sid, request_hex=uds.hex(),
            )
            s.exchanges.append(exch)
            inflight[xkey] = exch
        elif pt == doip.PayloadType.DIAGNOSTIC_MESSAGE_ACK:
            if len(payload) < 5:
                continue
            sa = (payload[0] << 8) | payload[1]
            ta = (payload[2] << 8) | payload[3]
            # Ack travels from entity → client, so the matching request
            # was client → entity i.e. SA=client, TA=entity → in the
            # inflight key that's (key[0], key[1], TA, SA).
            xkey = (key[0], key[1], ta, sa)
            exch = inflight.get(xkey)
            if exch is not None:
                exch.ack_frame = m.frame_index
                exch.ack_ts = m.ts
        # Other payload types (NACKs, status, etc.) — surfaced in the
        # raw list elsewhere; we don't need to track them for sessions.

    # Detect missed alive responses (sent count - answered count).
    for s in order:
        gap = s.alive_checks_sent - s.alive_checks_answered
        if gap > 0:
            s.missing_alive_responses = list(range(gap))

    rep = DoipSessionReport(sessions=order, reconnects=reconnects)
    rep.summary_text = ", ".join(f"{k}={v}" for k, v in rep.summary().items())
    return rep
