"""Offline SOME/IP-SD timing analyser — operates on real captures.

Where :mod:`someip_suite.modules.sd_analyzer` *simulates* an ECU boot
schedule, this module reconstructs the *actual* schedule that happened
on the wire. Given the SD messages decoded from a pcap by
:class:`someip_suite.protocols.decoder.CaptureDecoder`, it:

* groups OfferService / FindService / SubscribeEventgroup entries per
  *(ECU = source IP) × (service_id, instance_id)*;
* recovers each ECU's first-offer time (≈ INITIAL_DELAY post-boot from
  the perspective of the trace zero), the empirically observed
  REPETITIONS_BASE_DELAY back-off ratio, the number of repetition
  offers and the CYCLIC_OFFER_DELAY in the steady state;
* compares those numbers to AUTOSAR PRS SD R21-11 timing constraints
  and to user-supplied expected bounds, surfacing every violation with
  the offending frame number(s) so the user can jump straight to the
  packet in Wireshark.

The implementation is pure standard library and deterministic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

from ..protocols import someip
from ..protocols.decoder import DecodedMessage


# AUTOSAR PRS SD R21-11 defaults (informative — used as sanity checks)
PRS_INITIAL_DELAY_MIN_MS = 10.0       # §4.2.1 INITIAL_DELAY_MIN
PRS_INITIAL_DELAY_MAX_MS = 3000.0     # §4.2.1 INITIAL_DELAY_MAX
PRS_REPETITIONS_BASE_MIN_MS = 10.0    # §4.2.1 REPETITIONS_BASE_DELAY (lower bound)
PRS_REPETITIONS_BASE_MAX_MS = 5000.0
PRS_REPETITIONS_MAX_DEFAULT = 3
PRS_CYCLIC_OFFER_MAX_MS = 5000.0      # §4.2.1 CYCLIC_OFFER_DELAY soft cap


@dataclass
class SdExpectations:
    """User-supplied bounds for the analyser.

    Any field left at its default acts as a no-op (only the AUTOSAR
    informative bounds apply). When set, the analyser flags ECUs whose
    observed timing falls outside the band.
    """

    initial_delay_min_ms: float = PRS_INITIAL_DELAY_MIN_MS
    initial_delay_max_ms: float = PRS_INITIAL_DELAY_MAX_MS
    repetitions_base_min_ms: float = PRS_REPETITIONS_BASE_MIN_MS
    repetitions_base_max_ms: float = PRS_REPETITIONS_BASE_MAX_MS
    repetitions_max: int = PRS_REPETITIONS_MAX_DEFAULT
    cyclic_offer_min_ms: float = 100.0
    cyclic_offer_max_ms: float = PRS_CYCLIC_OFFER_MAX_MS


@dataclass
class SdEntryRecord:
    """One SD entry observed on the wire (offer, find or subscribe)."""

    frame_index: int
    ts: float
    src_ip: str
    kind: str           # "offer" | "stop-offer" | "find" | "subscribe" | "subscribe-ack"
    service_id: int
    instance_id: int
    major: int
    minor: int
    ttl: int


@dataclass
class EcuServiceTiming:
    """Reconstructed schedule for a single (ECU, service, instance)."""

    src_ip: str
    service_id: int
    instance_id: int
    offers: List[SdEntryRecord] = field(default_factory=list)
    stop_offers: List[SdEntryRecord] = field(default_factory=list)

    @property
    def first_offer_ts(self) -> Optional[float]:
        return self.offers[0].ts if self.offers else None

    @property
    def initial_delay_ms(self) -> Optional[float]:
        """Time from trace zero to the first OfferService."""
        return self.first_offer_ts * 1000.0 if self.first_offer_ts is not None else None

    def repetition_deltas_ms(self) -> List[float]:
        """Intervals between successive offers, in ms (newest last)."""
        out: List[float] = []
        for a, b in zip(self.offers, self.offers[1:]):
            out.append((b.ts - a.ts) * 1000.0)
        return out

    def estimated_repetitions_base_ms(self) -> Optional[float]:
        """Initial inter-offer gap (≈ REPETITIONS_BASE_DELAY) in ms."""
        d = self.repetition_deltas_ms()
        return d[0] if d else None

    def estimated_cyclic_offer_ms(self) -> Optional[float]:
        """Median of the later inter-offer gaps (≈ CYCLIC_OFFER_DELAY).

        Once an ECU finishes the repetition phase its offer interval
        becomes (approximately) constant. We take the median of the last
        4 gaps to be robust against the back-off ramp.
        """
        d = self.repetition_deltas_ms()
        if len(d) < 2:
            return None
        tail = d[-min(4, len(d)):]
        s = sorted(tail)
        mid = len(s) // 2
        return s[mid] if len(s) % 2 else 0.5 * (s[mid - 1] + s[mid])

    def repetition_count(self) -> int:
        """Number of offers in the repetition phase (heuristic).

        We count the offers whose inter-arrival roughly doubles (within
        ±40%) the previous one, plus the first offer. Falls back to all
        offers if no back-off is detectable.
        """
        d = self.repetition_deltas_ms()
        if not d:
            return 0
        count = 1   # first offer
        for i, dt in enumerate(d):
            if i == 0:
                count += 1
                prev = dt
                continue
            if 1.6 * prev <= dt <= 2.4 * prev:
                count += 1
                prev = dt
            else:
                break
        return count


@dataclass
class SdViolation:
    src_ip: str
    service_id: int
    instance_id: int
    kind: str           # short tag, e.g. "initial-delay-too-large"
    detail: str
    frame_index: int
    ts: float


@dataclass
class SdReport:
    finds: List[SdEntryRecord]
    subscribes: List[SdEntryRecord]
    timings: List[EcuServiceTiming]
    violations: List[SdViolation]
    ecus: List[str]                    # unique source IPs observed
    services: List[Tuple[int, int]]    # unique (sid, inst) observed

    def summary(self) -> Dict[str, object]:
        return {
            "ecus":            len(self.ecus),
            "services":        len(self.services),
            "offers":          sum(len(t.offers) for t in self.timings),
            "finds":           len(self.finds),
            "subscribes":      len(self.subscribes),
            "violations":      len(self.violations),
            "first_offer_ms":  min((t.initial_delay_ms for t in self.timings
                                    if t.initial_delay_ms is not None),
                                   default=None),
        }


# ---------------------------------------------------------------------------
# Analyser
# ---------------------------------------------------------------------------


def _entry_kind(e: someip.SdEntry) -> str:
    if e.type == someip.SdEntryType.OFFER_SERVICE:
        return "stop-offer" if e.ttl == 0 else "offer"
    if e.type == someip.SdEntryType.FIND_SERVICE:
        return "find"
    if e.type == someip.SdEntryType.SUBSCRIBE_EVENTGROUP:
        return "subscribe"
    if e.type == someip.SdEntryType.SUBSCRIBE_EVENTGROUP_ACK:
        return "subscribe-ack"
    return f"entry-0x{e.type:02X}"


def analyse_sd(messages: Iterable[DecodedMessage],
               expectations: Optional[SdExpectations] = None,
               ) -> SdReport:
    """Run the offline SD analyser on a sequence of decoded SD messages.

    Messages that aren't SOME/IP-SD are silently ignored so callers can
    pass the full output of :class:`CaptureDecoder` unfiltered.
    """
    exp = expectations or SdExpectations()
    finds: List[SdEntryRecord] = []
    subscribes: List[SdEntryRecord] = []
    timings: Dict[Tuple[str, int, int], EcuServiceTiming] = {}
    ecus: Dict[str, None] = {}            # ordered set
    services: Dict[Tuple[int, int], None] = {}

    # Normalise the trace's t=0 to the first SD packet's timestamp so
    # "initial delay" is meaningful even when the pcap doesn't start at
    # an ECU's power-on.
    base_ts: Optional[float] = None

    for m in messages:
        if m.protocol != "someip-sd" or m.sd_message is None:
            continue
        src_ip = m.src.rsplit(":", 1)[0]
        ecus.setdefault(src_ip, None)
        if base_ts is None:
            base_ts = m.ts
        rel_ts = max(0.0, m.ts - base_ts)
        for entry in m.sd_message.entries:
            rec = SdEntryRecord(
                frame_index=m.frame_index, ts=rel_ts,
                src_ip=src_ip, kind=_entry_kind(entry),
                service_id=entry.service_id, instance_id=entry.instance_id,
                major=entry.major_version, minor=entry.minor_version,
                ttl=entry.ttl,
            )
            services.setdefault((entry.service_id, entry.instance_id), None)
            if rec.kind == "find":
                finds.append(rec)
            elif rec.kind in ("subscribe", "subscribe-ack"):
                subscribes.append(rec)
            else:  # offer / stop-offer
                key = (src_ip, entry.service_id, entry.instance_id)
                t = timings.setdefault(key, EcuServiceTiming(
                    src_ip=src_ip, service_id=entry.service_id,
                    instance_id=entry.instance_id))
                (t.stop_offers if rec.kind == "stop-offer" else t.offers).append(rec)

    timings_list = sorted(timings.values(),
                          key=lambda t: (t.src_ip, t.service_id, t.instance_id))
    violations = _check_violations(timings_list, exp)

    return SdReport(
        finds=finds, subscribes=subscribes,
        timings=timings_list, violations=violations,
        ecus=list(ecus.keys()),
        services=list(services.keys()),
    )


def _check_violations(timings: List[EcuServiceTiming],
                      exp: SdExpectations) -> List[SdViolation]:
    violations: List[SdViolation] = []
    for t in timings:
        if not t.offers:
            continue
        first = t.offers[0]

        init_ms = t.initial_delay_ms or 0.0
        if init_ms > exp.initial_delay_max_ms:
            violations.append(SdViolation(
                t.src_ip, t.service_id, t.instance_id,
                "initial-delay-too-large",
                (f"first OfferService at {init_ms:.1f} ms exceeds "
                 f"INITIAL_DELAY_MAX={exp.initial_delay_max_ms:.0f} ms "
                 "(AUTOSAR PRS SD R21-11 §4.2.1)"),
                first.frame_index, first.ts,
            ))

        deltas = t.repetition_deltas_ms()
        rep_base = t.estimated_repetitions_base_ms()
        if rep_base is not None:
            if rep_base < exp.repetitions_base_min_ms:
                violations.append(SdViolation(
                    t.src_ip, t.service_id, t.instance_id,
                    "repetitions-base-too-small",
                    (f"observed REPETITIONS_BASE_DELAY≈{rep_base:.1f} ms "
                     f"is below the {exp.repetitions_base_min_ms:.0f} ms "
                     "PRS minimum — risk of multicast burst"),
                    t.offers[1].frame_index, t.offers[1].ts,
                ))
            elif rep_base > exp.repetitions_base_max_ms:
                violations.append(SdViolation(
                    t.src_ip, t.service_id, t.instance_id,
                    "repetitions-base-too-large",
                    (f"observed REPETITIONS_BASE_DELAY≈{rep_base:.1f} ms "
                     "exceeds PRS maximum"),
                    t.offers[1].frame_index, t.offers[1].ts,
                ))

        # Validate the doubling back-off across the first N gaps (where N is
        # the configured REPETITIONS_MAX). If an ECU sends only flat-spaced
        # repetitions it never enters cyclic mode properly.
        check_pairs = min(max(0, len(deltas) - 1), max(0, exp.repetitions_max - 1))
        for i in range(check_pairs):
            a, b = deltas[i], deltas[i + 1]
            if b < a * 1.5:
                violations.append(SdViolation(
                    t.src_ip, t.service_id, t.instance_id,
                    "missing-exponential-backoff",
                    (f"repetition gap #{i + 2} = {b:.1f} ms did not double "
                     f"the previous {a:.1f} ms — back-off broken"),
                    t.offers[i + 2].frame_index, t.offers[i + 2].ts,
                ))
                break

        cyc = t.estimated_cyclic_offer_ms()
        if cyc is not None:
            if cyc < exp.cyclic_offer_min_ms:
                violations.append(SdViolation(
                    t.src_ip, t.service_id, t.instance_id,
                    "cyclic-offer-too-fast",
                    (f"steady-state OfferService cadence≈{cyc:.1f} ms "
                     f"is below {exp.cyclic_offer_min_ms:.0f} ms — "
                     "may flood the multicast group"),
                    t.offers[-1].frame_index, t.offers[-1].ts,
                ))
            elif cyc > exp.cyclic_offer_max_ms:
                violations.append(SdViolation(
                    t.src_ip, t.service_id, t.instance_id,
                    "cyclic-offer-too-slow",
                    (f"steady-state OfferService cadence≈{cyc:.1f} ms "
                     "exceeds CYCLIC_OFFER_DELAY soft cap"),
                    t.offers[-1].frame_index, t.offers[-1].ts,
                ))

    return violations
