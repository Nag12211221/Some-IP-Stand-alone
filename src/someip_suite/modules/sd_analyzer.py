"""SOME/IP-SD timing analyser & multi-ECU boot simulator.

This module is *the* tool corresponding to solution #1 of the project
brief. It models any number of ECUs going through the AUTOSAR SOME/IP-SD
state machine (NotReady → InitialWait → Repetition → Main) and verifies:

* application-readiness gating (no ``OfferService`` before the service
  reports AVAILABLE);
* per-ECU random ``INITIAL_DELAY`` inside ``[min, max]`` (multicast burst
  prevention);
* exponential ``REPETITIONS_BASE_DELAY`` back-off, with
  ``REPETITIONS_MAX`` configurable;
* drop-resilient discovery — synthetic packet loss can be injected and
  the simulator counts how many clients still discovered the service in
  time.

The engine is deterministic when given a seed, which lets the user
reproduce a failing schedule.
"""

from __future__ import annotations

import enum
import math
import random
import statistics
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional


class SdState(enum.Enum):
    NOT_READY = "NotReady"
    INITIAL_WAIT = "InitialWait"
    REPETITION = "Repetition"
    MAIN = "Main"
    DOWN = "Down"


@dataclass
class EcuConfig:
    name: str
    service_id: int
    instance_id: int
    app_ready_after_ms: float           # how long the app needs to come up
    initial_delay_min_ms: float = 50.0
    initial_delay_max_ms: float = 500.0
    repetitions_base_delay_ms: float = 200.0
    repetitions_max: int = 3
    cyclic_offer_delay_ms: float = 2000.0
    # Probability that an outgoing SD packet is "lost" on the wire.
    loss_probability: float = 0.0


@dataclass
class SdEvent:
    t_ms: float
    ecu: str
    kind: str           # state-change / offer-sent / offer-lost / discovered / violation
    detail: str = ""


@dataclass
class SimulationReport:
    duration_ms: float
    events: List[SdEvent]
    discovery_latency_ms: Dict[str, float]   # service_id:instance_id → time-to-discover
    violations: List[SdEvent]

    def summary(self) -> Dict[str, object]:
        lat = list(self.discovery_latency_ms.values())
        return {
            "ecu_count": len({e.ecu for e in self.events}),
            "event_count": len(self.events),
            "violations": len(self.violations),
            "discovered": len(lat),
            "mean_discovery_ms": round(statistics.mean(lat), 2) if lat else None,
            "p95_discovery_ms": round(_percentile(lat, 95), 2) if lat else None,
            "max_discovery_ms": round(max(lat), 2) if lat else None,
        }


def _percentile(values: List[float], p: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    k = (len(s) - 1) * (p / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return s[int(k)]
    return s[f] + (s[c] - s[f]) * (k - f)


class SdSimulator:
    """Multi-ECU SOME/IP-SD timing simulator.

    The simulator runs in *virtual* time (no real sleeps) so a 10-second
    scenario completes in milliseconds. A progress callback is invoked
    periodically so the UI can drive a progress bar.
    """

    def __init__(self, ecus: List[EcuConfig], duration_ms: float = 10_000.0,
                 client_listen_ms: float = 5_000.0, seed: Optional[int] = None,
                 progress_cb: Optional[Callable[[float], None]] = None) -> None:
        self.ecus = ecus
        self.duration_ms = duration_ms
        self.client_listen_ms = client_listen_ms
        self._rng = random.Random(seed)
        self._progress_cb = progress_cb
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> SimulationReport:
        events: List[SdEvent] = []
        violations: List[SdEvent] = []
        discovered: Dict[str, float] = {}

        # Each ECU's per-run schedule lives in a small struct.
        @dataclass
        class _Ctx:
            cfg: EcuConfig
            state: SdState = SdState.NOT_READY
            next_action_ms: float = 0.0
            repetition_index: int = 0

        ctxs = [_Ctx(cfg=e) for e in self.ecus]

        t = 0.0
        tick = 1.0   # 1 ms virtual tick
        next_progress = 0.0
        while t <= self.duration_ms and not self._stop.is_set():
            for c in ctxs:
                self._step_ecu(c, t, events, violations, discovered)
            if t >= next_progress and self._progress_cb is not None:
                self._progress_cb(min(1.0, t / self.duration_ms))
                next_progress = t + 50.0
            t += tick

        if self._progress_cb is not None:
            self._progress_cb(1.0)

        return SimulationReport(
            duration_ms=self.duration_ms,
            events=events,
            discovery_latency_ms=discovered,
            violations=violations,
        )

    # ------------------------------------------------------------------
    def _step_ecu(self, c, t: float, events: List[SdEvent],
                  violations: List[SdEvent], discovered: Dict[str, float]) -> None:
        cfg = c.cfg
        key = f"{cfg.service_id:04X}:{cfg.instance_id:04X}"

        # State transitions
        if c.state is SdState.NOT_READY:
            if t >= cfg.app_ready_after_ms:
                # Schedule InitialWait with random jitter (anti-burst).
                jitter = self._rng.uniform(cfg.initial_delay_min_ms,
                                           cfg.initial_delay_max_ms)
                c.state = SdState.INITIAL_WAIT
                c.next_action_ms = t + jitter
                events.append(SdEvent(t, cfg.name, "state",
                                      f"NotReady→InitialWait (jitter={jitter:.1f}ms)"))
            return

        if c.state is SdState.INITIAL_WAIT and t >= c.next_action_ms:
            # Application readiness gating check
            if t < cfg.app_ready_after_ms:
                v = SdEvent(t, cfg.name, "violation",
                            "OfferService scheduled before app ready")
                violations.append(v)
                events.append(v)
            self._send_offer(c, t, events, discovered)
            c.state = SdState.REPETITION
            c.repetition_index = 0
            # base * 2^0
            c.next_action_ms = t + cfg.repetitions_base_delay_ms
            return

        if c.state is SdState.REPETITION and t >= c.next_action_ms:
            self._send_offer(c, t, events, discovered)
            c.repetition_index += 1
            if c.repetition_index >= cfg.repetitions_max:
                c.state = SdState.MAIN
                c.next_action_ms = t + cfg.cyclic_offer_delay_ms
            else:
                # exponential back-off
                delay = cfg.repetitions_base_delay_ms * (2 ** c.repetition_index)
                c.next_action_ms = t + delay
            return

        if c.state is SdState.MAIN and t >= c.next_action_ms:
            self._send_offer(c, t, events, discovered)
            c.next_action_ms = t + cfg.cyclic_offer_delay_ms

    def _send_offer(self, c, t, events, discovered):
        cfg = c.cfg
        key = f"{cfg.service_id:04X}:{cfg.instance_id:04X}"
        if self._rng.random() < cfg.loss_probability:
            events.append(SdEvent(t, cfg.name, "offer-lost", key))
            return
        events.append(SdEvent(t, cfg.name, "offer-sent", key))
        if key not in discovered and t <= self.client_listen_ms:
            discovered[key] = t


# ---------------------------------------------------------------------------
# Convenience defaults
# ---------------------------------------------------------------------------

def default_scenario() -> List[EcuConfig]:
    """Reasonable multi-ECU boot scenario used by the GUI defaults."""
    return [
        EcuConfig("Gateway", 0x1001, 1, app_ready_after_ms=120),
        EcuConfig("BodyCtrl", 0x2001, 1, app_ready_after_ms=320),
        EcuConfig("Cluster",  0x3001, 1, app_ready_after_ms=480),
        EcuConfig("ADAS",     0x4001, 1, app_ready_after_ms=820,
                  loss_probability=0.05),
        EcuConfig("Infotain", 0x5001, 1, app_ready_after_ms=1500,
                  initial_delay_min_ms=100, initial_delay_max_ms=800),
    ]
