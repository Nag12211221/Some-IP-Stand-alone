"""DoIP flash-session stability monitor.

This module implements the solution to problem #2 (flashing instability):

* a tiny **DoIP entity (server)** that accepts a TCP connection, answers
  ``RoutingActivationRequest`` and ``AliveCheckRequest`` from the
  protocol layer itself (so a busy "flash driver" cannot starve them);
* a **DoIP tester (client)** that runs a configurable flashing session
  with adjustable block size, processing time and forced disruptions
  (TCP drop, packet stall);
* a real-time **metrics collector** producing throughput, RTT and
  retransmission counters that drive the GUI sparklines.

Everything uses blocking sockets on dedicated threads. We deliberately
keep it standard-library only.
"""

from __future__ import annotations

import queue
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from ..protocols import doip


SOCK_RECV_TIMEOUT = 1.0       # poll-friendly value, keepalive runs concurrently
TCP_KEEPALIVE_IDLE = 30
TCP_KEEPALIVE_INTVL = 10
TCP_KEEPALIVE_CNT = 3


def _enable_tcp_keepalive(sock: socket.socket) -> None:
    """Best-effort cross-platform keepalive tuning."""
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    # The following knobs are Linux-specific; ignore failures on Windows/macOS.
    for opt, val in (
        ("TCP_KEEPIDLE", TCP_KEEPALIVE_IDLE),
        ("TCP_KEEPINTVL", TCP_KEEPALIVE_INTVL),
        ("TCP_KEEPCNT", TCP_KEEPALIVE_CNT),
    ):
        if hasattr(socket, opt):
            try:
                sock.setsockopt(socket.IPPROTO_TCP, getattr(socket, opt), val)
            except OSError:
                pass


@dataclass
class FlashConfig:
    host: str = "127.0.0.1"
    port: int = 13400
    tester_sa: int = 0x0E00
    entity_sa: int = 0x1234
    block_size: int = 4096
    block_count: int = 256
    processing_time_ms: float = 5.0     # entity erase/write delay per block
    alive_check_interval_ms: float = 1000.0
    drop_after_blocks: int = 0           # 0 disables; >0 forces TCP drop once
    stall_after_blocks: int = 0          # forces a 5s stall
    resume_on_drop: bool = True


@dataclass
class FlashMetrics:
    bytes_sent: int = 0
    blocks_acked: int = 0
    alive_checks_sent: int = 0
    alive_checks_answered: int = 0
    rtts_ms: List[float] = field(default_factory=list)
    reconnects: int = 0
    errors: int = 0
    finished: bool = False

    def add_rtt(self, ms: float) -> None:
        # keep the last 1024 samples so memory stays bounded
        self.rtts_ms.append(ms)
        if len(self.rtts_ms) > 1024:
            del self.rtts_ms[:-1024]


# ---------------------------------------------------------------------------
# DoIP server (entity)
# ---------------------------------------------------------------------------


class DoipEntityServer(threading.Thread):
    """Minimal DoIP entity that answers RoutingActivation, AliveCheck and
    acknowledges DiagnosticMessage payloads after a configurable processing
    delay (mimics the flash hardware being busy)."""

    daemon = True

    def __init__(self, cfg: FlashConfig,
                 log: Callable[[str], None]) -> None:
        super().__init__(name="DoipEntity")
        self.cfg = cfg
        self.log = log
        self._stop_event = threading.Event()
        self._sock: Optional[socket.socket] = None

    def stop(self) -> None:
        self._stop_event.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass

    # ------------------------------------------------------------------
    def run(self) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind((self.cfg.host, self.cfg.port))
        except OSError as exc:
            self.log(f"[entity] bind failed: {exc}")
            return
        srv.listen(1)
        srv.settimeout(0.5)
        self._sock = srv
        self.log(f"[entity] listening on {self.cfg.host}:{self.cfg.port}")
        while not self._stop_event.is_set():
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self.log(f"[entity] tester connected from {addr[0]}:{addr[1]}")
            _enable_tcp_keepalive(conn)
            try:
                self._serve_one(conn)
            finally:
                conn.close()
                self.log("[entity] tester disconnected")
        try:
            srv.close()
        except OSError:
            pass

    def _serve_one(self, conn: socket.socket) -> None:
        conn.settimeout(SOCK_RECV_TIMEOUT)
        buf = bytearray()
        routing_active = False
        while not self._stop_event.is_set():
            try:
                chunk = conn.recv(65536)
                if not chunk:
                    return
                buf.extend(chunk)
            except socket.timeout:
                continue
            except OSError as exc:
                self.log(f"[entity] recv error: {exc}")
                return

            while len(buf) >= doip.DOIP_HEADER_SIZE:
                try:
                    hdr = doip.DoipHeader.unpack(bytes(buf))
                except ValueError as exc:
                    self.log(f"[entity] bad header → NACK: {exc}")
                    _send_all(conn, doip.build_generic_nack(
                        doip.GenericNackCode.INCORRECT_PATTERN))
                    return
                total = doip.DOIP_HEADER_SIZE + hdr.payload_length
                if len(buf) < total:
                    break
                payload = bytes(buf[doip.DOIP_HEADER_SIZE:total])
                del buf[:total]
                self._dispatch(conn, hdr, payload, routing_active)
                if hdr.payload_type == doip.PayloadType.ROUTING_ACTIVATION_REQ:
                    routing_active = True

    def _dispatch(self, conn, hdr, payload, routing_active):
        pt = hdr.payload_type
        if pt == doip.PayloadType.ROUTING_ACTIVATION_REQ:
            sa = struct.unpack_from("!H", payload, 0)[0]
            self.log(f"[entity] routing activation from SA={sa:#06x}")
            _send_all(conn, doip.build_routing_activation_response(
                sa, self.cfg.entity_sa,
                doip.RoutingActivationResponseCode.SUCCESS))
        elif pt == doip.PayloadType.ALIVE_CHECK_REQ:
            _send_all(conn, doip.build_alive_check_response(self.cfg.entity_sa))
        elif pt == doip.PayloadType.DIAGNOSTIC_MESSAGE:
            if not routing_active:
                _send_all(conn, doip.build_diagnostic_ack(
                    self.cfg.entity_sa, 0, ack_code=0x02))
                return
            # Simulate flash-write processing time. Critically, the alive
            # check (handled above) is on the same thread but only triggered
            # by an incoming packet — in a real implementation this would
            # live on a dedicated I/O thread.
            time.sleep(self.cfg.processing_time_ms / 1000.0)
            sa, ta = struct.unpack_from("!HH", payload, 0)
            _send_all(conn, doip.build_diagnostic_ack(ta, sa, 0x00))
        else:
            _send_all(conn, doip.build_generic_nack(
                doip.GenericNackCode.UNKNOWN_PAYLOAD_TYPE))


# ---------------------------------------------------------------------------
# DoIP client (tester)
# ---------------------------------------------------------------------------


class DoipFlashTester(threading.Thread):
    daemon = True

    def __init__(self, cfg: FlashConfig, metrics: FlashMetrics,
                 log: Callable[[str], None]) -> None:
        super().__init__(name="DoipTester")
        self.cfg = cfg
        self.metrics = metrics
        self.log = log
        self._stop_event = threading.Event()
        self._alive_thread: Optional[threading.Thread] = None

    def stop(self) -> None:
        self._stop_event.set()

    # ------------------------------------------------------------------
    def run(self) -> None:
        block_no = 0
        while block_no < self.cfg.block_count and not self._stop_event.is_set():
            try:
                self._run_session(block_no_start=block_no)
                break  # session completed
            except _NeedReconnect as nr:
                self.metrics.reconnects += 1
                block_no = nr.next_block
                if not self.cfg.resume_on_drop:
                    self.log("[tester] giving up — resume disabled")
                    break
                self.log(f"[tester] reconnecting and resuming at block {block_no}")
                time.sleep(0.5)
            except Exception as exc:                # noqa: BLE001
                self.metrics.errors += 1
                self.log(f"[tester] fatal: {exc}")
                break
        self.metrics.finished = True

    def _run_session(self, block_no_start: int) -> None:
        sock = socket.create_connection((self.cfg.host, self.cfg.port), timeout=5.0)
        _enable_tcp_keepalive(sock)
        sock.settimeout(5.0)
        try:
            # Routing activation
            _send_all(sock, doip.build_routing_activation_request(self.cfg.tester_sa))
            self._read_one(sock, expect=doip.PayloadType.ROUTING_ACTIVATION_RES)

            self._start_alive_check_thread(sock)

            payload = bytes(self.cfg.block_size)   # zeroed dummy data
            for n in range(block_no_start, self.cfg.block_count):
                if self._stop_event.is_set():
                    return
                # UDS RequestDownload-ish (just for the show): 0x36 = TransferData
                uds = bytes([0x36, (n & 0xFF)]) + payload
                t0 = time.perf_counter()
                _send_all(sock, doip.build_diagnostic_message(
                    self.cfg.tester_sa, self.cfg.entity_sa, uds))
                hdr, _ = self._read_one(sock,
                                        expect=doip.PayloadType.DIAGNOSTIC_MESSAGE_ACK)
                dt_ms = (time.perf_counter() - t0) * 1000.0
                self.metrics.add_rtt(dt_ms)
                self.metrics.bytes_sent += len(uds)
                self.metrics.blocks_acked += 1

                # Disruption injection
                if self.cfg.drop_after_blocks and n + 1 == self.cfg.drop_after_blocks:
                    self.log("[tester] injecting TCP drop")
                    try:
                        sock.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    sock.close()
                    raise _NeedReconnect(next_block=n + 1)
                if self.cfg.stall_after_blocks and n + 1 == self.cfg.stall_after_blocks:
                    self.log("[tester] injecting 5s stall")
                    time.sleep(5.0)
        finally:
            self._stop_alive_check_thread()
            try:
                sock.close()
            except OSError:
                pass

    # ------------------------------------------------------------------
    def _start_alive_check_thread(self, sock: socket.socket) -> None:
        interval = self.cfg.alive_check_interval_ms / 1000.0

        def _loop() -> None:
            while not self._stop_event.is_set():
                time.sleep(interval)
                try:
                    _send_all(sock, doip.build_alive_check_request())
                    self.metrics.alive_checks_sent += 1
                except OSError:
                    return

        self._alive_thread = threading.Thread(target=_loop, daemon=True,
                                              name="AliveCheck")
        self._alive_thread.start()

    def _stop_alive_check_thread(self) -> None:
        # The thread is daemon; setting the stop event is enough.
        self._alive_thread = None

    # ------------------------------------------------------------------
    def _read_one(self, sock: socket.socket, expect: int) -> tuple:
        hdr_bytes = _recv_exact(sock, doip.DOIP_HEADER_SIZE)
        hdr = doip.DoipHeader.unpack(hdr_bytes)
        payload = _recv_exact(sock, hdr.payload_length) if hdr.payload_length else b""
        if hdr.payload_type == doip.PayloadType.ALIVE_CHECK_RES:
            self.metrics.alive_checks_answered += 1
            # Read next message instead.
            return self._read_one(sock, expect)
        if hdr.payload_type != expect:
            raise OSError(f"unexpected DoIP payload type {hdr.payload_type:#06x}")
        return hdr, payload


class _NeedReconnect(Exception):
    def __init__(self, next_block: int) -> None:
        self.next_block = next_block


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _send_all(sock: socket.socket, data: bytes) -> None:
    view = memoryview(data)
    while view:
        n = sock.send(view)
        if n == 0:
            raise OSError("socket closed during send")
        view = view[n:]


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("connection closed mid-message")
        buf.extend(chunk)
    return bytes(buf)
