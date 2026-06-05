"""Live network capture — Npcap on Windows, AF_PACKET on Linux.

This module gives the rest of the suite a uniform :class:`LiveCapture`
API:

    cap = LiveCapture("eth0")
    cap.start()                       # spawns a reader thread
    for frame in cap.drain():         # PcapFrame objects with timestamps
        ...
    cap.stop()

On Windows the implementation loads ``wpcap.dll`` (installed by
`Npcap <https://npcap.com/>`_) through :mod:`ctypes`. If Npcap isn't
installed :func:`available_backend` returns ``None`` and the GUI shows a
helpful "Install Npcap from https://npcap.com" message instead of
silently failing.

On Linux we use a raw ``AF_PACKET`` socket — no extra installs needed
(works without root if the binary has ``CAP_NET_RAW``; otherwise the
GUI surfaces the EPERM and tells the user how to fix it).

On macOS / unsupported platforms :func:`available_backend` returns
``None``.

This file is intentionally self-contained and degrades gracefully — it
must not import-fail at module load even when no backend is available,
because the rest of the application (pcap-file analysis, simulator
modes) must still work.
"""

from __future__ import annotations

import ctypes
import os
import platform
import socket
import struct
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Callable, Deque, Iterable, List, Optional

from ..protocols.pcap import (DLT_EN10MB, DLT_LINUX_SLL, PcapFrame, PcapWriter,
                              make_frame)


@dataclass
class CaptureInterface:
    """One network interface presented by the backend."""

    name: str               # backend-specific identifier (Npcap GUID, ifname)
    description: str        # human-readable
    addresses: List[str]    # IPv4/IPv6 strings


# ---------------------------------------------------------------------------
# Backend discovery
# ---------------------------------------------------------------------------


def available_backend() -> Optional[str]:
    """Return ``"npcap"``, ``"afpacket"`` or ``None`` if no backend is usable."""
    if sys.platform.startswith("win"):
        return "npcap" if _try_load_wpcap() is not None else None
    if sys.platform.startswith("linux"):
        return "afpacket" if hasattr(socket, "AF_PACKET") else None
    return None


def list_interfaces() -> List[CaptureInterface]:
    """List capture-capable interfaces on this host (best effort)."""
    backend = available_backend()
    if backend == "npcap":
        return _list_npcap_interfaces()
    if backend == "afpacket":
        return _list_linux_interfaces()
    return []


# ---------------------------------------------------------------------------
# The unified live-capture object
# ---------------------------------------------------------------------------


class LiveCapture:
    """Threaded packet capture that funnels frames into an internal queue.

    The constructor doesn't open the socket — call :meth:`start`. This
    keeps construction side-effect-free so the GUI can build a capture
    object speculatively to validate input.
    """

    def __init__(self, iface_name: str, *,
                 snaplen: int = 65535,
                 max_queue: int = 100_000,
                 promisc: bool = True,
                 on_drop: Optional[Callable[[int], None]] = None) -> None:
        self.iface_name = iface_name
        self.snaplen = snaplen
        self.max_queue = max_queue
        self.promisc = promisc
        self._on_drop = on_drop
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._buf: Deque[PcapFrame] = deque(maxlen=max_queue)
        self._lock = threading.Lock()
        self._counter = 0
        self._dropped = 0
        self._writer: Optional[PcapWriter] = None
        self._writer_lock = threading.Lock()
        self.linktype = DLT_EN10MB
        self.error: Optional[str] = None
        self._backend = available_backend()
        if self._backend is None:
            raise RuntimeError(
                "no live-capture backend available on this platform "
                "(install Npcap on Windows, or run on Linux)")

    # -- recording control ---------------------------------------------
    def begin_recording(self, path: str) -> None:
        """Spool every captured frame to ``path`` (libpcap 2.4 format)."""
        with self._writer_lock:
            if self._writer is not None:
                self._writer.close()
            self._writer = PcapWriter(path, linktype=self.linktype,
                                      snaplen=self.snaplen)

    def end_recording(self) -> Optional[str]:
        with self._writer_lock:
            if self._writer is None:
                return None
            path = self._writer.path
            self._writer.close()
            self._writer = None
            return path

    # -- start / stop ---------------------------------------------------
    def start(self) -> None:
        if self._thread is not None:
            return
        self._stop.clear()
        if self._backend == "npcap":
            target = self._run_npcap
        elif self._backend == "afpacket":
            target = self._run_afpacket
        else:
            raise RuntimeError("no live-capture backend available")
        self._thread = threading.Thread(
            target=target, name=f"LiveCapture[{self.iface_name}]", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        t = self._thread
        if t is not None and t.is_alive():
            t.join(timeout=2.0)
        self._thread = None
        with self._writer_lock:
            if self._writer is not None:
                self._writer.close()
                self._writer = None

    # -- consumer side --------------------------------------------------
    @property
    def captured(self) -> int:
        return self._counter

    @property
    def dropped(self) -> int:
        return self._dropped

    def drain(self) -> List[PcapFrame]:
        """Atomically pull and return every queued frame."""
        with self._lock:
            out = list(self._buf)
            self._buf.clear()
        return out

    # -- producers ------------------------------------------------------
    def _enqueue(self, ts: float, data: bytes) -> None:
        self._counter += 1
        frame = make_frame(self._counter, data, self.linktype, ts)
        with self._lock:
            if len(self._buf) >= self.max_queue:
                # drop oldest
                self._buf.popleft()
                self._dropped += 1
                if self._on_drop is not None:
                    self._on_drop(self._dropped)
            self._buf.append(frame)
        with self._writer_lock:
            if self._writer is not None:
                try:
                    self._writer.write(ts, data)
                except OSError:
                    # disk full, etc — stop recording silently
                    self._writer.close()
                    self._writer = None

    # -- linux backend --------------------------------------------------
    def _run_afpacket(self) -> None:
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,  # type: ignore[attr-defined]
                                 socket.htons(0x0003))
            sock.bind((self.iface_name, 0))
            sock.settimeout(0.5)
        except OSError as exc:
            self.error = f"AF_PACKET open failed: {exc} (need CAP_NET_RAW?)"
            return
        try:
            while not self._stop.is_set():
                try:
                    data, _addr = sock.recvfrom(self.snaplen)
                except socket.timeout:
                    continue
                except OSError as exc:
                    self.error = f"recv failed: {exc}"
                    return
                self._enqueue(time.time(), data)
        finally:
            sock.close()

    # -- windows backend (Npcap via ctypes) -----------------------------
    def _run_npcap(self) -> None:
        wpcap = _try_load_wpcap()
        if wpcap is None:
            self.error = "wpcap.dll not found — install Npcap"
            return
        errbuf = ctypes.create_string_buffer(256)
        # Use the Npcap-specific opener which can do immediate-mode / monitor mode.
        # Fall back to pcap_open_live if pcap_create isn't exported.
        handle = None
        try:
            iface_bytes = self.iface_name.encode("utf-8")
            try:
                handle = wpcap.pcap_create(iface_bytes, errbuf)
                if handle:
                    wpcap.pcap_set_snaplen(handle, self.snaplen)
                    wpcap.pcap_set_promisc(handle, 1 if self.promisc else 0)
                    wpcap.pcap_set_timeout(handle, 100)
                    wpcap.pcap_set_immediate_mode(handle, 1)
                    if wpcap.pcap_activate(handle) != 0:
                        msg = ctypes.cast(wpcap.pcap_geterr(handle),
                                          ctypes.c_char_p).value
                        self.error = (f"pcap_activate failed: "
                                      f"{(msg or b'').decode('utf-8', 'replace')}")
                        return
            except (AttributeError, OSError):
                handle = None
            if not handle:
                handle = wpcap.pcap_open_live(iface_bytes, self.snaplen,
                                              1 if self.promisc else 0,
                                              100, errbuf)
                if not handle:
                    self.error = (f"pcap_open_live failed: "
                                  f"{errbuf.value.decode('utf-8', 'replace')}")
                    return
            # Detect link-layer type to forward to the decoder.
            try:
                self.linktype = wpcap.pcap_datalink(handle)
            except AttributeError:
                pass

            hdr_p = ctypes.POINTER(_PcapPktHdr)()
            data_pp = ctypes.POINTER(ctypes.c_ubyte)()
            while not self._stop.is_set():
                rc = wpcap.pcap_next_ex(handle,
                                        ctypes.byref(hdr_p),
                                        ctypes.byref(data_pp))
                if rc == 0:
                    continue            # timeout — loop and check stop flag
                if rc < 0:
                    msg = ctypes.cast(wpcap.pcap_geterr(handle),
                                      ctypes.c_char_p).value
                    self.error = (f"pcap_next_ex failed: "
                                  f"{(msg or b'').decode('utf-8', 'replace')}")
                    return
                h = hdr_p.contents
                length = h.caplen
                ts = h.ts_sec + h.ts_usec / 1_000_000.0
                buf = ctypes.string_at(data_pp, length)
                self._enqueue(ts, buf)
        finally:
            if handle:
                try:
                    wpcap.pcap_close(handle)
                except OSError:
                    pass


# ---------------------------------------------------------------------------
# Linux interface enumeration (uses /sys/class/net)
# ---------------------------------------------------------------------------


def _list_linux_interfaces() -> List[CaptureInterface]:
    out: List[CaptureInterface] = []
    sys_net = "/sys/class/net"
    if not os.path.isdir(sys_net):
        return out
    for name in sorted(os.listdir(sys_net)):
        addrs: List[str] = []
        # Best-effort: ask the kernel for the addresses via getaddrinfo
        try:
            for fam in (socket.AF_INET, socket.AF_INET6):
                try:
                    for info in socket.getaddrinfo(socket.gethostname(),
                                                   None, fam):
                        addrs.append(info[4][0])
                except OSError:
                    pass
        except OSError:
            pass
        out.append(CaptureInterface(name=name, description=name,
                                    addresses=sorted(set(addrs))))
    return out


# ---------------------------------------------------------------------------
# Windows / Npcap interface enumeration via wpcap.dll
# ---------------------------------------------------------------------------


class _PcapPktHdr(ctypes.Structure):
    _fields_ = [
        ("ts_sec", ctypes.c_long),
        ("ts_usec", ctypes.c_long),
        ("caplen", ctypes.c_uint32),
        ("len", ctypes.c_uint32),
    ]


class _PcapAddr(ctypes.Structure):
    pass


_PcapAddr._fields_ = [
    ("next", ctypes.POINTER(_PcapAddr)),
    ("addr", ctypes.c_void_p),
    ("netmask", ctypes.c_void_p),
    ("broadaddr", ctypes.c_void_p),
    ("dstaddr", ctypes.c_void_p),
]


class _PcapIf(ctypes.Structure):
    pass


_PcapIf._fields_ = [
    ("next", ctypes.POINTER(_PcapIf)),
    ("name", ctypes.c_char_p),
    ("description", ctypes.c_char_p),
    ("addresses", ctypes.POINTER(_PcapAddr)),
    ("flags", ctypes.c_uint32),
]


_wpcap_cache: List[Optional[ctypes.CDLL]] = [None]
_wpcap_tried = [False]


def _try_load_wpcap() -> Optional[ctypes.CDLL]:
    if _wpcap_cache[0] is not None:
        return _wpcap_cache[0]
    if _wpcap_tried[0]:
        return None
    _wpcap_tried[0] = True
    if not sys.platform.startswith("win"):
        return None
    # Prefer the Npcap directory which is installed in System32\Npcap.
    candidates = [
        os.path.join(os.environ.get("WINDIR", r"C:\Windows"),
                     "System32", "Npcap", "wpcap.dll"),
        "wpcap.dll",
    ]
    for cand in candidates:
        try:
            dll = ctypes.WinDLL(cand)  # type: ignore[attr-defined]
        except (OSError, AttributeError):
            continue
        _configure_wpcap(dll)
        _wpcap_cache[0] = dll
        return dll
    return None


def _configure_wpcap(dll) -> None:
    dll.pcap_findalldevs.argtypes = [
        ctypes.POINTER(ctypes.POINTER(_PcapIf)), ctypes.c_char_p]
    dll.pcap_findalldevs.restype = ctypes.c_int
    dll.pcap_freealldevs.argtypes = [ctypes.POINTER(_PcapIf)]
    dll.pcap_freealldevs.restype = None
    dll.pcap_open_live.argtypes = [
        ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int,
        ctypes.c_char_p]
    dll.pcap_open_live.restype = ctypes.c_void_p
    dll.pcap_close.argtypes = [ctypes.c_void_p]
    dll.pcap_close.restype = None
    dll.pcap_next_ex.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.POINTER(_PcapPktHdr)),
        ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte))]
    dll.pcap_next_ex.restype = ctypes.c_int
    dll.pcap_datalink.argtypes = [ctypes.c_void_p]
    dll.pcap_datalink.restype = ctypes.c_int
    dll.pcap_geterr.argtypes = [ctypes.c_void_p]
    dll.pcap_geterr.restype = ctypes.c_void_p
    # Optional newer API
    for name, argtypes, restype in (
        ("pcap_create", [ctypes.c_char_p, ctypes.c_char_p], ctypes.c_void_p),
        ("pcap_set_snaplen", [ctypes.c_void_p, ctypes.c_int], ctypes.c_int),
        ("pcap_set_promisc", [ctypes.c_void_p, ctypes.c_int], ctypes.c_int),
        ("pcap_set_timeout", [ctypes.c_void_p, ctypes.c_int], ctypes.c_int),
        ("pcap_set_immediate_mode",
            [ctypes.c_void_p, ctypes.c_int], ctypes.c_int),
        ("pcap_activate", [ctypes.c_void_p], ctypes.c_int),
    ):
        if hasattr(dll, name):
            f = getattr(dll, name)
            f.argtypes = argtypes
            f.restype = restype


def _list_npcap_interfaces() -> List[CaptureInterface]:
    dll = _try_load_wpcap()
    if dll is None:
        return []
    head = ctypes.POINTER(_PcapIf)()
    errbuf = ctypes.create_string_buffer(256)
    if dll.pcap_findalldevs(ctypes.byref(head), errbuf) != 0:
        return []
    out: List[CaptureInterface] = []
    try:
        cur = head
        while cur:
            ent = cur.contents
            name = (ent.name or b"").decode("utf-8", "replace")
            desc = (ent.description or ent.name or b"").decode("utf-8",
                                                               "replace")
            out.append(CaptureInterface(name=name, description=desc,
                                        addresses=[]))
            cur = ent.next
    finally:
        dll.pcap_freealldevs(head)
    return out
