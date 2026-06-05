"""GUI tabs that work on real captures (pcap files + live capture).

Three tabs are defined here so :mod:`someip_suite.app` stays
manageable:

* :class:`CaptureTab` — open a .pcap/.pcapng, or start a live capture on
  a NIC. Shows a packet list with time, src→dst, protocol and summary.
  Selecting a row reveals the SOME/IP / DoIP / SD breakdown.
* :class:`SdOfflineTab` — runs the offline SD analyser over the
  currently-loaded capture and shows the per-ECU timing breakdown and
  violations with frame numbers.
* :class:`DoipOfflineTab` — runs the offline DoIP session reconstructor
  and shows each session, its routing-activation outcome, alive-check
  pairing and UDS exchanges.

All three pull their data from a shared :class:`CaptureStore` instance
held by the application.
"""

from __future__ import annotations

import os
import threading
import time
import tkinter as tk
from dataclasses import dataclass, field
from tkinter import filedialog, messagebox, ttk
from typing import Callable, List, Optional

from .modules import doip_offline, live_capture, sd_offline
from .protocols import pcap as pcap_mod
from .protocols.decoder import CaptureDecoder, DecodedMessage
from .protocols.l2 import decode_frame


# ---------------------------------------------------------------------------
# Shared capture store
# ---------------------------------------------------------------------------


@dataclass
class CaptureStore:
    """Holds the currently-loaded capture and exposes change listeners."""

    source_label: str = "(none)"
    frames: List[pcap_mod.PcapFrame] = field(default_factory=list)
    messages: List[DecodedMessage] = field(default_factory=list)
    _listeners: List[Callable[["CaptureStore"], None]] = field(default_factory=list)

    def listen(self, cb: Callable[["CaptureStore"], None]) -> None:
        self._listeners.append(cb)

    def _fire(self) -> None:
        for cb in list(self._listeners):
            try:
                cb(self)
            except Exception:  # noqa: BLE001 — UI callbacks must never propagate
                pass

    def clear(self) -> None:
        self.source_label = "(none)"
        self.frames = []
        self.messages = []
        self._fire()

    def set(self, label: str, frames: List[pcap_mod.PcapFrame],
            messages: List[DecodedMessage]) -> None:
        self.source_label = label
        self.frames = frames
        self.messages = messages
        self._fire()

    def append(self, new_frames: List[pcap_mod.PcapFrame],
               new_messages: List[DecodedMessage]) -> None:
        self.frames.extend(new_frames)
        self.messages.extend(new_messages)
        self._fire()


# ---------------------------------------------------------------------------
# Capture tab — pcap viewer + live capture controls
# ---------------------------------------------------------------------------


class CaptureTab(ttk.Frame):
    UPDATE_INTERVAL_MS = 250
    MAX_TABLE_ROWS = 5000   # cap rendering to keep the UI snappy

    def __init__(self, master, app) -> None:
        super().__init__(master, padding=10)
        self.app = app
        self._live: Optional[live_capture.LiveCapture] = None
        self._live_decoder: Optional[CaptureDecoder] = None
        self._recording_path: Optional[str] = None
        self._build()
        self.app.store.listen(self._on_store_changed)

    # -- layout --------------------------------------------------------
    def _build(self) -> None:
        # Top: source selector
        top = ttk.Frame(self)
        top.pack(fill="x")
        ttk.Label(top, text="Capture", style="Title.TLabel"
                  ).grid(row=0, column=0, sticky="w")
        self._summary = ttk.Label(top, text="No capture loaded.",
                                  foreground="#9E9E9E")
        self._summary.grid(row=0, column=1, sticky="w", padx=(12, 0))
        top.columnconfigure(1, weight=1)

        # Action row
        act = ttk.Frame(self)
        act.pack(fill="x", pady=(8, 6))
        ttk.Button(act, text="Open .pcap / .pcapng…  (Ctrl+O)",
                   style="Accent.TButton",
                   command=self._open_pcap).pack(side="left")
        ttk.Button(act, text="Clear", command=self._clear).pack(
            side="left", padx=(8, 16))

        ttk.Label(act, text="Live capture:").pack(side="left")
        self._iface_var = tk.StringVar(value="")
        self._iface_combo = ttk.Combobox(act, textvariable=self._iface_var,
                                         width=40, state="readonly")
        self._iface_combo.pack(side="left", padx=4)
        self._refresh_btn = ttk.Button(act, text="↻",
                                       command=self._refresh_ifaces, width=3)
        self._refresh_btn.pack(side="left")
        self._start_btn = ttk.Button(act, text="▶  Start",
                                     command=self._start_live)
        self._start_btn.pack(side="left", padx=(6, 0))
        self._stop_btn = ttk.Button(act, text="Stop",
                                    command=self._stop_live, state="disabled")
        self._stop_btn.pack(side="left", padx=4)
        self._record_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(act, text="Record to pcap",
                        variable=self._record_var).pack(side="left",
                                                        padx=(12, 0))
        self._refresh_ifaces()

        # Filter row
        filt = ttk.Frame(self)
        filt.pack(fill="x", pady=(4, 8))
        ttk.Label(filt, text="Filter (Ctrl+F):").pack(side="left")
        self._filter_var = tk.StringVar(value="")
        ent = ttk.Entry(filt, textvariable=self._filter_var, width=60)
        ent.pack(side="left", padx=6, fill="x", expand=True)
        ent.bind("<Return>", lambda _e: self._refresh_table())
        self._filter_entry = ent
        ttk.Button(filt, text="Apply",
                   command=self._refresh_table).pack(side="left", padx=4)
        ttk.Label(filt, text="(matches src/dst/protocol/summary)",
                  foreground="#9E9E9E").pack(side="left", padx=(8, 0))

        # Packet table
        cols = ("idx", "time", "src", "dst", "proto", "summary")
        self.tree = ttk.Treeview(self, columns=cols, show="headings",
                                 height=18)
        for c, w, lbl, anchor in (
            ("idx", 70, "Frame", "e"),
            ("time", 110, "Time (s)", "e"),
            ("src", 200, "Source", "w"),
            ("dst", 200, "Destination", "w"),
            ("proto", 90, "Protocol", "w"),
            ("summary", 600, "Info", "w"),
        ):
            self.tree.heading(c, text=lbl)
            self.tree.column(c, width=w, anchor=anchor)
        self.tree.pack(fill="both", expand=True, pady=4)
        self.tree.tag_configure("doip", foreground="#90CAF9")
        self.tree.tag_configure("someip", foreground="#A5D6A7")
        self.tree.tag_configure("someip-sd", foreground="#FFD54F")
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        # Detail pane
        det = ttk.LabelFrame(self, text=" Detail ", padding=8)
        det.pack(fill="x", pady=(8, 0))
        self._detail = tk.Text(det, height=8, bg="#121212", fg="#E0E0E0",
                               font=("Consolas", 9), wrap="word",
                               relief="flat", borderwidth=0)
        self._detail.configure(state="disabled")
        self._detail.pack(fill="both", expand=True)

    # -- pcap file -----------------------------------------------------
    def _open_pcap(self) -> None:
        path = filedialog.askopenfilename(
            parent=self,
            filetypes=[("Capture files", "*.pcap *.pcapng *.cap"),
                       ("All files", "*.*")],
            title="Open capture")
        if not path:
            return
        self.load_pcap(path)

    def load_pcap(self, path: str) -> None:
        """Public hook so the File menu / CLI can pre-load a capture."""
        try:
            self.app.status.set(f"Reading {os.path.basename(path)}…")
            t0 = time.perf_counter()
            frames = list(pcap_mod.read_pcap(path))
            dec = CaptureDecoder()
            messages: List[DecodedMessage] = []
            for f in frames:
                pkt = decode_frame(f)
                if pkt is not None:
                    messages.extend(dec.feed(pkt))
            dt = (time.perf_counter() - t0) * 1000.0
        except Exception as exc:    # noqa: BLE001
            messagebox.showerror("Open failed", str(exc), parent=self)
            return
        self.app.store.set(os.path.basename(path), frames, messages)
        self.app.log(
            f"[capture] loaded {len(frames):,} frames "
            f"({len(messages):,} SOME/IP/DoIP messages) "
            f"from {path} in {dt:.0f} ms", "OK")
        self.app.status.set(
            f"{os.path.basename(path)} — {len(frames):,} frames, "
            f"{len(messages):,} decoded")

    def _clear(self) -> None:
        self.app.store.clear()
        self.app.status.set("Ready")

    # -- live capture --------------------------------------------------
    def _refresh_ifaces(self) -> None:
        backend = live_capture.available_backend()
        if backend is None:
            self._iface_combo["values"] = ("(no backend — install Npcap)",)
            self._iface_var.set("(no backend — install Npcap)")
            self._iface_combo.configure(state="disabled")
            self._start_btn.configure(state="disabled")
            return
        ifaces = live_capture.list_interfaces()
        items = [f"{i.name}   —   {i.description}" for i in ifaces] or \
                ["(no interfaces found)"]
        self._iface_combo["values"] = items
        if items:
            self._iface_var.set(items[0])
        self._iface_combo.configure(state="readonly")
        self._start_btn.configure(state="normal")

    def _selected_iface(self) -> Optional[str]:
        s = self._iface_var.get()
        if not s or s.startswith("("):
            return None
        return s.split(" ", 1)[0]

    def _start_live(self) -> None:
        iface = self._selected_iface()
        if iface is None:
            messagebox.showwarning("No interface",
                                   "Pick a network interface first.",
                                   parent=self)
            return
        try:
            cap = live_capture.LiveCapture(iface)
        except RuntimeError as exc:
            messagebox.showerror("Live capture unavailable", str(exc),
                                 parent=self)
            return
        rec_path = None
        if self._record_var.get():
            rec_path = filedialog.asksaveasfilename(
                parent=self, defaultextension=".pcap",
                filetypes=[("PCAP", "*.pcap")],
                title="Record capture to…")
            if rec_path:
                cap.begin_recording(rec_path)
        cap.start()
        self._live = cap
        self._live_decoder = CaptureDecoder()
        self._recording_path = rec_path
        # Fresh capture replaces any loaded pcap
        self.app.store.set(f"live: {iface}", [], [])
        self.app.log(f"[capture] live start on {iface}"
                     + (f" → recording to {rec_path}" if rec_path else ""),
                     "OK")
        self._start_btn.configure(state="disabled")
        self._stop_btn.configure(state="normal")
        self.after(self.UPDATE_INTERVAL_MS, self._pump_live)

    def _stop_live(self) -> None:
        cap = self._live
        if cap is not None:
            cap.stop()
            if cap.error:
                self.app.log(f"[capture] {cap.error}", "ERROR")
            saved = cap.end_recording() if self._recording_path else None
            if saved:
                self.app.log(f"[capture] recording saved to {saved}", "OK")
        self._live = None
        self._live_decoder = None
        self._recording_path = None
        self._start_btn.configure(state="normal")
        self._stop_btn.configure(state="disabled")

    def _pump_live(self) -> None:
        cap = self._live
        if cap is None:
            return
        new_frames = cap.drain()
        if new_frames:
            dec = self._live_decoder
            assert dec is not None
            new_msgs: List[DecodedMessage] = []
            for f in new_frames:
                pkt = decode_frame(f)
                if pkt is not None:
                    new_msgs.extend(dec.feed(pkt))
            self.app.store.append(new_frames, new_msgs)
        if cap.error:
            self.app.log(f"[capture] {cap.error}", "ERROR")
            self._stop_live()
            return
        self.after(self.UPDATE_INTERVAL_MS, self._pump_live)

    # -- table rendering ----------------------------------------------
    def _on_store_changed(self, _store: CaptureStore) -> None:
        self._summary.configure(text=(
            f"{self.app.store.source_label}: "
            f"{len(self.app.store.frames):,} frames, "
            f"{len(self.app.store.messages):,} SOME/IP / DoIP messages"))
        self._refresh_table()

    def _refresh_table(self) -> None:
        self.tree.delete(*self.tree.get_children())
        flt = self._filter_var.get().strip().lower()
        msgs = self.app.store.messages
        # Show the most recent MAX_TABLE_ROWS for usability.
        if len(msgs) > self.MAX_TABLE_ROWS:
            shown = msgs[-self.MAX_TABLE_ROWS:]
        else:
            shown = msgs
        t0 = shown[0].ts if shown else 0.0
        for m in shown:
            if flt:
                hay = f"{m.src} {m.dst} {m.protocol} {m.summary}".lower()
                if flt not in hay:
                    continue
            self.tree.insert("", "end",
                             values=(m.frame_index, f"{m.ts - t0:.6f}",
                                     m.src, m.dst, m.protocol, m.summary),
                             tags=(m.protocol,))

    def _on_select(self, _event=None) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        try:
            frame_idx = int(self.tree.item(sel[0])["values"][0])
        except (ValueError, IndexError):
            return
        msg = next((m for m in self.app.store.messages
                    if m.frame_index == frame_idx), None)
        if msg is None:
            return
        lines = [
            f"Frame  : {msg.frame_index}",
            f"Time   : {msg.ts:.6f} s",
            f"Src→Dst: {msg.src}  →  {msg.dst}",
            f"L4     : {msg.transport}",
            f"Proto  : {msg.protocol}",
            f"Summary: {msg.summary}",
        ]
        if msg.someip_header is not None:
            h = msg.someip_header
            lines += [
                "",
                "── SOME/IP header ──",
                f"service_id   = 0x{h.service_id:04X}",
                f"method_id    = 0x{h.method_id:04X}",
                f"length       = {h.length}",
                f"client_id    = 0x{h.client_id:04X}",
                f"session_id   = 0x{h.session_id:04X}",
                f"protocol_ver = 0x{h.protocol_version:02X}",
                f"interface_v  = 0x{h.interface_version:02X}",
                f"message_type = 0x{h.message_type:02X}",
                f"return_code  = 0x{h.return_code:02X}",
            ]
        if msg.sd_message is not None:
            lines.append("")
            lines.append("── SD entries ──")
            for e in msg.sd_message.entries:
                lines.append(
                    f"  type=0x{e.type:02X} svc=0x{e.service_id:04X} "
                    f"inst={e.instance_id} maj={e.major_version} "
                    f"min={e.minor_version} ttl={e.ttl}")
        if msg.doip_header is not None:
            lines += [
                "",
                "── DoIP header ──",
                f"protocol_version = 0x{msg.doip_header.protocol_version:02X}",
                f"payload_type     = 0x{msg.doip_header.payload_type:04X}",
                f"payload_length   = {msg.doip_header.payload_length}",
                f"payload (hex)    = {msg.doip_payload.hex()}",
            ]
        lines.append("")
        lines.append(f"raw (hex) = {msg.raw.hex()}")

        self._detail.configure(state="normal")
        self._detail.delete("1.0", "end")
        self._detail.insert("end", "\n".join(lines))
        self._detail.configure(state="disabled")


# ---------------------------------------------------------------------------
# SD offline tab
# ---------------------------------------------------------------------------


class SdOfflineTab(ttk.Frame):
    def __init__(self, master, app) -> None:
        super().__init__(master, padding=10)
        self.app = app
        self._report: Optional[sd_offline.SdReport] = None
        self._build()
        self.app.store.listen(lambda _s: self._summary.configure(
            text=f"Capture loaded: {self.app.store.source_label}"))

    def _build(self) -> None:
        top = ttk.Frame(self)
        top.pack(fill="x")
        ttk.Label(top, text="SOME/IP-SD timing analysis (offline)",
                  style="Title.TLabel").pack(side="left")
        ttk.Button(top, text="▶  Analyse current capture",
                   style="Accent.TButton",
                   command=self._analyse).pack(side="right")
        self._summary = ttk.Label(self, text="No capture loaded.",
                                  foreground="#9E9E9E")
        self._summary.pack(anchor="w", pady=(2, 8))

        # KPI strip
        kpis = ttk.Frame(self)
        kpis.pack(fill="x")
        self._cards = {}
        from .app import _metric_card    # local import to avoid cycle
        for i, (key, cap) in enumerate((
            ("ecus", "ECUs"),
            ("services", "Services"),
            ("offers", "OfferService count"),
            ("finds", "FindService count"),
            ("violations", "Violations"),
        )):
            card, lbl = _metric_card(kpis, cap)
            card.grid(row=0, column=i, padx=(0, 10), sticky="ew")
            kpis.columnconfigure(i, weight=1)
            self._cards[key] = lbl

        # Timing table
        ttk.Label(self, text="Per-ECU × service timing",
                  foreground="#BDBDBD").pack(anchor="w", pady=(14, 4))
        cols = ("ecu", "svc", "inst", "first", "rep_base", "cyclic",
                "offers", "first_frame")
        self.timings = ttk.Treeview(self, columns=cols, show="headings",
                                    height=10)
        for c, w, lbl, anchor in (
            ("ecu", 130, "ECU (src IP)", "w"),
            ("svc", 100, "Service", "e"),
            ("inst", 80, "Inst", "e"),
            ("first", 110, "First offer (ms)", "e"),
            ("rep_base", 130, "Rep base (ms)", "e"),
            ("cyclic", 130, "Cyclic (ms)", "e"),
            ("offers", 80, "Offers", "e"),
            ("first_frame", 110, "First frame", "e"),
        ):
            self.timings.heading(c, text=lbl)
            self.timings.column(c, width=w, anchor=anchor)
        self.timings.pack(fill="both", expand=True)

        # Violations
        ttk.Label(self, text="Violations",
                  foreground="#BDBDBD").pack(anchor="w", pady=(14, 4))
        vcols = ("kind", "ecu", "svc", "frame", "detail")
        self.vio = ttk.Treeview(self, columns=vcols, show="headings",
                                height=6)
        for c, w, lbl, anchor in (
            ("kind", 220, "Kind", "w"),
            ("ecu", 130, "ECU", "w"),
            ("svc", 130, "Service", "w"),
            ("frame", 80, "Frame", "e"),
            ("detail", 700, "Detail", "w"),
        ):
            self.vio.heading(c, text=lbl)
            self.vio.column(c, width=w, anchor=anchor)
        self.vio.tag_configure("violation", foreground="#EF9A9A")
        self.vio.pack(fill="both", expand=True)

    def _analyse(self) -> None:
        msgs = self.app.store.messages
        if not msgs:
            messagebox.showinfo("No capture", "Open a .pcap first (Ctrl+O).",
                                parent=self)
            return
        rep = sd_offline.analyse_sd(msgs)
        self._report = rep
        s = rep.summary()
        self._cards["ecus"].configure(text=str(s["ecus"]))
        self._cards["services"].configure(text=str(s["services"]))
        self._cards["offers"].configure(text=str(s["offers"]))
        self._cards["finds"].configure(text=str(s["finds"]))
        self._cards["violations"].configure(
            text=str(s["violations"]),
            foreground=("#EF9A9A" if s["violations"] else "#A5D6A7"))

        self.timings.delete(*self.timings.get_children())
        for t in rep.timings:
            first_ts = (f"{t.initial_delay_ms:.1f}"
                        if t.initial_delay_ms is not None else "—")
            rb = t.estimated_repetitions_base_ms()
            cy = t.estimated_cyclic_offer_ms()
            self.timings.insert("", "end", values=(
                t.src_ip,
                f"0x{t.service_id:04X}",
                t.instance_id,
                first_ts,
                f"{rb:.1f}" if rb is not None else "—",
                f"{cy:.1f}" if cy is not None else "—",
                len(t.offers),
                t.offers[0].frame_index if t.offers else "—",
            ))
        self.vio.delete(*self.vio.get_children())
        for v in rep.violations:
            self.vio.insert("", "end", values=(
                v.kind, v.src_ip, f"0x{v.service_id:04X}.{v.instance_id}",
                v.frame_index, v.detail,
            ), tags=("violation",))
        self.app.log(f"[sd-offline] analysed {len(msgs):,} messages: {s}",
                     "OK")
        self.app.dashboard.update_kpis(sd_violations=s["violations"])


# ---------------------------------------------------------------------------
# DoIP offline tab
# ---------------------------------------------------------------------------


class DoipOfflineTab(ttk.Frame):
    def __init__(self, master, app) -> None:
        super().__init__(master, padding=10)
        self.app = app
        self._report: Optional[doip_offline.DoipSessionReport] = None
        self._build()
        self.app.store.listen(lambda _s: self._summary.configure(
            text=f"Capture loaded: {self.app.store.source_label}"))

    def _build(self) -> None:
        top = ttk.Frame(self)
        top.pack(fill="x")
        ttk.Label(top, text="DoIP session analysis (offline)",
                  style="Title.TLabel").pack(side="left")
        ttk.Button(top, text="▶  Analyse current capture",
                   style="Accent.TButton",
                   command=self._analyse).pack(side="right")
        self._summary = ttk.Label(self, text="No capture loaded.",
                                  foreground="#9E9E9E")
        self._summary.pack(anchor="w", pady=(2, 8))

        # KPIs
        from .app import _metric_card
        kpis = ttk.Frame(self)
        kpis.pack(fill="x")
        self._cards = {}
        for i, (key, cap) in enumerate((
            ("sessions", "Sessions"),
            ("reconnects", "Reconnects"),
            ("uds", "UDS exchanges"),
            ("nrcs", "Negative responses"),
            ("retx", "Retransmits"),
            ("avg_rtt", "Avg RTT (ms)"),
        )):
            card, lbl = _metric_card(kpis, cap)
            card.grid(row=0, column=i, padx=(0, 10), sticky="ew")
            kpis.columnconfigure(i, weight=1)
            self._cards[key] = lbl

        # Sessions table
        ttk.Label(self, text="Sessions",
                  foreground="#BDBDBD").pack(anchor="w", pady=(14, 4))
        cols = ("client", "entity", "started", "ra_rc", "ra_lat",
                "alive", "uds")
        self.sessions = ttk.Treeview(self, columns=cols, show="headings",
                                     height=6)
        for c, w, lbl, anchor in (
            ("client", 180, "Client", "w"),
            ("entity", 180, "Entity", "w"),
            ("started", 110, "Start ts", "e"),
            ("ra_rc", 130, "RA code", "w"),
            ("ra_lat", 110, "RA latency (ms)", "e"),
            ("alive", 110, "Alive a/s", "e"),
            ("uds", 100, "UDS msgs", "e"),
        ):
            self.sessions.heading(c, text=lbl)
            self.sessions.column(c, width=w, anchor=anchor)
        self.sessions.pack(fill="x")
        self.sessions.bind("<<TreeviewSelect>>", self._on_session_select)

        # UDS exchanges
        ttk.Label(self, text="UDS exchanges (selected session)",
                  foreground="#BDBDBD").pack(anchor="w", pady=(14, 4))
        ucols = ("req_frame", "ts", "sa", "ta", "sid", "rtt",
                 "ack", "nrc", "retx", "request", "response")
        self.uds = ttk.Treeview(self, columns=ucols, show="headings",
                                height=10)
        for c, w, lbl, anchor in (
            ("req_frame", 70, "Frame", "e"),
            ("ts", 100, "Time (s)", "e"),
            ("sa", 80, "SA", "e"),
            ("ta", 80, "TA", "e"),
            ("sid", 70, "SID", "e"),
            ("rtt", 80, "RTT (ms)", "e"),
            ("ack", 60, "Ack", "e"),
            ("nrc", 60, "NRC", "e"),
            ("retx", 60, "ReTx", "e"),
            ("request", 200, "Request (hex)", "w"),
            ("response", 200, "Response (hex)", "w"),
        ):
            self.uds.heading(c, text=lbl)
            self.uds.column(c, width=w, anchor=anchor)
        self.uds.tag_configure("nrc", foreground="#EF9A9A")
        self.uds.tag_configure("retx", foreground="#FFD54F")
        self.uds.pack(fill="both", expand=True)

    def _analyse(self) -> None:
        msgs = self.app.store.messages
        if not msgs:
            messagebox.showinfo("No capture", "Open a .pcap first (Ctrl+O).",
                                parent=self)
            return
        rep = doip_offline.reconstruct_doip(msgs)
        self._report = rep
        s = rep.summary()
        self._cards["sessions"].configure(text=str(s["sessions"]))
        self._cards["reconnects"].configure(text=str(s["reconnects"]))
        self._cards["uds"].configure(text=str(s["uds_exchanges"]))
        self._cards["nrcs"].configure(
            text=str(s["negative_responses"]),
            foreground=("#EF9A9A" if s["negative_responses"] else "#A5D6A7"))
        self._cards["retx"].configure(
            text=str(s["retransmits"]),
            foreground=("#FFD54F" if s["retransmits"] else "#A5D6A7"))
        self._cards["avg_rtt"].configure(
            text=f"{s['avg_rtt_ms']:.2f}" if s["avg_rtt_ms"] is not None
            else "—")

        self.sessions.delete(*self.sessions.get_children())
        for i, sess in enumerate(rep.sessions):
            try:
                rc = doip_offline.doip.RoutingActivationResponseCode(
                    sess.routing_activation_rc).name \
                    if sess.routing_activation_rc is not None else "—"
            except ValueError:
                rc = f"0x{sess.routing_activation_rc:02X}"
            lat = (f"{sess.routing_activation_latency_ms:.2f}"
                   if sess.routing_activation_latency_ms is not None else "—")
            self.sessions.insert("", "end", iid=str(i), values=(
                sess.client, sess.entity, f"{sess.started_ts:.6f}",
                rc, lat,
                f"{sess.alive_checks_answered}/{sess.alive_checks_sent}",
                len(sess.exchanges),
            ))
        # Auto-select the first session so the UDS table has something to show
        if rep.sessions:
            self.sessions.selection_set("0")
            self._on_session_select()
        else:
            self.uds.delete(*self.uds.get_children())
        self.app.log(f"[doip-offline] reconstructed {s}", "OK")
        self.app.dashboard.update_kpis(doip_blocks=s["uds_exchanges"],
                                       doip_rtt=s["avg_rtt_ms"] or 0.0)

    def _on_session_select(self, _event=None) -> None:
        sel = self.sessions.selection()
        if not sel or self._report is None:
            return
        try:
            idx = int(sel[0])
            sess = self._report.sessions[idx]
        except (ValueError, IndexError):
            return
        self.uds.delete(*self.uds.get_children())
        for e in sess.exchanges:
            tag = "nrc" if e.nrc is not None else (
                "retx" if e.retransmits else "")
            self.uds.insert("", "end", values=(
                e.request_frame, f"{e.request_ts:.6f}",
                f"0x{e.sa:04X}", f"0x{e.ta:04X}",
                f"0x{e.sid:02X}",
                f"{e.rtt_ms:.2f}" if e.rtt_ms is not None else "—",
                "✓" if e.ack_frame is not None else "—",
                f"0x{e.nrc:02X}" if e.nrc is not None else "—",
                e.retransmits if e.retransmits else "—",
                e.request_hex[:64],
                e.response_hex[:64] if e.response_hex else "—",
            ), tags=(tag,))
