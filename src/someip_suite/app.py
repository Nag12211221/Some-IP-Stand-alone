"""Tkinter front-end of the SOME/IP Diagnostics Suite.

The GUI is organised as a notebook with four tabs:

    Dashboard │ SD Timing │ DoIP Flashing │ Filter Engine

A bottom log console aggregates every backend module's messages and a
status bar shows global state. Everything is pure standard library so
PyInstaller can produce a single .exe.
"""

from __future__ import annotations

import csv
import json
import queue
import threading
import time
import tkinter as tk
from dataclasses import asdict
from tkinter import filedialog, messagebox, ttk
from typing import List, Optional

from . import __version__
from .modules import sd_analyzer, doip_monitor, filter_engine
from .widgets import LogConsole, Sparkline, StatusBar


# Dark colour palette (kept consistent across tabs)
BG = "#1E1E1E"
PANEL = "#252526"
FG = "#E0E0E0"
ACCENT = "#4FC3F7"
WARN = "#FFD54F"
DANGER = "#EF9A9A"
OK = "#A5D6A7"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _apply_dark_theme(root: tk.Tk) -> None:
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    root.configure(bg=BG)
    style.configure(".", background=BG, foreground=FG, fieldbackground=PANEL,
                    bordercolor=PANEL, lightcolor=PANEL, darkcolor=PANEL)
    style.configure("TFrame", background=BG)
    style.configure("Card.TFrame", background=PANEL, relief="flat")
    style.configure("TLabel", background=BG, foreground=FG, font=("Segoe UI", 10))
    style.configure("Title.TLabel", font=("Segoe UI Semibold", 14))
    style.configure("Metric.TLabel", font=("Segoe UI Semibold", 18),
                    foreground=ACCENT)
    style.configure("MetricCaption.TLabel", font=("Segoe UI", 9),
                    foreground="#9E9E9E")
    style.configure("Card.TLabel", background=PANEL, foreground=FG)
    style.configure("CardMetric.TLabel", background=PANEL, foreground=ACCENT,
                    font=("Segoe UI Semibold", 18))
    style.configure("CardCaption.TLabel", background=PANEL, foreground="#9E9E9E",
                    font=("Segoe UI", 9))
    style.configure("TButton", padding=6)
    style.configure("Accent.TButton", padding=6, foreground="#0D1117",
                    background=ACCENT)
    style.map("Accent.TButton",
              background=[("active", "#81D4FA"), ("disabled", "#37474F")])
    style.configure("TNotebook", background=BG, borderwidth=0)
    style.configure("TNotebook.Tab", padding=(14, 6), background=PANEL,
                    foreground=FG)
    style.map("TNotebook.Tab",
              background=[("selected", BG)], foreground=[("selected", ACCENT)])
    style.configure("Treeview", background=PANEL, fieldbackground=PANEL,
                    foreground=FG, rowheight=22, borderwidth=0)
    style.configure("Treeview.Heading", background=BG, foreground=FG,
                    font=("Segoe UI Semibold", 9))
    style.map("Treeview", background=[("selected", "#37474F")])
    style.configure("TEntry", fieldbackground=PANEL, foreground=FG,
                    insertcolor=FG)
    style.configure("TSpinbox", fieldbackground=PANEL, foreground=FG)
    style.configure("TCheckbutton", background=BG, foreground=FG)
    style.configure("Horizontal.TProgressbar", background=ACCENT,
                    troughcolor=PANEL)


def _metric_card(parent: tk.Widget, caption: str) -> tuple:
    f = ttk.Frame(parent, style="Card.TFrame", padding=(14, 10))
    val = ttk.Label(f, text="—", style="CardMetric.TLabel")
    cap = ttk.Label(f, text=caption, style="CardCaption.TLabel")
    val.pack(anchor="w")
    cap.pack(anchor="w")
    return f, val


# ===========================================================================
# Dashboard
# ===========================================================================


class DashboardTab(ttk.Frame):
    def __init__(self, master, app: "SomeIpSuiteApp") -> None:
        super().__init__(master, padding=16)
        self.app = app

        ttk.Label(self, text="SOME/IP Diagnostics Suite",
                  style="Title.TLabel").pack(anchor="w")
        ttk.Label(self,
                  text=("Standalone professional toolkit addressing SOME/IP "
                        "service-discovery timing, DoIP flash-session "
                        "stability and high-throughput packet filtering."),
                  foreground="#BDBDBD",
                  wraplength=800, justify="left").pack(anchor="w", pady=(2, 16))

        # KPI strip
        kpis = ttk.Frame(self)
        kpis.pack(fill="x")
        self._kpi_widgets = {}
        for i, (key, caption) in enumerate((
            ("sd_violations", "SD violations"),
            ("doip_blocks",   "DoIP blocks acked"),
            ("doip_rtt",      "DoIP avg RTT (ms)"),
            ("filter_pps",    "Filter throughput (pps)"),
        )):
            card, lbl = _metric_card(kpis, caption)
            card.grid(row=0, column=i, padx=(0, 12), sticky="ew")
            kpis.columnconfigure(i, weight=1)
            self._kpi_widgets[key] = lbl

        # How-to panel
        howto = ttk.LabelFrame(self, text=" Quick start ", padding=14)
        howto.pack(fill="both", expand=True, pady=(20, 0))
        howto.configure()
        tips = (
            "1. Open the SD Timing tab, click Run to simulate a multi-ECU "
            "boot and inspect timing violations.\n"
            "2. Open the DoIP Flashing tab, click Start Entity then Start "
            "Tester to drive a flash session; inject a TCP drop to verify "
            "resume logic.\n"
            "3. Open the Filter Engine tab, click Start to push synthetic "
            "SOME/IP traffic through the compiled rule set and watch "
            "throughput in real time.\n"
            "4. Use File ▸ Export Report to dump the latest session as "
            "JSON or CSV for hand-off."
        )
        ttk.Label(howto, text=tips, justify="left",
                  wraplength=900).pack(anchor="w")

    def update_kpis(self, *, sd_violations: Optional[int] = None,
                    doip_blocks: Optional[int] = None,
                    doip_rtt: Optional[float] = None,
                    filter_pps: Optional[float] = None) -> None:
        if sd_violations is not None:
            self._kpi_widgets["sd_violations"].configure(
                text=str(sd_violations),
                foreground=(DANGER if sd_violations else OK))
        if doip_blocks is not None:
            self._kpi_widgets["doip_blocks"].configure(text=str(doip_blocks))
        if doip_rtt is not None:
            self._kpi_widgets["doip_rtt"].configure(text=f"{doip_rtt:.2f}")
        if filter_pps is not None:
            self._kpi_widgets["filter_pps"].configure(text=f"{filter_pps:,.0f}")


# ===========================================================================
# SD timing tab
# ===========================================================================


class SdTimingTab(ttk.Frame):
    def __init__(self, master, app: "SomeIpSuiteApp") -> None:
        super().__init__(master, padding=12)
        self.app = app
        self._report: Optional[sd_analyzer.SimulationReport] = None
        self._sim: Optional[sd_analyzer.SdSimulator] = None
        self._build()

    # ------------------------------------------------------------------
    def _build(self) -> None:
        top = ttk.Frame(self)
        top.pack(fill="x")
        ttk.Label(top, text="SOME/IP-SD timing analyzer",
                  style="Title.TLabel").pack(side="left")
        ttk.Button(top, text="Load defaults",
                   command=self._load_defaults).pack(side="right", padx=4)
        ttk.Button(top, text="Add ECU", command=self._add_ecu_row
                   ).pack(side="right", padx=4)

        # ECU table (editable)
        cols = ("name", "service", "instance", "app_ready",
                "init_min", "init_max", "rep_base", "rep_max", "loss")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=8)
        for c, w, lbl in (
            ("name", 110, "ECU"),
            ("service", 80, "Service"),
            ("instance", 70, "Inst"),
            ("app_ready", 110, "App ready (ms)"),
            ("init_min", 100, "InitDly min"),
            ("init_max", 100, "InitDly max"),
            ("rep_base", 100, "Rep base ms"),
            ("rep_max", 80, "Rep #"),
            ("loss", 80, "Loss %"),
        ):
            self.tree.heading(c, text=lbl)
            self.tree.column(c, width=w, anchor="center")
        self.tree.pack(fill="x", pady=10)
        self.tree.bind("<Double-1>", self._edit_cell)
        self.tree.bind("<Delete>", lambda _e: self._delete_selected())

        # Controls
        ctrl = ttk.Frame(self)
        ctrl.pack(fill="x", pady=(0, 10))
        ttk.Label(ctrl, text="Duration (ms):").pack(side="left")
        self._duration = tk.StringVar(value="10000")
        ttk.Entry(ctrl, textvariable=self._duration, width=8).pack(side="left", padx=(2, 12))
        ttk.Label(ctrl, text="Client listen (ms):").pack(side="left")
        self._listen = tk.StringVar(value="5000")
        ttk.Entry(ctrl, textvariable=self._listen, width=8).pack(side="left", padx=(2, 12))
        ttk.Label(ctrl, text="Seed:").pack(side="left")
        self._seed = tk.StringVar(value="42")
        ttk.Entry(ctrl, textvariable=self._seed, width=6).pack(side="left", padx=(2, 12))

        self._run_btn = ttk.Button(ctrl, text="▶  Run simulation",
                                   style="Accent.TButton", command=self._run)
        self._run_btn.pack(side="right")
        ttk.Button(ctrl, text="Export…", command=self._export
                   ).pack(side="right", padx=6)

        self._progress = ttk.Progressbar(self, mode="determinate",
                                         maximum=1000)
        self._progress.pack(fill="x", pady=(0, 8))

        # Summary cards
        cards = ttk.Frame(self)
        cards.pack(fill="x")
        self._sd_cards = {}
        for i, (key, cap) in enumerate((
            ("violations", "Violations"),
            ("discovered", "Services discovered"),
            ("mean_lat",  "Mean discovery (ms)"),
            ("p95_lat",   "P95 discovery (ms)"),
            ("max_lat",   "Max discovery (ms)"),
        )):
            card, lbl = _metric_card(cards, cap)
            card.grid(row=0, column=i, padx=(0, 10), sticky="ew")
            cards.columnconfigure(i, weight=1)
            self._sd_cards[key] = lbl

        # Event log
        ttk.Label(self, text="Events", foreground="#BDBDBD"
                  ).pack(anchor="w", pady=(14, 4))
        ev_cols = ("t", "ecu", "kind", "detail")
        self.events = ttk.Treeview(self, columns=ev_cols, show="headings",
                                   height=10)
        for c, w, lbl in (("t", 80, "t (ms)"), ("ecu", 110, "ECU"),
                          ("kind", 110, "Kind"), ("detail", 500, "Detail")):
            self.events.heading(c, text=lbl)
            self.events.column(c, width=w, anchor="w")
        self.events.tag_configure("violation", foreground=DANGER)
        self.events.tag_configure("offer-sent", foreground=OK)
        self.events.tag_configure("offer-lost", foreground=WARN)
        self.events.pack(fill="both", expand=True)

        self._load_defaults()

    # ------------------------------------------------------------------
    def _load_defaults(self) -> None:
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        for e in sd_analyzer.default_scenario():
            self.tree.insert("", "end", values=(
                e.name, f"0x{e.service_id:04X}", e.instance_id,
                int(e.app_ready_after_ms), int(e.initial_delay_min_ms),
                int(e.initial_delay_max_ms), int(e.repetitions_base_delay_ms),
                e.repetitions_max, int(e.loss_probability * 100),
            ))

    def _add_ecu_row(self) -> None:
        n = len(self.tree.get_children()) + 1
        self.tree.insert("", "end", values=(f"ECU{n}", "0x9000", 1, 200, 50, 500,
                                            200, 3, 0))

    def _delete_selected(self) -> None:
        for iid in self.tree.selection():
            self.tree.delete(iid)

    def _edit_cell(self, event) -> None:
        region = self.tree.identify("region", event.x, event.y)
        if region != "cell":
            return
        iid = self.tree.identify_row(event.y)
        col = self.tree.identify_column(event.x)
        col_idx = int(col.replace("#", "")) - 1
        x, y, w, h = self.tree.bbox(iid, col)
        old = self.tree.set(iid, self.tree["columns"][col_idx])
        entry = ttk.Entry(self.tree)
        entry.insert(0, old)
        entry.select_range(0, "end")
        entry.focus()
        entry.place(x=x, y=y, width=w, height=h)

        def _commit(_e=None):
            self.tree.set(iid, self.tree["columns"][col_idx], entry.get())
            entry.destroy()

        entry.bind("<Return>", _commit)
        entry.bind("<FocusOut>", _commit)
        entry.bind("<Escape>", lambda _e: entry.destroy())

    # ------------------------------------------------------------------
    def _collect_ecus(self) -> List[sd_analyzer.EcuConfig]:
        out: List[sd_analyzer.EcuConfig] = []
        for iid in self.tree.get_children():
            v = self.tree.item(iid)["values"]
            try:
                out.append(sd_analyzer.EcuConfig(
                    name=str(v[0]),
                    service_id=int(str(v[1]), 0),
                    instance_id=int(v[2]),
                    app_ready_after_ms=float(v[3]),
                    initial_delay_min_ms=float(v[4]),
                    initial_delay_max_ms=float(v[5]),
                    repetitions_base_delay_ms=float(v[6]),
                    repetitions_max=int(v[7]),
                    loss_probability=float(v[8]) / 100.0,
                ))
            except (ValueError, IndexError) as exc:
                raise ValueError(f"row {v}: {exc}")
        return out

    def _run(self) -> None:
        try:
            ecus = self._collect_ecus()
            duration = float(self._duration.get())
            listen = float(self._listen.get())
            seed = int(self._seed.get())
        except ValueError as exc:
            messagebox.showerror("Invalid input", str(exc), parent=self)
            return
        if not ecus:
            messagebox.showwarning("No ECUs", "Add at least one ECU.", parent=self)
            return

        self._run_btn.configure(state="disabled")
        self._progress["value"] = 0
        self.events.delete(*self.events.get_children())
        self.app.log(f"[SD] starting simulation: {len(ecus)} ECUs, "
                     f"{duration:.0f} ms, seed={seed}", "INFO")

        def _on_progress(p: float) -> None:
            self.after(0, lambda: self._progress.configure(value=int(p * 1000)))

        sim = sd_analyzer.SdSimulator(ecus, duration_ms=duration,
                                      client_listen_ms=listen, seed=seed,
                                      progress_cb=_on_progress)
        self._sim = sim

        def _worker() -> None:
            try:
                report = sim.run()
            except Exception as exc:                # noqa: BLE001
                self.after(0, lambda: messagebox.showerror(
                    "Simulation error", str(exc), parent=self))
                return
            self.after(0, lambda: self._on_finished(report))

        threading.Thread(target=_worker, daemon=True,
                         name="SdSim").start()

    def _on_finished(self, report: sd_analyzer.SimulationReport) -> None:
        self._report = report
        self._run_btn.configure(state="normal")
        summary = report.summary()
        self._sd_cards["violations"].configure(
            text=str(summary["violations"]),
            foreground=DANGER if summary["violations"] else OK)
        self._sd_cards["discovered"].configure(text=str(summary["discovered"]))
        self._sd_cards["mean_lat"].configure(
            text=f"{summary['mean_discovery_ms'] or 0:.1f}")
        self._sd_cards["p95_lat"].configure(
            text=f"{summary['p95_discovery_ms'] or 0:.1f}")
        self._sd_cards["max_lat"].configure(
            text=f"{summary['max_discovery_ms'] or 0:.1f}")

        # Populate event log (cap to first 1000 for UI snappiness)
        for ev in report.events[:1000]:
            tag = ev.kind if ev.kind in ("violation", "offer-sent",
                                         "offer-lost") else ""
            self.events.insert("", "end",
                               values=(f"{ev.t_ms:.1f}", ev.ecu, ev.kind,
                                       ev.detail), tags=(tag,))
        self.app.log(f"[SD] done — {summary}", "OK")
        self.app.dashboard.update_kpis(sd_violations=summary["violations"])

    def _export(self) -> None:
        if self._report is None:
            messagebox.showinfo("Nothing to export", "Run the simulation first.",
                                parent=self)
            return
        path = filedialog.asksaveasfilename(
            parent=self, defaultextension=".json",
            filetypes=[("JSON report", "*.json"), ("CSV events", "*.csv")])
        if not path:
            return
        if path.lower().endswith(".csv"):
            with open(path, "w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(["t_ms", "ecu", "kind", "detail"])
                for ev in self._report.events:
                    w.writerow([ev.t_ms, ev.ecu, ev.kind, ev.detail])
        else:
            data = {
                "summary": self._report.summary(),
                "discovery_latency_ms": self._report.discovery_latency_ms,
                "events": [asdict(e) for e in self._report.events],
            }
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
        self.app.log(f"[SD] report saved to {path}", "OK")


# ===========================================================================
# DoIP flashing tab
# ===========================================================================


class DoipFlashTab(ttk.Frame):
    def __init__(self, master, app: "SomeIpSuiteApp") -> None:
        super().__init__(master, padding=12)
        self.app = app
        self._metrics = doip_monitor.FlashMetrics()
        self._server: Optional[doip_monitor.DoipEntityServer] = None
        self._tester: Optional[doip_monitor.DoipFlashTester] = None
        self._build()
        self.after(500, self._poll_metrics)

    def _build(self) -> None:
        top = ttk.Frame(self)
        top.pack(fill="x")
        ttk.Label(top, text="DoIP flash-session monitor",
                  style="Title.TLabel").pack(side="left")

        # Config grid
        cfg = ttk.LabelFrame(self, text=" Configuration ", padding=10)
        cfg.pack(fill="x", pady=10)

        self._fields = {}
        defaults = [
            ("host", "127.0.0.1", "Host"),
            ("port", "13400", "Port"),
            ("tester_sa", "0x0E00", "Tester SA"),
            ("entity_sa", "0x1234", "Entity SA"),
            ("block_size", "4096", "Block size (B)"),
            ("block_count", "256", "Block count"),
            ("processing_time_ms", "5", "Proc time (ms)"),
            ("alive_check_interval_ms", "1000", "AliveCheck (ms)"),
            ("drop_after_blocks", "64", "Drop @ block"),
            ("stall_after_blocks", "0", "Stall @ block"),
        ]
        for i, (key, default, label) in enumerate(defaults):
            r, c = divmod(i, 5)
            ttk.Label(cfg, text=label).grid(row=r * 2, column=c, sticky="w",
                                            padx=4, pady=(0, 2))
            var = tk.StringVar(value=default)
            ttk.Entry(cfg, textvariable=var, width=12).grid(
                row=r * 2 + 1, column=c, padx=4, pady=(0, 6), sticky="ew")
            cfg.columnconfigure(c, weight=1)
            self._fields[key] = var

        self._resume_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(cfg, text="Resume on TCP drop",
                        variable=self._resume_var).grid(row=99, column=0,
                                                        columnspan=5,
                                                        sticky="w", pady=(6, 0))

        # Buttons
        btns = ttk.Frame(self)
        btns.pack(fill="x", pady=(0, 8))
        self._start_entity_btn = ttk.Button(btns, text="Start entity",
                                            command=self._start_entity)
        self._start_entity_btn.pack(side="left", padx=4)
        self._stop_entity_btn = ttk.Button(btns, text="Stop entity",
                                           command=self._stop_entity,
                                           state="disabled")
        self._stop_entity_btn.pack(side="left", padx=4)
        ttk.Separator(btns, orient="vertical").pack(side="left", fill="y",
                                                    padx=10)
        self._start_tester_btn = ttk.Button(btns, text="▶  Start tester",
                                            style="Accent.TButton",
                                            command=self._start_tester)
        self._start_tester_btn.pack(side="left", padx=4)
        self._stop_tester_btn = ttk.Button(btns, text="Stop tester",
                                           command=self._stop_tester,
                                           state="disabled")
        self._stop_tester_btn.pack(side="left", padx=4)

        # Metric strip
        m = ttk.Frame(self)
        m.pack(fill="x")
        self._cards = {}
        for i, (key, cap) in enumerate((
            ("blocks", "Blocks acked"),
            ("bytes",  "Bytes sent"),
            ("rtt",    "Avg RTT (ms)"),
            ("alive",  "AliveCheck OK"),
            ("recon",  "Reconnects"),
            ("errors", "Errors"),
        )):
            card, lbl = _metric_card(m, cap)
            card.grid(row=0, column=i, padx=(0, 10), sticky="ew")
            m.columnconfigure(i, weight=1)
            self._cards[key] = lbl

        # Sparkline strip
        sk = ttk.Frame(self)
        sk.pack(fill="x", pady=(14, 0))
        ttk.Label(sk, text="RTT trend (ms)", foreground="#BDBDBD"
                  ).grid(row=0, column=0, sticky="w")
        self._rtt_spark = Sparkline(sk, width=600, height=80, fg=ACCENT)
        self._rtt_spark.grid(row=1, column=0, sticky="ew", pady=(2, 0))
        sk.columnconfigure(0, weight=1)

    # ------------------------------------------------------------------
    def _make_cfg(self) -> doip_monitor.FlashConfig:
        f = self._fields
        return doip_monitor.FlashConfig(
            host=f["host"].get(),
            port=int(f["port"].get()),
            tester_sa=int(f["tester_sa"].get(), 0),
            entity_sa=int(f["entity_sa"].get(), 0),
            block_size=int(f["block_size"].get()),
            block_count=int(f["block_count"].get()),
            processing_time_ms=float(f["processing_time_ms"].get()),
            alive_check_interval_ms=float(f["alive_check_interval_ms"].get()),
            drop_after_blocks=int(f["drop_after_blocks"].get()),
            stall_after_blocks=int(f["stall_after_blocks"].get()),
            resume_on_drop=self._resume_var.get(),
        )

    def _start_entity(self) -> None:
        try:
            cfg = self._make_cfg()
        except ValueError as exc:
            messagebox.showerror("Invalid input", str(exc), parent=self)
            return
        self._server = doip_monitor.DoipEntityServer(
            cfg, log=lambda m: self.app.log(m, "INFO"))
        self._server.start()
        self._start_entity_btn.configure(state="disabled")
        self._stop_entity_btn.configure(state="normal")

    def _stop_entity(self) -> None:
        if self._server is not None:
            self._server.stop()
            self._server = None
        self._start_entity_btn.configure(state="normal")
        self._stop_entity_btn.configure(state="disabled")

    def _start_tester(self) -> None:
        try:
            cfg = self._make_cfg()
        except ValueError as exc:
            messagebox.showerror("Invalid input", str(exc), parent=self)
            return
        self._metrics = doip_monitor.FlashMetrics()
        self._tester = doip_monitor.DoipFlashTester(
            cfg, self._metrics, log=lambda m: self.app.log(m, "INFO"))
        self._tester.start()
        self._start_tester_btn.configure(state="disabled")
        self._stop_tester_btn.configure(state="normal")
        self._rtt_spark.clear()

    def _stop_tester(self) -> None:
        if self._tester is not None:
            self._tester.stop()
            self._tester = None
        self._start_tester_btn.configure(state="normal")
        self._stop_tester_btn.configure(state="disabled")

    def _poll_metrics(self) -> None:
        m = self._metrics
        self._cards["blocks"].configure(text=f"{m.blocks_acked:,}")
        self._cards["bytes"].configure(text=f"{m.bytes_sent:,}")
        avg_rtt = (sum(m.rtts_ms[-64:]) / max(1, len(m.rtts_ms[-64:]))) if m.rtts_ms else 0.0
        self._cards["rtt"].configure(text=f"{avg_rtt:.2f}")
        self._cards["alive"].configure(
            text=f"{m.alive_checks_answered}/{m.alive_checks_sent}")
        self._cards["recon"].configure(
            text=str(m.reconnects),
            foreground=(WARN if m.reconnects else FG))
        self._cards["errors"].configure(
            text=str(m.errors),
            foreground=(DANGER if m.errors else FG))
        if m.rtts_ms:
            self._rtt_spark.push(m.rtts_ms[-1])

        if self._tester is not None and m.finished:
            self._stop_tester()
            self.app.log("[tester] session finished", "OK")

        self.app.dashboard.update_kpis(doip_blocks=m.blocks_acked,
                                       doip_rtt=avg_rtt)
        self.after(250, self._poll_metrics)


# ===========================================================================
# Filter engine tab
# ===========================================================================


class FilterEngineTab(ttk.Frame):
    def __init__(self, master, app: "SomeIpSuiteApp") -> None:
        super().__init__(master, padding=12)
        self.app = app
        self._metrics = filter_engine.FilterMetrics()
        self._worker: Optional[filter_engine.FilterWorker] = None
        self._source: Optional[filter_engine.SyntheticSource] = None
        self._build()
        self.after(500, self._poll_metrics)

    def _build(self) -> None:
        ttk.Label(self, text="Real-time SOME/IP filter engine",
                  style="Title.TLabel").pack(anchor="w")

        # Rule table
        rules_frame = ttk.LabelFrame(self, text=" Filter rules ", padding=8)
        rules_frame.pack(fill="x", pady=10)

        cols = ("name", "sid", "mid", "cid", "mt", "action")
        self.rules = ttk.Treeview(rules_frame, columns=cols, show="headings",
                                  height=6)
        for c, w, lbl in (
            ("name", 180, "Name"),
            ("sid", 110, "Service (or *)"),
            ("mid", 110, "Method (or *)"),
            ("cid", 110, "Client (or *)"),
            ("mt", 110, "MsgType (or *)"),
            ("action", 100, "Action"),
        ):
            self.rules.heading(c, text=lbl)
            self.rules.column(c, width=w, anchor="center")
        self.rules.pack(fill="x")
        self.rules.bind("<Double-1>", self._edit_rule)

        btns = ttk.Frame(rules_frame)
        btns.pack(fill="x", pady=(6, 0))
        ttk.Button(btns, text="Add rule", command=self._add_rule
                   ).pack(side="left", padx=4)
        ttk.Button(btns, text="Delete selected", command=self._del_rule
                   ).pack(side="left", padx=4)
        ttk.Button(btns, text="Load defaults", command=self._load_default_rules
                   ).pack(side="left", padx=4)

        # Traffic config
        traf = ttk.LabelFrame(self, text=" Synthetic traffic ", padding=10)
        traf.pack(fill="x")
        ttk.Label(traf, text="Target pps:").grid(row=0, column=0, sticky="w")
        self._pps = tk.StringVar(value="200000")
        ttk.Entry(traf, textvariable=self._pps, width=10
                  ).grid(row=0, column=1, padx=6)
        ttk.Label(traf, text="Duration (s):").grid(row=0, column=2, sticky="w")
        self._dur = tk.StringVar(value="10")
        ttk.Entry(traf, textvariable=self._dur, width=6
                  ).grid(row=0, column=3, padx=6)
        ttk.Label(traf, text="Service set:").grid(row=0, column=4, sticky="w")
        self._sids = tk.StringVar(value="0x1001,0x2001,0x3001,0x4001")
        ttk.Entry(traf, textvariable=self._sids, width=30
                  ).grid(row=0, column=5, padx=6, sticky="ew")
        traf.columnconfigure(5, weight=1)

        self._start_btn = ttk.Button(traf, text="▶  Start",
                                     style="Accent.TButton",
                                     command=self._start)
        self._start_btn.grid(row=0, column=6, padx=6)
        self._stop_btn = ttk.Button(traf, text="Stop", command=self._stop,
                                    state="disabled")
        self._stop_btn.grid(row=0, column=7, padx=6)

        # Metric cards
        m = ttk.Frame(self)
        m.pack(fill="x", pady=(14, 0))
        self._cards = {}
        for i, (key, cap) in enumerate((
            ("pps", "Throughput (pps)"),
            ("mbps", "Throughput (Mbps)"),
            ("accepted", "Accepted"),
            ("dropped", "Dropped"),
            ("counted", "Counted"),
            ("latency", "Avg latency (ns)"),
        )):
            card, lbl = _metric_card(m, cap)
            card.grid(row=0, column=i, padx=(0, 10), sticky="ew")
            m.columnconfigure(i, weight=1)
            self._cards[key] = lbl

        # Sparkline
        sk = ttk.Frame(self)
        sk.pack(fill="x", pady=(14, 0))
        ttk.Label(sk, text="Throughput (pps) trend", foreground="#BDBDBD"
                  ).grid(row=0, column=0, sticky="w")
        self._pps_spark = Sparkline(sk, width=600, height=80, fg=OK)
        self._pps_spark.grid(row=1, column=0, sticky="ew")
        sk.columnconfigure(0, weight=1)

        # Rule hits
        ttk.Label(self, text="Rule hits", foreground="#BDBDBD"
                  ).pack(anchor="w", pady=(14, 4))
        self.hits = ttk.Treeview(self, columns=("rule", "hits"),
                                 show="headings", height=6)
        self.hits.heading("rule", text="Rule")
        self.hits.heading("hits", text="Hits")
        self.hits.column("rule", width=320, anchor="w")
        self.hits.column("hits", width=120, anchor="e")
        self.hits.pack(fill="both", expand=True)

        self._load_default_rules()

    # ------------------------------------------------------------------
    def _load_default_rules(self) -> None:
        for iid in self.rules.get_children():
            self.rules.delete(iid)
        defaults = [
            ("Gateway diag",   "0x1001", "*", "*", "*", "accept"),
            ("Body events",    "0x2001", "*", "*", "0x02", "count"),
            ("ADAS requests",  "0x4001", "*", "*", "0x00", "accept"),
            ("Block infotain", "0x5001", "*", "*", "*", "drop"),
            ("<default>",      "*",      "*", "*", "*", "drop"),
        ]
        for v in defaults:
            self.rules.insert("", "end", values=v)

    def _add_rule(self) -> None:
        self.rules.insert("", "end", values=("new-rule", "*", "*", "*", "*",
                                             "accept"))

    def _del_rule(self) -> None:
        for iid in self.rules.selection():
            self.rules.delete(iid)

    def _edit_rule(self, event) -> None:
        region = self.rules.identify("region", event.x, event.y)
        if region != "cell":
            return
        iid = self.rules.identify_row(event.y)
        col = self.rules.identify_column(event.x)
        idx = int(col.replace("#", "")) - 1
        x, y, w, h = self.rules.bbox(iid, col)
        old = self.rules.set(iid, self.rules["columns"][idx])
        entry = ttk.Entry(self.rules)
        entry.insert(0, old)
        entry.select_range(0, "end")
        entry.focus()
        entry.place(x=x, y=y, width=w, height=h)

        def _commit(_e=None):
            self.rules.set(iid, self.rules["columns"][idx], entry.get())
            entry.destroy()

        entry.bind("<Return>", _commit)
        entry.bind("<FocusOut>", _commit)
        entry.bind("<Escape>", lambda _e: entry.destroy())

    def _collect_rules(self) -> List[filter_engine.FilterRule]:
        def _v(s: str) -> int:
            s = s.strip()
            if s == "*" or s == "":
                return filter_engine.ANY
            return int(s, 0)
        out = []
        for iid in self.rules.get_children():
            v = self.rules.item(iid)["values"]
            out.append(filter_engine.FilterRule(
                name=str(v[0]),
                service_id=_v(str(v[1])),
                method_id=_v(str(v[2])),
                client_id=_v(str(v[3])),
                message_type=_v(str(v[4])),
                action=str(v[5]),
            ))
        return out

    # ------------------------------------------------------------------
    def _start(self) -> None:
        try:
            rules = self._collect_rules()
            pps = int(self._pps.get())
            dur = float(self._dur.get())
            sids = [int(s.strip(), 0) for s in self._sids.get().split(",")
                    if s.strip()]
        except ValueError as exc:
            messagebox.showerror("Invalid input", str(exc), parent=self)
            return
        if not sids:
            sids = [0x1001]
        compiled = filter_engine.compile_rules(rules)
        self._metrics = filter_engine.FilterMetrics()
        self._source = filter_engine.SyntheticSource(
            target_pps=pps, duration_s=dur, services=sids,
            methods=[0x0001, 0x0002, 0x0003, 0x0004])
        self._worker = filter_engine.FilterWorker(
            self._source, compiled, self._metrics)
        self._worker.start()
        self._start_btn.configure(state="disabled")
        self._stop_btn.configure(state="normal")
        self._pps_spark.clear()
        self.app.log(f"[filter] started: target {pps:,} pps for {dur:.0f}s, "
                     f"{len(rules)} rules", "INFO")

    def _stop(self) -> None:
        if self._source is not None:
            self._source.stop()
        if self._worker is not None:
            self._worker.stop()
        self._source = None
        self._worker = None
        self._start_btn.configure(state="normal")
        self._stop_btn.configure(state="disabled")

    def _poll_metrics(self) -> None:
        m = self._metrics
        self._cards["pps"].configure(text=f"{m.pps:,.0f}")
        self._cards["mbps"].configure(text=f"{m.mbps:.2f}")
        self._cards["accepted"].configure(text=f"{m.packets_accepted:,}")
        self._cards["dropped"].configure(text=f"{m.packets_dropped:,}")
        self._cards["counted"].configure(text=f"{m.packets_counted:,}")
        self._cards["latency"].configure(text=f"{m.avg_latency_ns:,.0f}")
        self._pps_spark.push(m.pps)

        # Update hits table
        existing = {self.hits.item(iid)["values"][0]: iid
                    for iid in self.hits.get_children()}
        for name, hits in sorted(m.rule_hits.items(),
                                 key=lambda x: -x[1])[:50]:
            if name in existing:
                self.hits.item(existing[name], values=(name, f"{hits:,}"))
            else:
                self.hits.insert("", "end", values=(name, f"{hits:,}"))

        if self._worker is not None and not self._worker.is_alive():
            self._stop()
            self.app.log(f"[filter] finished — {m.packets_in:,} packets, "
                         f"avg {m.pps:,.0f} pps", "OK")

        self.app.dashboard.update_kpis(filter_pps=m.pps)
        self.after(500, self._poll_metrics)


# ===========================================================================
# Main application
# ===========================================================================


class SomeIpSuiteApp:
    def __init__(self) -> None:
        self.root = tk.Tk()
        self.root.title(f"SOME/IP Diagnostics Suite  v{__version__}")
        self.root.geometry("1280x820")
        self.root.minsize(1024, 700)
        _apply_dark_theme(self.root)
        self._build_menu()
        self._build_layout()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ------------------------------------------------------------------
    def _build_menu(self) -> None:
        bar = tk.Menu(self.root, tearoff=False, bg=PANEL, fg=FG,
                      activebackground=ACCENT, activeforeground="#0D1117")
        file_menu = tk.Menu(bar, tearoff=False, bg=PANEL, fg=FG)
        file_menu.add_command(label="Clear log", command=lambda: self.console.clear())
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self._on_close)
        bar.add_cascade(label="File", menu=file_menu)

        help_menu = tk.Menu(bar, tearoff=False, bg=PANEL, fg=FG)
        help_menu.add_command(label="About…", command=self._show_about)
        bar.add_cascade(label="Help", menu=help_menu)
        self.root.configure(menu=bar)

    def _build_layout(self) -> None:
        main = ttk.Frame(self.root)
        main.pack(fill="both", expand=True)

        nb = ttk.Notebook(main)
        nb.pack(fill="both", expand=True, padx=8, pady=(8, 0))

        self.dashboard = DashboardTab(nb, self)
        self.sd_tab = SdTimingTab(nb, self)
        self.doip_tab = DoipFlashTab(nb, self)
        self.filter_tab = FilterEngineTab(nb, self)
        nb.add(self.dashboard, text="  Dashboard  ")
        nb.add(self.sd_tab,    text="  SD Timing  ")
        nb.add(self.doip_tab,  text="  DoIP Flashing  ")
        nb.add(self.filter_tab,text="  Filter Engine  ")

        # Log
        log_frame = ttk.LabelFrame(main, text=" Log ", padding=(8, 4))
        log_frame.pack(fill="x", padx=8, pady=8)
        self.console = LogConsole(log_frame, height=8)
        self.console.pack(fill="both", expand=True)

        # Status
        self.status = StatusBar(main)
        self.status.pack(fill="x")
        self.status.set("Ready")
        self.status.set_right(f"v{__version__}")
        self.log("Suite started — choose a tab to begin.", "OK")

    def _show_about(self) -> None:
        messagebox.showinfo(
            "About",
            f"SOME/IP Diagnostics Suite v{__version__}\n\n"
            "A standalone professional tool addressing:\n"
            "  • SOME/IP-SD timing during ECU boot\n"
            "  • DoIP flash-session stability\n"
            "  • Real-time SOME/IP filter performance\n\n"
            "Built with the Python standard library only — packaged as a "
            "single executable with PyInstaller.",
            parent=self.root)

    # ------------------------------------------------------------------
    def log(self, message: str, level: str = "INFO") -> None:
        ts = time.strftime("%H:%M:%S")
        self.console.log(f"{ts}  {message}", level)

    def _on_close(self) -> None:
        for closer in (
            getattr(self.doip_tab, "_tester", None),
            getattr(self.doip_tab, "_server", None),
            getattr(self.filter_tab, "_worker", None),
            getattr(self.filter_tab, "_source", None),
        ):
            if closer is None:
                continue
            try:
                closer.stop()
            except (OSError, RuntimeError) as exc:
                # Non-fatal during shutdown — log and move on.
                self.log(f"shutdown: {closer.__class__.__name__}: {exc}",
                         "WARN")
        self.root.destroy()

    def run(self) -> None:
        self.root.mainloop()
