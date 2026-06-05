"""Reusable Tkinter widgets used across the suite."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import List, Optional


class Sparkline(tk.Canvas):
    """A tiny rolling-window line chart drawn on a Canvas (no external deps)."""

    def __init__(self, master, *, width: int = 200, height: int = 50,
                 fg: str = "#4FC3F7", bg: str = "#1E1E1E",
                 max_points: int = 240) -> None:
        super().__init__(master, width=width, height=height, bg=bg,
                         highlightthickness=0)
        self._cw = width
        self._ch = height
        self._fg = fg
        self._max = max_points
        self._data: List[float] = []

    def push(self, value: float) -> None:
        self._data.append(float(value))
        if len(self._data) > self._max:
            del self._data[: len(self._data) - self._max]
        self._redraw()

    def clear(self) -> None:
        self._data.clear()
        self.delete("all")

    def _redraw(self) -> None:
        self.delete("all")
        if len(self._data) < 2:
            return
        d = self._data
        lo, hi = min(d), max(d)
        if hi - lo < 1e-9:
            hi = lo + 1.0
        step = self._cw / max(1, len(d) - 1)
        pts = []
        for i, v in enumerate(d):
            x = i * step
            y = self._ch - (v - lo) / (hi - lo) * (self._ch - 4) - 2
            pts.extend((x, y))
        self.create_line(*pts, fill=self._fg, width=1.5, smooth=False)
        self.create_text(self._cw - 4, 2, anchor="ne",
                         text=f"{d[-1]:.1f}", fill=self._fg,
                         font=("Segoe UI", 8))


class LogConsole(ttk.Frame):
    """Read-only colour-coded log view with autoscroll."""

    LEVEL_COLORS = {
        "INFO":    "#E0E0E0",
        "OK":      "#A5D6A7",
        "WARN":    "#FFD54F",
        "ERROR":   "#EF9A9A",
        "DEBUG":   "#90CAF9",
    }

    def __init__(self, master, *, height: int = 12) -> None:
        super().__init__(master)
        self._text = tk.Text(self, height=height, bg="#121212", fg="#E0E0E0",
                             insertbackground="#E0E0E0",
                             font=("Consolas", 9), wrap="none",
                             relief="flat", borderwidth=0)
        self._text.configure(state="disabled")
        ysb = ttk.Scrollbar(self, orient="vertical", command=self._text.yview)
        self._text.configure(yscrollcommand=ysb.set)
        self._text.grid(row=0, column=0, sticky="nsew")
        ysb.grid(row=0, column=1, sticky="ns")
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        for lvl, color in self.LEVEL_COLORS.items():
            self._text.tag_configure(lvl, foreground=color)

    def log(self, message: str, level: str = "INFO") -> None:
        self._text.configure(state="normal")
        self._text.insert("end", f"{message}\n", level)
        self._text.see("end")
        # cap at 5000 lines
        line_count = int(self._text.index("end-1c").split(".")[0])
        if line_count > 5000:
            self._text.delete("1.0", f"{line_count - 5000}.0")
        self._text.configure(state="disabled")

    def clear(self) -> None:
        self._text.configure(state="normal")
        self._text.delete("1.0", "end")
        self._text.configure(state="disabled")


class StatusBar(ttk.Frame):
    def __init__(self, master) -> None:
        super().__init__(master, padding=(8, 4))
        self._label = ttk.Label(self, text="Ready", anchor="w")
        self._right = ttk.Label(self, text="", anchor="e")
        self._label.pack(side="left", fill="x", expand=True)
        self._right.pack(side="right")

    def set(self, text: str) -> None:
        self._label.configure(text=text)

    def set_right(self, text: str) -> None:
        self._right.configure(text=text)
