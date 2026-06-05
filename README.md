# SOME/IP Diagnostics Suite

A **standalone, professional desktop tool** that operationalises three solutions for
common in-vehicle Ethernet pain points:

| # | Problem | Module in the tool |
|---|---------|--------------------|
| 1 | SOME/IP service-discovery timing issues during ECU boot | **SD Timing** tab |
| 2 | DoIP (Diagnostic-over-IP) connection instability during flashing | **DoIP Flashing** tab |
| 3 | Real-time SOME/IP filter performance degrades above 100 k pps | **Filter Engine** tab |

The application is delivered as a **single Windows `.exe`** — no Python install, no
DLLs to copy, no pip dependencies for the end user. Just download and run.

---

## Why it works (engineering rationale)

* **SD Timing tab** runs a deterministic multi-ECU SOME/IP-SD state machine simulator
  (NotReady → InitialWait → Repetition → Main, per AUTOSAR PRS SD R21-11). It gates
  `OfferService` on application readiness, randomises `INITIAL_DELAY` per ECU,
  applies exponential `REPETITIONS_BASE_DELAY` back-off, and reports any timing
  violation that would have caused a boot-time race condition.

* **DoIP Flashing tab** spins up a fully compliant **DoIP entity (server)** and a
  **tester (client)** on the same machine. The transport layer enables
  `TCP_NODELAY` + `SO_KEEPALIVE`, the entity answers `AliveCheck` requests from the
  protocol layer (not the flash driver), and the tester implements
  **routing-activation + resume-after-drop** logic per ISO 13400-2:2019. You can
  inject a TCP drop or a 5-second stall and watch the session recover live.

* **Filter Engine tab** runs a **compiled** filter pipeline — rules are flattened into
  an O(1) hash-lookup table so per-packet cost stays sub-µs regardless of rule count.
  A built-in synthetic generator pushes SOME/IP traffic at any target pps so you can
  reproduce the >100 kpps regression and verify the fix.

A full write-up of the rationale lives in the answer to the original problem
statement; this repo is the runnable counterpart.

---

## Download & run

1. Grab `SomeIPDiagnosticsSuite.exe` from the latest workflow run / release.
2. Double-click. That's it.

No installer, no admin rights required.

---

## Build from source

The runtime is pure standard library (Tkinter). The **only** build-time dependency
is PyInstaller.

```bash
python -m pip install pyinstaller==6.10.0
pyinstaller build/someip_suite.spec --clean --noconfirm
# → dist/SomeIPDiagnosticsSuite.exe   (or the platform equivalent)
```

A GitHub Actions workflow (`.github/workflows/build-windows.yml`) does this
automatically on every push to `main` and uploads the `.exe` as a build artifact.
Tags matching `v*` additionally attach the binary to a GitHub Release.

### Run from source (no packaging)

```bash
python -m someip_suite              # from inside src/
# or
PYTHONPATH=src python -m someip_suite
```

### Run the tests

```bash
python -m unittest discover -s tests -v
```

---

## Project layout

```
src/someip_suite/
    __main__.py            # entry point
    app.py                 # Tkinter GUI (dashboard + 3 tool tabs + log + status)
    protocols/
        someip.py          # SOME/IP + SOME/IP-SD codec (AUTOSAR PRS R21-11)
        doip.py            # DoIP codec (ISO 13400-2:2019)
    modules/
        sd_analyzer.py     # multi-ECU SD timing simulator
        doip_monitor.py    # DoIP entity + tester + live metrics
        filter_engine.py   # compiled filter pipeline + synthetic traffic
    widgets/
        __init__.py        # Sparkline, LogConsole, StatusBar
build/
    someip_suite.spec      # PyInstaller one-file spec
.github/workflows/
    build-windows.yml      # Windows-native build of the .exe
tests/
    test_engines.py        # 10 unit tests covering codecs + engines
```

---

## License

MIT (recommended) — add a `LICENSE` file before shipping.
