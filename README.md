# SOME/IP Diagnostics Suite — v2

A **standalone, professional desktop tool** for in-vehicle Ethernet diagnostics.
v2 turns the previous simulator-only build into a **real diagnostics suite** that
works on actual captures:

| Tab | What it does |
|-----|--------------|
| **Capture** | Open `.pcap` / `.pcapng` or capture live from a NIC (Npcap on Windows, AF_PACKET on Linux). Packet list with SOME/IP, SOME/IP-SD, DoIP decode and a detail pane. |
| **SD Analyzer** | Offline SOME/IP-SD timing analyser — recovers per-ECU INITIAL_DELAY, REPETITIONS_BASE_DELAY and CYCLIC_OFFER_DELAY from the trace, flags AUTOSAR PRS SD R21-11 timing violations with the offending frame numbers. |
| **DoIP Analyzer** | Offline DoIP session reconstructor — RoutingActivation outcomes, AliveCheck pairing, UDS exchange list with RTTs, NRCs, retransmits and reconnects. |
| **Filter Engine** | Compiled O(1) hash-lookup pipeline; can be fed a capture, a live NIC or the legacy synthetic generator. |
| **SD Demo / DoIP Demo** | The original deterministic simulators, kept behind a *Demo mode* for teaching / regression. |

The application is still delivered as a **single Windows `.exe`** — no Python
install, no DLLs to copy. New in v2: bundled icon, VS_VERSIONINFO, splash
screen, ~30% smaller binary, plus a **CLI mode** so it can be run from CI:

```text
SomeIPDiagnosticsSuite.exe                                       # GUI
SomeIPDiagnosticsSuite.exe info    capture.pcap                  # show summary
SomeIPDiagnosticsSuite.exe analyze capture.pcap --report out.html
                                          [--json out.json] [--strict]
```

`--strict` exits with code 2 if any SD violation is found — wire it up to your
build pipeline.

Keyboard: **Ctrl+O** open capture, **Ctrl+F** focus filter, **F5** re-analyse.

---

## Why it works (engineering rationale)

* **SD Analyzer** consumes parsed `SdMessage` entries from the trace,
  normalises t=0 to the first SD packet and groups OfferService /
  FindService / SubscribeEventgroup per ECU. It then recovers
  `INITIAL_DELAY`, `REPETITIONS_BASE_DELAY` and `CYCLIC_OFFER_DELAY`
  from the actual inter-packet gaps and checks them against the AUTOSAR
  PRS SD R21-11 expectations (initial delay window, exponential back-off
  during repetition phase, cyclic-offer drift).

* **DoIP Analyzer** reassembles TCP per half-stream, locks onto port
  13400 to determine the client/entity direction, and walks the
  RoutingActivation → AliveCheck → DiagnosticMessage / Ack /
  PositiveResponse / NegativeResponse state machine of ISO 13400-2:2019.
  It surfaces NRCs, retransmits and any reconnect inside a logical
  session.

* **Filter Engine** runs the same compiled O(1) hash-lookup pipeline
  as v1. It now ingests from: synthetic generator (regression), real
  `.pcap`/`.pcapng` files via the same decoder used by the GUI, or live
  NIC capture for in-the-loop testing.

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
