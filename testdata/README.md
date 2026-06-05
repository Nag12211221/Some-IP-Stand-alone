# Test data

This folder ships a **ready-to-use, realistically large** capture so you
can verify that the SOME/IP Diagnostics Suite is working end-to-end —
no Wireshark, no real vehicle, no ECU rack required.

| File | Size | Purpose |
|------|------|---------|
| `large_realistic.pcap` | ~ 1.1 MB / ≈ 13 000 frames | The capture itself (libpcap 2.4 format) |
| `generate_test_pcap.py` | — | Script that produced the capture; re-run to make it larger / smaller |
| `sample_report.html` | ~ 930 KB | HTML report produced by `analyze --report` on the capture above |
| `sample_summary.json` | < 1 KB | Machine-readable summary produced by `analyze --json` on the capture above |

## What is inside the capture

The trace contains **real-world automotive Ethernet scenarios** that
the suite is built to diagnose. Every byte is crafted by the same
codecs that ship in `src/someip_suite/protocols/`, so the file
round-trips cleanly through the analyser.

### A. SOME/IP-SD (Service Discovery)

* **6 well-behaved ECUs** (`10.0.0.10` … `10.0.0.15`) each advertising
  a distinct service (`0x1001`, `0x1002`, `0x1010`, `0x2001`, `0x2010`,
  `0x3000`).
  * INITIAL_DELAY: 50 – 200 ms (per ECU)
  * REPETITIONS_BASE_DELAY: 200 ms, **doubled** for 4 repetitions
    (AUTOSAR PRS R21-11 §4.2.1)
  * CYCLIC_OFFER_DELAY: 2 000 ms, sustained for ~ 10 min
* **1 misbehaving ECU** (`10.0.0.99` / service `0x9999`) that flat-lines
  its repetition phase at 200 ms (no doubling).
  The SD Analyzer is expected to flag this as
  `missing-exponential-backoff`. ✅ confirmed in `sample_summary.json`.
* **FindService** probes from a head-unit (`10.0.0.50`) for two services.
* **SubscribeEventgroup** messages from two consumer ECUs
  (`10.0.0.60`, `10.0.0.61`).

### B. DoIP (ISO 13400-2:2019)

Five TCP sessions between the diagnostic tester (`10.0.0.200`) and
various ECUs on port 13400:

| Session | Description | What it exercises |
|---------|-------------|-------------------|
| 1 | TesterPresent loop — 500 × `0x3E 0x00` | High-rate keep-alives, RTT statistics |
| 2 | ReadDataByIdentifier loop — 3 000 requests, ~ 8 % NRC `0x31` (requestOutOfRange) | Bulk UDS flow, NRC counter |
| 3 | RoutineControl with 3 × NRC `0x78` (response-pending) then positive | Response-pending recognition |
| 4 | RoutingActivation rejected (`UNKNOWN_SA`), tester reconnects with valid SA, then reads VIN | Reconnect handling |
| 5 | ReadDataByIdentifier with no ack on first try, application-level retransmit | Retransmit detection |

### C. Background noise

300 unrelated UDP/TCP frames so the protocol filter is exercised.

## Expected analyser output

Running the bundled CLI:

```bash
PYTHONPATH=src python -m someip_suite analyze testdata/large_realistic.pcap \
    --report testdata/sample_report.html \
    --json   testdata/sample_summary.json
```

prints (numbers are deterministic — the generator uses fixed RNG seeds):

```
analysed 12,575 messages from 12,894 frames in ~200 ms
  SD:   ECUs=10  services=7  offers=1835  finds=2  violations=1
  DoIP: sessions=6  reconnects=0  uds=3505  NRCs=254  retx=2  avg_rtt_ms=3.328
```

If your run prints those same numbers, the suite is working correctly.

The pre-generated `sample_report.html` shows what a healthy report
looks like — open it in any browser. The SD-violations section near
the top lists `10.0.0.99 / 0x9999 / missing-exponential-backoff`, and
the DoIP session table shows the five tester sessions with their RTTs,
NRC counts and routing-activation outcomes.

## Regenerating / inflating the capture

The generator is fully deterministic and parameterised by environment
variables:

```bash
# defaults
python testdata/generate_test_pcap.py

# go really big (≈ 80 000 frames, ≈ 8 MB on disk)
CYCLE_COUNT=2000 DID_LOOP=10000 TESTER_PRESENT_COUNT=2000 \
    python testdata/generate_test_pcap.py
```

You can also point the script at any output path:

```bash
python testdata/generate_test_pcap.py /tmp/huge.pcap
```

## Using the capture in the GUI

1. Launch the suite (`python -m someip_suite` from `src/` or run the
   packaged `.exe`).
2. **Capture** tab → **Open .pcap…** → pick `testdata/large_realistic.pcap`.
3. Switch to **SD Analyzer** → press **Run** → confirm one violation
   on ECU `10.0.0.99` for service `0x9999`.
4. Switch to **DoIP Analyzer** → press **Run** → confirm 6 sessions
   and ~ 254 NRCs.
5. Use **File → Save HTML report…** to write a fresh HTML report.

See [`docs/USER_GUIDE.md`](../docs/USER_GUIDE.md) for the full
step-by-step walk-through with screenshots.
