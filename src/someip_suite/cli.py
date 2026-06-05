"""Command-line interface for the SOME/IP Diagnostics Suite.

Invoked when the first argv is one of the known sub-commands:

    SomeIPDiagnosticsSuite.exe analyze capture.pcap --report report.html
    SomeIPDiagnosticsSuite.exe info  capture.pcap

If no sub-command is given, :mod:`__main__` falls back to the GUI.

The CLI shares **all** decoding/analysis code with the GUI — there is
no duplicate logic. The only thing unique here is the small HTML report
template at the bottom of this file.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import sys
import time
from typing import Iterable, List, Sequence

from . import __version__
from .modules import doip_offline, sd_offline
from .protocols import pcap as pcap_mod
from .protocols.decoder import CaptureDecoder, DecodedMessage
from .protocols.l2 import decode_frame


_SUBCOMMANDS = {"analyze", "analyse", "info"}


def is_cli_invocation(argv: Sequence[str]) -> bool:
    """Return ``True`` if ``argv[1:]`` begins with a CLI sub-command."""
    return len(argv) > 1 and argv[1].lower() in _SUBCOMMANDS


def _decode_pcap(path: str) -> tuple:
    frames = list(pcap_mod.read_pcap(path))
    dec = CaptureDecoder()
    messages: List[DecodedMessage] = []
    for f in frames:
        pkt = decode_frame(f)
        if pkt is not None:
            messages.extend(dec.feed(pkt))
    return frames, messages


def _cmd_info(args) -> int:
    t0 = time.perf_counter()
    frames, messages = _decode_pcap(args.pcap)
    dt = (time.perf_counter() - t0) * 1000.0
    proto_counts: dict = {}
    for m in messages:
        proto_counts[m.protocol] = proto_counts.get(m.protocol, 0) + 1
    print(f"file        : {args.pcap}")
    print(f"frames      : {len(frames):,}")
    print(f"decoded     : {len(messages):,}")
    for p, n in sorted(proto_counts.items()):
        print(f"  {p:<10}: {n:,}")
    print(f"decode time : {dt:.0f} ms")
    return 0


def _cmd_analyze(args) -> int:
    t0 = time.perf_counter()
    frames, messages = _decode_pcap(args.pcap)
    sd_rep = sd_offline.analyse_sd(messages)
    doip_rep = doip_offline.reconstruct_doip(messages)
    dt = (time.perf_counter() - t0) * 1000.0

    sd_sum = sd_rep.summary()
    doip_sum = doip_rep.summary()
    sd_violations = len(sd_rep.violations)

    print(f"analysed {len(messages):,} messages from {len(frames):,} "
          f"frames in {dt:.0f} ms")
    print(f"  SD:   ECUs={sd_sum['ecus']}  services={sd_sum['services']}  "
          f"offers={sd_sum['offers']}  finds={sd_sum['finds']}  "
          f"violations={sd_violations}")
    print(f"  DoIP: sessions={doip_sum['sessions']}  "
          f"reconnects={doip_sum['reconnects']}  "
          f"uds={doip_sum['uds_exchanges']}  "
          f"NRCs={doip_sum['negative_responses']}  "
          f"retx={doip_sum['retransmits']}  "
          f"avg_rtt_ms={doip_sum['avg_rtt_ms']}")

    if args.report:
        render_html_report(args.pcap, messages, args.report,
                           sd_report=sd_rep, doip_report=doip_rep)
        print(f"  → HTML report written to {args.report}")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({
                "file": args.pcap,
                "frames": len(frames),
                "messages": len(messages),
                "sd": sd_sum,
                "sd_violations": [v.__dict__ for v in sd_rep.violations],
                "doip": doip_sum,
            }, fh, indent=2)
        print(f"  → JSON summary written to {args.json}")

    # Non-zero exit for SD violations (useful in CI).
    if args.strict and sd_violations:
        return 2
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv
    parser = argparse.ArgumentParser(
        prog="SomeIPDiagnosticsSuite",
        description="SOME/IP / DoIP diagnostics — CLI mode")
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_info = sub.add_parser("info", help="show capture summary")
    p_info.add_argument("pcap", help="path to .pcap / .pcapng")
    p_info.set_defaults(func=_cmd_info)

    p_an = sub.add_parser("analyze", aliases=["analyse"],
                          help="run SD + DoIP offline analysis")
    p_an.add_argument("pcap", help="path to .pcap / .pcapng")
    p_an.add_argument("--report", metavar="HTML",
                      help="write an HTML report to HTML")
    p_an.add_argument("--json", metavar="JSON",
                      help="write a JSON summary to JSON")
    p_an.add_argument("--strict", action="store_true",
                      help="exit with code 2 if any SD violation is found")
    p_an.set_defaults(func=_cmd_analyze)

    args = parser.parse_args(argv[1:])
    return args.func(args)


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------


_HTML_CSS = """
body { font-family: -apple-system, Segoe UI, Roboto, sans-serif;
       background:#0E0E11; color:#E6E6E6; margin:0; padding:24px; }
h1   { color:#80D8FF; margin:0 0 4px 0; font-weight:600; }
h2   { color:#FFD180; margin-top:32px; border-bottom:1px solid #333; padding-bottom:4px; }
small{ color:#9E9E9E; }
table{ border-collapse:collapse; width:100%; margin:8px 0 24px 0; font-size:13px; }
th,td{ padding:6px 10px; border-bottom:1px solid #222; text-align:left; }
th   { background:#1A1A1F; color:#80D8FF; font-weight:600; }
tr:hover td { background:#181820; }
.k   { color:#9E9E9E; }
.ok  { color:#A5D6A7; }
.bad { color:#EF9A9A; font-weight:600; }
.warn{ color:#FFD54F; }
.mono{ font-family: Consolas, monospace; }
.kpi { display:inline-block; background:#1A1A1F; border-radius:6px;
       padding:10px 16px; margin:0 8px 8px 0; min-width:120px; }
.kpi .v { font-size:22px; font-weight:600; color:#80D8FF; }
.kpi .c { font-size:11px; color:#9E9E9E; text-transform:uppercase; }
"""


def _esc(x) -> str:
    return html.escape(str(x))


def _kpi(value, caption, klass: str = "") -> str:
    return (f'<div class="kpi"><div class="v {klass}">{_esc(value)}</div>'
            f'<div class="c">{_esc(caption)}</div></div>')


def render_html_report(source_label: str,
                       messages: Iterable[DecodedMessage],
                       out_path: str,
                       sd_report=None,
                       doip_report=None) -> None:
    """Write a self-contained HTML report to ``out_path``.

    If ``sd_report`` / ``doip_report`` aren't supplied they are computed
    here, so the GUI can call this with just the message list.
    """
    messages = list(messages)
    if sd_report is None:
        sd_report = sd_offline.analyse_sd(messages)
    if doip_report is None:
        doip_report = doip_offline.reconstruct_doip(messages)

    sd_sum = sd_report.summary()
    doip_sum = doip_report.summary()

    parts: List[str] = []
    parts.append(f"<!doctype html><html><head><meta charset='utf-8'>")
    parts.append(f"<title>SOME/IP Diagnostics report — {_esc(source_label)}</title>")
    parts.append(f"<style>{_HTML_CSS}</style></head><body>")
    parts.append(f"<h1>SOME/IP Diagnostics report</h1>")
    parts.append(f"<small>source: <span class='mono'>{_esc(source_label)}</span> &nbsp;|&nbsp; "
                 f"generated {_esc(time.strftime('%Y-%m-%d %H:%M:%S'))} &nbsp;|&nbsp; "
                 f"suite v{__version__}</small>")

    # Capture summary
    proto_counts: dict = {}
    for m in messages:
        proto_counts[m.protocol] = proto_counts.get(m.protocol, 0) + 1
    parts.append("<h2>Capture summary</h2>")
    parts.append(_kpi(f"{len(messages):,}", "Messages"))
    for p, n in sorted(proto_counts.items()):
        parts.append(_kpi(f"{n:,}", p))

    # SD section
    parts.append("<h2>SOME/IP-SD timing</h2>")
    parts.append(_kpi(sd_sum["ecus"],      "ECUs"))
    parts.append(_kpi(sd_sum["services"],  "Services"))
    parts.append(_kpi(sd_sum["offers"],    "OfferService"))
    parts.append(_kpi(sd_sum["finds"],     "FindService"))
    parts.append(_kpi(sd_sum["violations"], "Violations",
                      "bad" if sd_sum["violations"] else "ok"))
    if sd_report.timings:
        parts.append("<h2>Per-ECU × service timing</h2>")
        parts.append("<table><tr><th>ECU</th><th>Service</th><th>Inst</th>"
                     "<th>First offer (ms)</th><th>Rep base (ms)</th>"
                     "<th>Cyclic (ms)</th><th>Offers</th>"
                     "<th>First frame</th></tr>")
        for t in sd_report.timings:
            rb = t.estimated_repetitions_base_ms()
            cy = t.estimated_cyclic_offer_ms()
            parts.append(
                f"<tr><td>{_esc(t.src_ip)}</td>"
                f"<td class='mono'>0x{t.service_id:04X}</td>"
                f"<td>{t.instance_id}</td>"
                f"<td>{('%.1f' % t.initial_delay_ms) if t.initial_delay_ms is not None else '&mdash;'}</td>"
                f"<td>{('%.1f' % rb) if rb is not None else '&mdash;'}</td>"
                f"<td>{('%.1f' % cy) if cy is not None else '&mdash;'}</td>"
                f"<td>{len(t.offers)}</td>"
                f"<td>{t.offers[0].frame_index if t.offers else '&mdash;'}</td></tr>")
        parts.append("</table>")
    if sd_report.violations:
        parts.append("<h2>SD violations</h2>")
        parts.append("<table><tr><th>Kind</th><th>ECU</th><th>Service</th>"
                     "<th>Frame</th><th>Detail</th></tr>")
        for v in sd_report.violations:
            parts.append(
                f"<tr><td class='bad'>{_esc(v.kind)}</td>"
                f"<td>{_esc(v.src_ip)}</td>"
                f"<td class='mono'>0x{v.service_id:04X}.{v.instance_id}</td>"
                f"<td>{v.frame_index}</td>"
                f"<td>{_esc(v.detail)}</td></tr>")
        parts.append("</table>")

    # DoIP section
    parts.append("<h2>DoIP sessions</h2>")
    parts.append(_kpi(doip_sum["sessions"],     "Sessions"))
    parts.append(_kpi(doip_sum["reconnects"],   "Reconnects",
                      "warn" if doip_sum["reconnects"] else "ok"))
    parts.append(_kpi(doip_sum["uds_exchanges"], "UDS exchanges"))
    parts.append(_kpi(doip_sum["negative_responses"], "NRCs",
                      "bad" if doip_sum["negative_responses"] else "ok"))
    parts.append(_kpi(doip_sum["retransmits"], "Retransmits",
                      "warn" if doip_sum["retransmits"] else "ok"))
    if doip_sum["avg_rtt_ms"] is not None:
        parts.append(_kpi(f"{doip_sum['avg_rtt_ms']:.2f}", "Avg RTT (ms)"))

    if doip_report.sessions:
        parts.append("<table><tr><th>Client</th><th>Entity</th>"
                     "<th>Start</th><th>RA code</th><th>RA lat (ms)</th>"
                     "<th>Alive a/s</th><th>UDS msgs</th></tr>")
        for s in doip_report.sessions:
            try:
                rc = doip_offline.doip.RoutingActivationResponseCode(
                    s.routing_activation_rc).name \
                    if s.routing_activation_rc is not None else "—"
            except ValueError:
                rc = f"0x{s.routing_activation_rc:02X}"
            klass = "ok" if rc == "RoutingSuccessfullyActivated" else "warn"
            parts.append(
                f"<tr><td>{_esc(s.client)}</td><td>{_esc(s.entity)}</td>"
                f"<td>{s.started_ts:.3f}</td>"
                f"<td class='{klass}'>{_esc(rc)}</td>"
                f"<td>{('%.2f' % s.routing_activation_latency_ms) if s.routing_activation_latency_ms is not None else '&mdash;'}</td>"
                f"<td>{s.alive_checks_answered}/{s.alive_checks_sent}</td>"
                f"<td>{len(s.exchanges)}</td></tr>")
        parts.append("</table>")

    # Per-session UDS detail
    for i, s in enumerate(doip_report.sessions):
        if not s.exchanges:
            continue
        parts.append(f"<h2>Session #{i+1} &mdash; "
                     f"{_esc(s.client)} → {_esc(s.entity)}</h2>")
        parts.append("<table><tr><th>Frame</th><th>Time</th><th>SA</th>"
                     "<th>TA</th><th>SID</th><th>RTT (ms)</th><th>Ack</th>"
                     "<th>NRC</th><th>ReTx</th><th>Request</th>"
                     "<th>Response</th></tr>")
        for e in s.exchanges:
            klass = "bad" if e.nrc is not None else (
                "warn" if e.retransmits else "")
            parts.append(
                f"<tr class='{klass}'><td>{e.request_frame}</td>"
                f"<td>{e.request_ts:.6f}</td>"
                f"<td class='mono'>0x{e.sa:04X}</td>"
                f"<td class='mono'>0x{e.ta:04X}</td>"
                f"<td class='mono'>0x{e.sid:02X}</td>"
                f"<td>{('%.2f' % e.rtt_ms) if e.rtt_ms is not None else '&mdash;'}</td>"
                f"<td>{'✓' if e.ack_frame is not None else '&mdash;'}</td>"
                f"<td>{('0x%02X' % e.nrc) if e.nrc is not None else '&mdash;'}</td>"
                f"<td>{e.retransmits or '&mdash;'}</td>"
                f"<td class='mono'>{_esc(e.request_hex[:64])}</td>"
                f"<td class='mono'>{_esc((e.response_hex or '')[:64])}</td></tr>")
        parts.append("</table>")

    parts.append("</body></html>")
    os.makedirs(os.path.dirname(os.path.abspath(out_path)) or ".",
                exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("".join(parts))
