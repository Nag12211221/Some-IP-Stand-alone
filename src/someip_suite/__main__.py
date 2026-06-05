"""Entry point.

* ``python -m someip_suite`` (or the EXE with no args) → launches the GUI.
* ``python -m someip_suite analyze capture.pcap --report out.html``
  (or ``SomeIPDiagnosticsSuite.exe analyze ...``) → runs the CLI.
"""

from __future__ import annotations

import sys


def main(argv=None) -> int:
    if argv is None:
        argv = sys.argv
    # Quick PyInstaller splash teardown — no-op outside the EXE.
    try:
        import pyi_splash    # type: ignore
        pyi_splash.close()
    except Exception:        # noqa: BLE001
        pass

    from someip_suite.cli import is_cli_invocation
    if is_cli_invocation(argv):
        from someip_suite.cli import main as cli_main
        return cli_main(argv)

    from someip_suite.app import SomeIpSuiteApp
    app = SomeIpSuiteApp()
    app.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
