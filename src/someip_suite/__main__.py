"""Entry point: ``python -m someip_suite`` launches the GUI."""

from someip_suite.app import SomeIpSuiteApp


def main() -> int:
    app = SomeIpSuiteApp()
    app.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
