"""SOME/IP Diagnostics Suite — standalone professional tool.

A self-contained desktop application that operationalises three solutions:

  1. SOME/IP Service Discovery timing analysis (boot-time race conditions).
  2. DoIP flash-session stability monitoring (long-lived TCP under load).
  3. High-performance real-time packet filter engine (>1 Mpps target).

The whole application is implemented on top of the Python standard library
only (no third-party runtime dependencies) so that PyInstaller can produce
a single ``.exe`` with nothing for the end user to install.
"""

__version__ = "1.0.0"
__author__ = "SOME/IP Diagnostics Suite Contributors"
__all__ = ["__version__", "__author__"]
