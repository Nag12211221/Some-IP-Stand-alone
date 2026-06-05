# PyInstaller spec for SOME/IP Diagnostics Suite
# Build with:
#     pyinstaller build/someip_suite.spec --clean --noconfirm

# -*- mode: python ; coding: utf-8 -*-

import os
import sys

block_cipher = None

# Resolve repo root regardless of where PyInstaller is invoked from.
here = os.path.dirname(os.path.abspath(SPEC))
project_root = os.path.abspath(os.path.join(here, os.pardir))
src_path = os.path.join(project_root, "src")
sys.path.insert(0, src_path)

icon_path = os.path.join(here, "icon.ico")
splash_path = os.path.join(here, "splash.png")
version_path = os.path.join(here, "version.txt")
if not os.path.exists(icon_path):
    icon_path = None
if not os.path.exists(version_path):
    version_path = None

a = Analysis(
    [os.path.join(src_path, "someip_suite", "__main__.py")],
    pathex=[src_path],
    binaries=[],
    datas=[],
    hiddenimports=[
        # Core
        "someip_suite",
        "someip_suite.cli",
        "someip_suite.capture_tab",
        "someip_suite.widgets",
        # Protocols
        "someip_suite.protocols",
        "someip_suite.protocols.someip",
        "someip_suite.protocols.doip",
        "someip_suite.protocols.pcap",
        "someip_suite.protocols.l2",
        "someip_suite.protocols.decoder",
        # Modules
        "someip_suite.modules",
        "someip_suite.modules.sd_analyzer",
        "someip_suite.modules.sd_offline",
        "someip_suite.modules.doip_monitor",
        "someip_suite.modules.doip_offline",
        "someip_suite.modules.filter_engine",
        "someip_suite.modules.live_capture",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # Aggressively prune things we don't use to keep the EXE small.
    # The biggest savings come from tkinter.test, tcl8/tzdata, lib2to3,
    # email.test and the unused stdlib XML-RPC stack.
    excludes=[
        "numpy", "pandas", "matplotlib", "PIL", "scipy",
        "pytest", "setuptools", "test",
        "pydoc_data",
        "tkinter.test",
        "lib2to3",
        "distutils",
        "xmlrpc",
        "email.test",
        "_tkinter.tix",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

# Drop heavy unused tcl/tk locale data — ~30% size cut.
def _drop(items, predicates):
    out = []
    for entry in items:
        dest = entry[0].replace("\\", "/").lower()
        if any(p in dest for p in predicates):
            continue
        out.append(entry)
    return out

_TCL_TRIM = (
    "tcl8/tzdata/",      # 700+ tz files we never read
    "tcl/tzdata/",
    "tcl8.6/tzdata/",
    "tk/demos/",
    "tcl8/8.6/encoding/",  # only ASCII/UTF-8 needed in practice
    "tcl8/8.6/msgs/",
    "tcl/8.6/msgs/",
    "tk/8.6/msgs/",
    "tk/msgs/",
)
a.datas = _drop(a.datas, _TCL_TRIM)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

# Optional splash — PyInstaller 5+ only; guarded so old versions still build.
splash = None
try:
    if os.path.exists(splash_path):
        splash = Splash(
            splash_path,
            binaries=a.binaries,
            datas=a.datas,
            text_pos=(10, 160),
            text_size=10,
            text_color="white",
        )
except NameError:
    splash = None

exe_args = [pyz, a.scripts, a.binaries, a.zipfiles, a.datas]
if splash is not None:
    exe_args = [pyz, a.scripts, splash, splash.binaries,
                a.binaries, a.zipfiles, a.datas]

exe = EXE(
    *exe_args,
    [],
    name="SomeIPDiagnosticsSuite",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,            # GUI app: no console window
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=icon_path,           # branded EXE icon (build/icon.ico)
    version=version_path,     # VS_VERSIONINFO (build/version.txt)
)
