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

a = Analysis(
    [os.path.join(src_path, "someip_suite", "__main__.py")],
    pathex=[src_path],
    binaries=[],
    datas=[],
    hiddenimports=[
        "someip_suite.protocols.someip",
        "someip_suite.protocols.doip",
        "someip_suite.modules.sd_analyzer",
        "someip_suite.modules.doip_monitor",
        "someip_suite.modules.filter_engine",
        "someip_suite.widgets",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["numpy", "pandas", "matplotlib", "PIL", "scipy",
              "pytest", "setuptools", "test", "unittest", "pydoc_data"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
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
    icon=None,                # add path/to/icon.ico to brand the EXE
    version=None,             # add path/to/version.txt for VS_VERSIONINFO
)
