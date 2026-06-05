#!/usr/bin/env python3
"""Generate ``build/icon.ico`` and ``build/splash.png``.

Run when you need to refresh the bundled art:

    python build/generate_assets.py

We avoid Pillow on purpose: PyInstaller users on the CI runner may not
have it installed and we want the build to stay pure-stdlib.
The icon is a single 64x64 PNG wrapped in an ICO header; the splash
is a 480x180 PNG. Both are emitted with the zlib + struct modules only.
"""

from __future__ import annotations

import os
import struct
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))


# ---------------------------------------------------------------------------
# Minimal PNG writer (RGBA, no filtering, single IDAT)
# ---------------------------------------------------------------------------
def _png_chunk(tag: bytes, data: bytes) -> bytes:
    return (struct.pack(">I", len(data)) + tag + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))


def _write_png(path: str, w: int, h: int, pixels: bytes) -> None:
    assert len(pixels) == w * h * 4
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0)  # RGBA
    # Each scanline is prefixed with filter byte 0
    raw = b"".join(b"\x00" + pixels[y * w * 4:(y + 1) * w * 4]
                   for y in range(h))
    idat = zlib.compress(raw, 9)
    with open(path, "wb") as fh:
        fh.write(sig)
        fh.write(_png_chunk(b"IHDR", ihdr))
        fh.write(_png_chunk(b"IDAT", idat))
        fh.write(_png_chunk(b"IEND", b""))


# ---------------------------------------------------------------------------
# Icon  ------ a rounded blue tile with a stylised "S/IP" mark
# ---------------------------------------------------------------------------
def _make_icon_png(size: int = 64) -> bytes:
    bg = (0x12, 0x1A, 0x24, 0xFF)              # dark navy
    accent = (0x40, 0xC4, 0xFF, 0xFF)          # cyan
    accent2 = (0xFF, 0xD1, 0x80, 0xFF)         # amber
    pixels = bytearray(size * size * 4)

    def setpx(x: int, y: int, rgba):
        if 0 <= x < size and 0 <= y < size:
            i = (y * size + x) * 4
            pixels[i:i+4] = bytes(rgba)

    r = size * 0.18
    # rounded-rect background
    for y in range(size):
        for x in range(size):
            # corner-radius rounding
            cx = max(r - x, x - (size - 1 - r), 0)
            cy = max(r - y, y - (size - 1 - r), 0)
            if cx * cx + cy * cy <= r * r:
                setpx(x, y, bg)
    # "/" diagonal stripe (accent2)
    for t in range(size):
        x = t
        y = size - 1 - t
        for dx in range(-2, 3):
            setpx(x + dx, y, accent2)
    # cyan dots — three small squares representing packets travelling
    for cx, cy in ((14, 14), (32, 14), (50, 14),
                   (14, 50), (32, 50), (50, 50)):
        for dy in range(-3, 4):
            for dx in range(-3, 4):
                setpx(cx + dx, cy + dy, accent)
    return bytes(pixels)


def write_ico(path: str) -> None:
    size = 64
    pixels = _make_icon_png(size)
    # The simplest ICO is a header + ICONDIRENTRY + a PNG blob.
    # Build the PNG bytes into memory.
    import io
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    raw = b"".join(b"\x00" + pixels[y*size*4:(y+1)*size*4]
                   for y in range(size))
    idat = zlib.compress(raw, 9)
    png = sig + _png_chunk(b"IHDR", ihdr) + _png_chunk(b"IDAT", idat) \
        + _png_chunk(b"IEND", b"")
    # ICONDIR (6 bytes) + ICONDIRENTRY (16 bytes) + PNG
    ico_hdr = struct.pack("<HHH", 0, 1, 1)   # reserved, type(1=icon), count
    ico_entry = struct.pack("<BBBBHHII",
                            size if size < 256 else 0,
                            size if size < 256 else 0,
                            0, 0,           # colors, reserved
                            1, 32,          # planes, bpp
                            len(png), 22)   # size, offset
    with open(path, "wb") as fh:
        fh.write(ico_hdr + ico_entry + png)


# ---------------------------------------------------------------------------
# Splash — a 480×180 panel "SOME/IP Diagnostics Suite" loading…
# ---------------------------------------------------------------------------
def write_splash(path: str) -> None:
    W, H = 480, 180
    bg = (0x0E, 0x10, 0x14, 0xFF)
    border = (0x40, 0xC4, 0xFF, 0xFF)
    accent2 = (0xFF, 0xD1, 0x80, 0xFF)
    pixels = bytearray(W * H * 4)
    for i in range(0, len(pixels), 4):
        pixels[i:i+4] = bytes(bg)

    def setpx(x, y, rgba):
        if 0 <= x < W and 0 <= y < H:
            i = (y * W + x) * 4
            pixels[i:i+4] = bytes(rgba)

    # Border
    for x in range(W):
        setpx(x, 0, border); setpx(x, H-1, border)
    for y in range(H):
        setpx(0, y, border); setpx(W-1, y, border)
    # Accent bar at bottom
    for y in range(H - 18, H - 12):
        for x in range(20, W - 20):
            setpx(x, y, accent2)
    # A few packet-square indicators
    for cx in range(40, W - 40, 60):
        for dy in range(-5, 6):
            for dx in range(-5, 6):
                setpx(cx + dx, 60 + dy, border)
    _write_png(path, W, H, bytes(pixels))


# ---------------------------------------------------------------------------
# Windows version-info file (consumed by PyInstaller --version-file)
# ---------------------------------------------------------------------------
_VERSION_TXT = """\
# UTF-8
#
# For more details about fixed file info 'ffi' see:
# http://msdn.microsoft.com/en-us/library/ms646997.aspx
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=(2, 0, 0, 0),
    prodvers=(2, 0, 0, 0),
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
    ),
  kids=[
    StringFileInfo(
      [
      StringTable(
        u'040904B0',
        [StringStruct(u'CompanyName',     u'Nag12211221'),
         StringStruct(u'FileDescription', u'SOME/IP Diagnostics Suite'),
         StringStruct(u'FileVersion',     u'2.0.0.0'),
         StringStruct(u'InternalName',    u'SomeIPDiagnosticsSuite'),
         StringStruct(u'LegalCopyright',  u'Open Source — see project LICENSE'),
         StringStruct(u'OriginalFilename',u'SomeIPDiagnosticsSuite.exe'),
         StringStruct(u'ProductName',     u'SOME/IP Diagnostics Suite'),
         StringStruct(u'ProductVersion',  u'2.0.0.0')])
      ]),
    VarFileInfo([VarStruct(u'Translation', [1033, 1200])])
  ]
)
"""


def write_version(path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(_VERSION_TXT)


def main() -> None:
    write_ico(os.path.join(HERE, "icon.ico"))
    write_splash(os.path.join(HERE, "splash.png"))
    write_version(os.path.join(HERE, "version.txt"))
    print("[generate_assets] wrote icon.ico, splash.png, version.txt")


if __name__ == "__main__":
    main()
