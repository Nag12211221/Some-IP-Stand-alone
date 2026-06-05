"""Protocol codecs (SOME/IP, SOME/IP-SD, DoIP).

All codecs operate on :class:`bytes`/``bytearray`` and are dependency-free.
They are designed to be allocation-light so they can be used on the data
path of the high-performance filter engine.
"""
