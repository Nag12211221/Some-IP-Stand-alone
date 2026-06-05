"""Protocol codecs (SOME/IP, SOME/IP-SD, DoIP, PCAP, L2/L3/L4, capture decoder).

All codecs operate on :class:`bytes`/``bytearray`` and are dependency-free.
They are designed to be allocation-light so they can be used on the data
path of the high-performance filter engine.
"""

from . import someip, doip, pcap, l2, decoder  # noqa: F401
