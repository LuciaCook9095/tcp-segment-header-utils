"""Decoder for TCP segment headers (RFC 9293 section 3.1).

The parser is deliberately strict about the two things that are easy to get
wrong when reading a header off the wire:

* The data offset field is measured in 32-bit words, so the header length in
  bytes is ``data_offset * 4``. A value below 5 is not a TCP header at all and
  is rejected rather than silently truncated.
* Options are returned as raw bytes. Reassembling option TLVs is a separate
  concern and guessing at malformed option lists would make this parser harder
to trust for the common case.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

# Flag bit positions within the 12-bit flags field (data offset high nibble is
# not part of the flags). NS is the low bit of the byte that also carries the
# data offset, which is why it needs its own mask.
FLAG_FIN = 0x001
FLAG_SYN = 0x002
FLAG_RST = 0x004
FLAG_PSH = 0x008
FLAG_ACK = 0x010
FLAG_URG = 0x020
FLAG_ECE = 0x040
FLAG_CWR = 0x080
FLAG_NS = 0x100

#: Human-readable names in the order they appear in the header.
FLAG_NAMES = (
    (FLAG_NS, "NS"),
    (FLAG_CWR, "CWR"),
    (FLAG_ECE, "ECE"),
    (FLAG_URG, "URG"),
    (FLAG_ACK, "ACK"),
    (FLAG_PSH, "PSH"),
    (FLAG_RST, "RST"),
    (FLAG_SYN, "SYN"),
    (FLAG_FIN, "FIN"),
)

MIN_HEADER_LEN = 20
MAX_HEADER_LEN = 60


class HeaderError(ValueError):
    """Raised when a byte string cannot be a valid TCP segment header."""


@dataclass(frozen=True)
class TCPHeader:
    """A decoded TCP segment header.

    ``options`` holds the raw option bytes (possibly empty). ``payload`` is
    everything after the header and is not interpreted.
    """

    src_port: int
    dst_port: int
    seq: int
    ack: int
    data_offset: int
    flags: int
    window: int
    checksum: int
    urgent_pointer: int
    options: bytes
    payload: bytes

    @property
    def header_len(self) -> int:
        """Header length in bytes, derived from the data offset field."""
        return self.data_offset * 4

    def has_flag(self, flag: int) -> bool:
        """True when every bit in ``flag`` is set."""
        return (self.flags & flag) == flag

    def flag_names(self) -> list:
        """Names of the flags that are set, in header order."""
        return [name for bit, name in FLAG_NAMES if self.flags & bit]


_eight_bytes = struct.Struct("!HHII")
_four_bytes = struct.Struct("!HHH")


def parse_tcp_header(data: bytes) -> TCPHeader:
    """Decode a TCP segment header from ``data``.

    ``data`` may contain the payload after the header; only the header is
    consumed. Raises :class:`HeaderError` if the buffer is shorter than the
    header or the data offset is impossible.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("data must be bytes-like")
    buf = bytes(data)
    if len(buf) < MIN_HEADER_LEN:
        raise HeaderError(
            "need at least %d bytes for a TCP header, got %d"
            % (MIN_HEADER_LEN, len(buf))
        )

    src_port, dst_port, seq, ack = _eight_bytes.unpack_from(buf, 0)

    # Byte 12 is the high nibble of the data offset and the low nibble is
    # reserved (must be zero per RFC 9293, but we do not enforce that here
    # because some middleboxes emit junk there).
    data_offset = buf[12] >> 4
    if data_offset < 5:
        raise HeaderError(
            "data offset %d is below the minimum of 5 (20 bytes)" % data_offset
        )

    header_len = data_offset * 4
    if len(buf) < header_len:
        raise HeaderError(
            "data offset claims %d bytes but only %d are available"
            % (header_len, len(buf))
        )

    # The NS flag lives in the low bit of byte 12; the remaining eight flags
    # occupy the low byte of the 16-bit field at offset 12.
    flags = ((buf[12] & 0x01) << 8) | buf[13]

    window, checksum, urgent_pointer = _four_bytes.unpack_from(buf, 14)

    options = buf[20:header_len]
    payload = buf[header_len:]

    return TCPHeader(
        src_port=src_port,
        dst_port=dst_port,
        seq=seq,
        ack=ack,
        data_offset=data_offset,
        flags=flags,
        window=window,
        checksum=checksum,
        urgent_pointer=urgent_pointer,
        options=options,
        payload=payload,
    )


def format_flags(flags: int) -> str:
    """Render a flags integer as a ``SYN,ACK`` style string.

    An empty flag set renders as the empty string, which keeps it easy to
    distinguish from a single unknown flag.
    """
    return ",".join(name for bit, name in FLAG_NAMES if flags & bit)
