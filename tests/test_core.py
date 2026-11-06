import unittest

from tcp_segment_header_utils import (
    TCPHeader,
    FLAG_ACK,
    FLAG_FIN,
    FLAG_NS,
    FLAG_PSH,
    FLAG_RST,
    FLAG_SYN,
    FLAG_URG,
    HeaderError,
    format_flags,
    parse_tcp_header,
)


def build_header(
    src_port=1234,
    dst_port=80,
    seq=1,
    ack=0,
    data_offset=5,
    flags=0,
    window=65535,
    checksum=0,
    urgent_pointer=0,
    options=b"",
    payload=b"",
):
    """Build a header the way the parser expects to read it."""
    reserved_and_offset = (data_offset << 4) | ((flags >> 8) & 0x01)
    low_flags = flags & 0xFF
    header = bytearray()
    header += src_port.to_bytes(2, "big")
    header += dst_port.to_bytes(2, "big")
    header += seq.to_bytes(4, "big")
    header += ack.to_bytes(4, "big")
    header.append(reserved_and_offset)
    header.append(low_flags)
    header += window.to_bytes(2, "big")
    header += checksum.to_bytes(2, "big")
    header += urgent_pointer.to_bytes(2, "big")
    header += options
    header += payload
    return bytes(header)


class TestParseHeader(unittest.TestCase):
    def test_basic_fields(self):
        raw = build_header(
            src_port=49152,
            dst_port=443,
            seq=0xDEADBEEF,
            ack=0x01020304,
            window=29200,
            checksum=0xABCD,
            urgent_pointer=0,
            flags=FLAG_SYN,
        )
        hdr = parse_tcp_header(raw)
        self.assertIsInstance(hdr, TCPHeader)
        self.assertEqual(hdr.src_port, 49152)
        self.assertEqual(hdr.dst_port, 443)
        self.assertEqual(hdr.seq, 0xDEADBEEF)
        self.assertEqual(hdr.ack, 0x01020304)
        self.assertEqual(hdr.window, 29200)
        self.assertEqual(hdr.checksum, 0xABCD)
        self.assertEqual(hdr.data_offset, 5)
        self.assertEqual(hdr.header_len, 20)
        self.assertEqual(hdr.options, b"")
        self.assertEqual(hdr.payload, b"")

    def test_flags_are_decoded_including_ns(self):
        raw = build_header(flags=FLAG_SYN | FLAG_ACK | FLAG_NS)
        hdr = parse_tcp_header(raw)
        self.assertEqual(hdr.flags, FLAG_SYN | FLAG_ACK | FLAG_NS)
        self.assertTrue(hdr.has_flag(FLAG_SYN))
        self.assertTrue(hdr.has_flag(FLAG_ACK))
        self.assertTrue(hdr.has_flag(FLAG_NS))
        self.assertFalse(hdr.has_flag(FLAG_FIN))
        self.assertEqual(hdr.flag_names(), ["NS", "ACK", "SYN"])

    def test_all_eight_low_flags(self):
        all_low = FLAG_FIN | FLAG_SYN | FLAG_RST | FLAG_PSH | FLAG_ACK | FLAG_URG
        raw = build_header(flags=all_low)
        hdr = parse_tcp_header(raw)
        self.assertEqual(hdr.flags, all_low)
        self.assertEqual(
            hdr.flag_names(), ["URG", "ACK", "PSH", "RST", "SYN", "FIN"]
        )

    def test_options_and_payload_are_split_at_data_offset(self):
        options = bytes([2, 4, 0x05, 0xB4])  # MSS option
        payload = b"GET / HTTP/1.0\r\n\r\n"
        raw = build_header(data_offset=6, options=options, payload=payload)
        hdr = parse_tcp_header(raw)
        self.assertEqual(hdr.data_offset, 6)
        self.assertEqual(hdr.header_len, 24)
        self.assertEqual(hdr.options, options)
        self.assertEqual(hdr.payload, payload)

    def test_payload_only_buffer(self):
        # A buffer with no trailing payload still parses cleanly.
        raw = build_header(flags=FLAG_ACK)
        hdr = parse_tcp_header(raw)
        self.assertEqual(hdr.payload, b"")

    def test_accepts_bytearray_and_memoryview(self):
        raw = build_header(flags=FLAG_RST)
        for view in (bytearray(raw), memoryview(raw)):
            hdr = parse_tcp_header(view)
            self.assertEqual(hdr.flags, FLAG_RST)


class TestErrors(unittest.TestCase):
    def test_short_buffer_rejected(self):
        with self.assertRaises(HeaderError):
            parse_tcp_header(b"\x00" * 19)

    def test_empty_buffer_rejected(self):
        with self.assertRaises(HeaderError):
            parse_tcp_header(b"")

    def test_data_offset_below_five_rejected(self):
        raw = bytearray(build_header())
        raw[12] = 4 << 4  # 4 * 4 = 16 bytes, impossible
        with self.assertRaises(HeaderError):
            parse_tcp_header(bytes(raw))

    def test_data_offset_larger_than_buffer_rejected(self):
        raw = bytearray(build_header())
        raw[12] = 15 << 4  # 60 bytes claimed, only 20 present
        with self.assertRaises(HeaderError):
            parse_tcp_header(bytes(raw))

    def test_non_bytes_rejected(self):
        with self.assertRaises(TypeError):
            parse_tcp_header("not bytes")


class TestFormatFlags(unittest.TestCase):
    def test_empty_flags_render_empty(self):
        self.assertEqual(format_flags(0), "")

    def test_single_flag(self):
        self.assertEqual(format_flags(FLAG_ACK), "ACK")

    def test_multiple_flags_in_header_order(self):
        self.assertEqual(
            format_flags(FLAG_SYN | FLAG_ACK | FLAG_NS), "NS,ACK,SYN"
        )


if __name__ == "__main__":
    unittest.main()
