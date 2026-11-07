# tcp-segment-header-utils

Decodes a TCP segment header from raw bytes, exposing the ports, sequence and
acknowledgment numbers, flags, window size, options and payload.

```python
from tcp_segment_header_utils import parse_tcp_header, FLAG_SYN, FLAG_ACK

# A SYN-ACK segment: source 443, destination 49152, window 29200.
raw = bytes.fromhex(
    "01bb c000 0000 0001 0000 0002"  # ports, seq, ack
    "50 12 7210 0000 0000"            # offset/flags, window, checksum, urgent
)

header = parse_tcp_header(raw)
header.src_port        # 443
header.dst_port        # 49152
header.seq             # 1
header.ack             # 2
header.window          # 29200
header.has_flag(FLAG_SYN)  # True
header.has_flag(FLAG_ACK)  # True
header.flag_names()        # ['ACK', 'SYN']
header.header_len          # 20
header.options             # b''
header.payload             # b''
```

## Why this exists

The TCP header has two fields that trip up hand-rolled decoders. The data
offset is counted in 32-bit words, not bytes, so the header length is
`data_offset * 4`; and the NS flag is hiding in the low bit of the byte that
also carries that offset, so a decoder that only reads the low byte of the
flags field silently loses it.

This library reads both fields explicitly and rejects a data offset below 5
(the RFC minimum) instead of producing a header that claims to be 16 bytes
long. The trade-off is that it is strict: it will refuse malformed input that
a lenient parser might accept, because a caller who needs to inspect a real
segment usually wants to know that the segment is malformed.

## Options and payload

Options are returned as raw bytes, not parsed into individual TLVs. Parsing
option lists is a separate problem, and a malformed option list should not
prevent you from reading the ports or flags. If you need the MSS option you
can walk the bytes yourself; the header length tells you where the options
end.

## API

- `parse_tcp_header(data)` — decode a header. `data` may be `bytes`,
  `bytearray` or `memoryview`, and may include the payload after the header.
  Raises `HeaderError` for a buffer shorter than the header or an impossible
  data offset, and `TypeError` for a non-bytes-like argument.
- `TCPHeader` — frozen dataclass with `src_port`, `dst_port`, `seq`, `ack`,
  `data_offset`, `flags`, `window`, `checksum`, `urgent_pointer`, `options`,
  `payload`, plus the `header_len` property, `has_flag(flag)` and
  `flag_names()` methods.
- `format_flags(flags)` — render a flags integer as `"SYN,ACK"`.
- Flag constants: `FLAG_FIN`, `FLAG_SYN`, `FLAG_RST`, `FLAG_PSH`, `FLAG_ACK`,
  `FLAG_URG`, `FLAG_ECE`, `FLAG_CWR`, `FLAG_NS`.
- `FLAG_NAMES` — the `(bit, name)` pairs used by `flag_names` and
  `format_flags`.
- `MIN_HEADER_LEN` (20) and `MAX_HEADER_LEN` (60).
- `HeaderError` — subclass of `ValueError`.

## Tests

```
PYTHONPATH=src python -m unittest discover -s tests
```
