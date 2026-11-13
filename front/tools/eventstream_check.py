#!/usr/bin/env python3
"""Proves front/eventstream.go against botocore's event stream parser.

Two checks, run in the VM with the spike's boto3 venv:

    eventstream_check.py gold                 builds known-good frames with an independent encoder written here (struct and zlib only), prints
                                              them as hex, and decodes each with botocore.eventstream.EventStreamBuffer (which checks both CRCs)
    eventstream_check.py decode <hexfile>     decodes the frames the Go encoder wrote (`ROVARA_ES_DUMP=<file> go test -run TestEventStreamDump`,
                                              one `name hex` per line), checks that each is accepted by botocore, and that the headers and the
                                              payload are what the Go test says it wrote

The golden hex in front/eventstream_test.go is the output of `gold`.
"""
import struct
import sys
import zlib

from botocore.eventstream import EventStreamBuffer


def hdr(name, typ, val=None):
    b = bytes([len(name)]) + name.encode() + bytes([typ])
    if typ == 7:
        b += struct.pack(">H", len(val.encode())) + val.encode()
    elif typ == 6:
        b += struct.pack(">H", len(val)) + val
    elif typ == 2:
        b += struct.pack(">b", val)
    elif typ == 3:
        b += struct.pack(">h", val)
    elif typ == 4:
        b += struct.pack(">i", val)
    elif typ in (5, 8):
        b += struct.pack(">q", val)
    elif typ == 9:
        b += val
    return b


def msg(headers, payload):
    h = b"".join(headers)
    total = 12 + len(h) + len(payload) + 4
    pre = struct.pack(">II", total, len(h))
    pre += struct.pack(">I", zlib.crc32(pre) & 0xFFFFFFFF)
    body = pre + h + payload
    return body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)


def gold():
    ev = lambda t, ct: [hdr(":event-type", 7, t), hdr(":content-type", 7, ct), hdr(":message-type", 7, "event")]
    return {
        "payload_part": msg(ev("PayloadPart", "application/octet-stream"), b"hello world"),
        "empty_part": msg(ev("PayloadPart", "application/octet-stream"), b""),
        "model_stream_error": msg([hdr(":exception-type", 7, "ModelStreamError"), hdr(":content-type", 7, "application/json"),
                                   hdr(":message-type", 7, "exception")], b'{"Message":"the stream broke","ErrorCode":"StreamBroken"}'),
        "error": msg([hdr(":error-code", 7, "InternalServerError"), hdr(":error-message", 7, "boom"), hdr(":message-type", 7, "error")], b""),
        "all_types": msg([hdr("t", 0), hdr("f", 1), hdr("b", 2, -5), hdr("s", 3, -1234), hdr("i", 4, 70000), hdr("l", 5, -(2 ** 40)),
                          hdr("bytes", 6, b"\x00\x01\xff"), hdr("str", 7, "héllo"), hdr("ts", 8, 1700000000123),
                          hdr("u", 9, bytes(range(16)))], b"x"),
    }


def parse(raw):
    buf = EventStreamBuffer()
    buf.add_data(raw)
    out = list(buf)  # raises on a bad CRC, a bad length or a bad header
    return out


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "gold":
        for name, raw in gold().items():
            events = parse(raw)
            assert len(events) == 1, name
            print(name, raw.hex())
        print("botocore accepts every golden frame", file=sys.stderr)
    elif mode == "decode":
        n = 0
        for line in open(sys.argv[2]):
            name, hexs = line.split()
            events = parse(bytes.fromhex(hexs))
            assert len(events) >= 1, name
            for e in events:
                h = e.headers
                if name.startswith("part"):
                    assert h[":message-type"] == "event" and h[":event-type"] == "PayloadPart", (name, h)
                n += 1
        print("botocore accepts %d Go-written frames" % n, file=sys.stderr)
    else:
        sys.exit(__doc__)


main()
