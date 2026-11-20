#!/usr/bin/env python3
"""news-image-20261120 — ship the editorial front-page picture unchanged.

The picture sums up Friday 20 November 2026 in a single frame: Trump, Xi and
Putin issue a peace declaration after the Shenzhen summit; Cyclone Akvan makes
landfall in India today; Denmark votes 109-0 for the US Greenland security
deal; 34 are killed in the Haiti raid; Trump is to speak at noon in
Washington; the Test resumes in Wellington.

This program does not transform the image. It finds the bundled ``entry.jpg``,
validates it (size, JPEG markers, dimensions from the start-of-frame segment)
and copies the bytes verbatim to ``$MAKEFUN_OUTPUT_DIR/entry.png`` (default
``/output``). Note the name is ``.png`` by contract even though the payload is
JPEG — the bytes are *never* re-encoded, so re-reading the written file must
reproduce the source sha256 exactly.

Standard library only, Python 3.13, deterministic. Exits non-zero on any
validation or verification failure.
"""

from __future__ import annotations

import hashlib
import os
import struct
import sys
from pathlib import Path

PROGRAM_NAME = "news-image-20261120"
SOURCE_NAME = "entry.jpg"
OUTPUT_NAME = "entry.png"
MAX_BYTES = 1_048_576
MAX_SIDE = 1_024
DEFAULT_OUTPUT_DIR = "/output"
SOI = b"\xff\xd8"
EOI = b"\xff\xd9"

# Start-of-frame markers carry the frame dimensions. C4 (DHT), C8 (JPG) and CC
# (DAC) share the 0xCn range but are not SOF segments and must be skipped.
SOF_MARKERS = frozenset(
    {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}
)


class ValidationError(Exception):
    """Raised when the bundled picture is unusable."""


def find_source() -> Path:
    """Return the bundled picture, beside this program or under /bot."""
    here = Path(__file__).resolve().parent
    for candidate in (here / SOURCE_NAME, Path("/bot") / SOURCE_NAME):
        if candidate.is_file():
            return candidate
    raise ValidationError(
        f"cannot locate {SOURCE_NAME}: looked beside {Path(__file__).name} "
        f"({here}) and in /bot"
    )


def read_source(path: Path) -> bytes:
    """Read the picture and reject it if it is oversized or not a JPEG."""
    data = path.read_bytes()
    if len(data) > MAX_BYTES:
        raise ValidationError(
            f"{path.name} is {len(data)} bytes, over the {MAX_BYTES}-byte limit"
        )
    if len(data) < 4 or not data.startswith(SOI):
        raise ValidationError(f"{path.name} does not start with JPEG SOI bytes FF D8")
    if not data.endswith(EOI):
        raise ValidationError(f"{path.name} does not end with JPEG EOI bytes FF D9")
    return data


def _next_segment(data: bytes, pos: int, length: int) -> tuple[int, int]:
    """Return ``(marker, payload_offset)`` for the next segment at ``pos``."""
    while pos < length:
        if data[pos] != 0xFF:
            pos += 1
            continue
        while pos < length and data[pos] == 0xFF:
            pos += 1  # fill bytes
        if pos >= length:
            break
        marker = data[pos]
        pos += 1
        if marker == 0x00 or marker == 0x01 or 0xD0 <= marker <= 0xD7:
            continue  # stuffed byte, TEM, or standalone RSTn: no length field
        if marker in (0xD8, 0xD9):
            continue
        return marker, pos
    raise ValidationError("reached end of file before a start-of-frame segment")


def dimensions(data: bytes) -> tuple[int, int]:
    """Parse ``(width, height)`` from the JPEG start-of-frame segment."""
    length = len(data)
    pos = 2  # past SOI
    while True:
        marker, pos = _next_segment(data, pos, length)
        if pos + 2 > length:
            raise ValidationError("truncated segment header in JPEG")
        (seg_len,) = struct.unpack(">H", data[pos : pos + 2])
        if seg_len < 2 or pos + seg_len > length:
            raise ValidationError(
                f"malformed segment length {seg_len} for marker FF{marker:02X}"
            )
        if marker in SOF_MARKERS:
            if seg_len < 7:
                raise ValidationError("start-of-frame segment too short for dimensions")
            height, width = struct.unpack(">HH", data[pos + 3 : pos + 7])
            return width, height
        pos += seg_len


def write_output(data: bytes, out_dir: Path) -> Path:
    """Write ``data`` unchanged to ``out_dir/entry.png`` and verify the copy."""
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / OUTPUT_NAME
    target.write_bytes(data)

    written = target.read_bytes()
    expected = hashlib.sha256(data).hexdigest()
    actual = hashlib.sha256(written).hexdigest()
    if actual != expected:
        raise ValidationError(
            f"verification failed: {target} re-read as sha256 {actual}, "
            f"but the source bytes hash to {expected} — the copy was altered"
        )
    if len(written) != len(data):
        raise ValidationError(
            f"verification failed: {target} re-read as {len(written)} bytes, "
            f"but the source is {len(data)} bytes — the copy was truncated"
        )
    return target


def main() -> int:
    try:
        source = find_source()
        data = read_source(source)
        width, height = dimensions(data)
        if width > MAX_SIDE or height > MAX_SIDE:
            raise ValidationError(
                f"dimensions {width}x{height} exceed the {MAX_SIDE}x{MAX_SIDE} limit"
            )
        out_dir = Path(os.environ.get("MAKEFUN_OUTPUT_DIR") or DEFAULT_OUTPUT_DIR)
        target = write_output(data, out_dir)
    except ValidationError as exc:
        print(f"{PROGRAM_NAME}: error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"{PROGRAM_NAME}: I/O error: {exc}", file=sys.stderr)
        return 1

    digest = hashlib.sha256(data).hexdigest()
    print(
        f"{PROGRAM_NAME}: wrote {target} — {len(data)} bytes, "
        f"{width}x{height}, sha256 {digest}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
