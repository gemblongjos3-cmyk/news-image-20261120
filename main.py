#!/usr/bin/env python3
"""news-image-20261120 — publish the editorial front page byte for byte.

The illustration bundled here condenses Friday 20 November 2026 into one
front page: a peace declaration issued by Trump, Xi and Putin after the
Shenzhen summit; Cyclone Akvan making landfall in India today; Denmark voting
109-0 for the US Greenland security deal; 34 killed in the Haiti raid; Trump
to speak at noon in Washington; the Test resuming in Wellington.

The job of this script is deliberately narrow: locate ``entry.jpg`` next to
itself, prove the file is a structurally complete JPEG, and copy the bytes
through untouched to ``$MAKEFUN_OUTPUT_DIR/entry.png`` (``/output`` when the
variable is unset). The destination keeps a ``.png`` name because that is the
contract the caller expects, but nothing is transcoded — the payload stays
JPEG and the written file is read back and compared by sha256 so that any
corruption or truncation during the write is caught before we exit zero.

Validation walks the whole marker chain from SOI to EOI rather than trusting
the header: every length-bearing segment must fit inside the file, entropy
coded scan data is skipped with correct handling of FF00 stuffing, fill bytes
and restart markers, and the EOI must be the last two bytes with nothing
trailing behind it. A file whose scan data simply stops is rejected.

Standard library only, Python 3.13, no randomness, no clock, no network.
Every failure path leaves via a non-zero exit status.
"""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

PROGRAM = "news-image-20261120"
INPUT_NAME = "entry.jpg"
OUTPUT_NAME = "entry.png"
BYTE_CEILING = 1_048_576
SIDE_CEILING = 1_024
FALLBACK_OUTPUT = "/output"

MARKER_PREFIX = 0xFF
SOI = 0xD8
EOI = 0xD9
TEM = 0x01
SOS = 0xDA

# Frame headers: the only markers that carry picture dimensions. 0xC4 (DHT),
# 0xC8 (JPG) and 0xCC (DAC) sit in the same 0xCn neighbourhood but are
# ordinary length-bearing segments, so they are absent from this set.
FRAME_HEADERS = frozenset(
    (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF)
)


class ImageError(Exception):
    """Any reason the bundled picture cannot be shipped as-is."""


def locate_image() -> Path:
    """Find entry.jpg beside this script, falling back to /bot."""
    here = Path(__file__).resolve().parent
    for directory in (here, Path("/bot")):
        candidate = directory / INPUT_NAME
        if candidate.is_file():
            return candidate
    raise ImageError(f"{INPUT_NAME} not found beside {here} or in /bot")


def load_image(path: Path) -> bytes:
    """Read the picture, refusing anything empty or over the byte ceiling."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ImageError(f"cannot read {path}: {exc}") from exc
    if not raw:
        raise ImageError(f"{path.name} is empty")
    if len(raw) > BYTE_CEILING:
        raise ImageError(
            f"{path.name} is {len(raw)} bytes, above the {BYTE_CEILING}-byte ceiling"
        )
    return raw


def _skip_entropy(raw: bytes, pos: int) -> int:
    """Walk entropy coded bytes; return the offset of the next real marker.

    Inside a scan a literal 0xFF is written as FF 00, restart markers D0-D7
    stand alone, and any number of FF fill bytes may precede a marker. When
    those cases are exhausted the byte that follows the FF run is a genuine
    marker, and we hand back the offset of the run's first FF.
    """
    end = len(raw)
    while pos < end:
        if raw[pos] != MARKER_PREFIX:
            pos += 1
            continue
        run_start = pos
        while pos < end and raw[pos] == MARKER_PREFIX:
            pos += 1
        if pos >= end:
            break
        follower = raw[pos]
        if follower == 0x00:  # stuffed literal FF
            pos += 1
            continue
        if 0xD0 <= follower <= 0xD7:  # RSTn, no length field
            pos += 1
            continue
        return run_start
    raise ImageError(
        "scan data runs to the end of the file without a closing EOI marker"
    )


def inspect(raw: bytes) -> tuple[int, int]:
    """Validate the whole JPEG structure and return ``(width, height)``."""
    end = len(raw)
    if end < 4:
        raise ImageError(f"file is only {end} bytes, too short to be a JPEG")
    if raw[0] != MARKER_PREFIX or raw[1] != SOI:
        raise ImageError("file does not begin with the JPEG SOI marker FF D8")

    pos = 2
    frame: tuple[int, int] | None = None
    scanned = False

    while True:
        if pos >= end:
            raise ImageError("file ends before an EOI marker was reached")
        if raw[pos] != MARKER_PREFIX:
            raise ImageError(f"expected a marker at offset {pos}, found 0x{raw[pos]:02X}")
        while pos < end and raw[pos] == MARKER_PREFIX:
            pos += 1
        if pos >= end:
            raise ImageError("file ends inside a marker prefix run")
        marker = raw[pos]
        pos += 1

        if marker == EOI:
            if pos != end:
                raise ImageError(
                    f"{end - pos} byte(s) of trailing data follow the EOI marker"
                )
            if frame is None:
                raise ImageError("no start-of-frame segment before EOI")
            if not scanned:
                raise ImageError("no scan segment before EOI")
            return frame

        if marker == SOI:
            raise ImageError(f"unexpected second SOI marker at offset {pos - 2}")
        if marker == 0x00:
            raise ImageError(f"stray FF 00 padding outside scan data at offset {pos - 2}")
        if marker == TEM or 0xD0 <= marker <= 0xD7:
            continue  # standalone markers carry no length field

        if pos + 2 > end:
            raise ImageError(f"truncated length field for marker FF{marker:02X}")
        span = int.from_bytes(raw[pos : pos + 2], "big")
        if span < 2:
            raise ImageError(f"illegal segment length {span} for marker FF{marker:02X}")
        body_end = pos + span
        if body_end > end:
            raise ImageError(
                f"segment FF{marker:02X} claims {span} bytes but only "
                f"{end - pos} remain"
            )

        if marker in FRAME_HEADERS:
            if span < 8:
                raise ImageError("start-of-frame segment is too short to hold dimensions")
            if frame is not None:
                raise ImageError("more than one start-of-frame segment")
            height = int.from_bytes(raw[pos + 3 : pos + 5], "big")
            width = int.from_bytes(raw[pos + 5 : pos + 7], "big")
            if width == 0 or height == 0:
                raise ImageError(f"start-of-frame declares a zero dimension {width}x{height}")
            frame = (width, height)

        pos = body_end
        if marker == SOS:
            scanned = True
            pos = _skip_entropy(raw, pos)


def emit(raw: bytes, out_dir: Path) -> Path:
    """Copy the bytes verbatim and prove the copy matches the source."""
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / OUTPUT_NAME
    target.write_bytes(raw)

    mirror = target.read_bytes()
    source_hash = hashlib.sha256(raw).hexdigest()
    mirror_hash = hashlib.sha256(mirror).hexdigest()
    if len(mirror) != len(raw):
        raise ImageError(
            f"{target} re-read as {len(mirror)} bytes, source is {len(raw)} bytes"
        )
    if mirror_hash != source_hash:
        raise ImageError(
            f"{target} re-read as sha256 {mirror_hash}, source hashes to {source_hash}"
        )
    return target


def run() -> int:
    try:
        raw = load_image(locate_image())
        width, height = inspect(raw)
        if width > SIDE_CEILING or height > SIDE_CEILING:
            raise ImageError(
                f"picture is {width}x{height}, over the {SIDE_CEILING}x{SIDE_CEILING} cap"
            )
        out_dir = Path(os.environ.get("MAKEFUN_OUTPUT_DIR") or FALLBACK_OUTPUT)
        target = emit(raw, out_dir)
    except ImageError as exc:
        print(f"{PROGRAM}: rejected: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"{PROGRAM}: I/O failure: {exc}", file=sys.stderr)
        return 1

    print(
        f"{PROGRAM}: {target} <- {len(raw)} bytes, {width}x{height}, "
        f"sha256 {hashlib.sha256(raw).hexdigest()}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(run())
