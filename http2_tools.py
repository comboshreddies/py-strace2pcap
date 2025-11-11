"""Minimal HTTP/2 frame parsing helpers for the UNIX TCP synthesiser."""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

MAX_HTTP2_FRAME_SIZE = (1 << 24) - 1
VALID_STREAM_ZERO_TYPES = {0x4, 0x6, 0x7, 0x8}


@dataclass
class HTTP2Header:
    length: int
    frame_type: int
    flags: int
    stream_id: int


@dataclass
class Chunk:
    kind: str  # "frame" or "opaque"
    data: bytes
    header: Optional[HTTP2Header] = None


class HTTP2Splitter:
    """Accumulate bytes and yield HTTP/2-aligned chunks."""

    def __init__(self) -> None:
        self._buffer = bytearray()

    def push(self, data: bytes) -> None:
        if data:
            self._buffer.extend(data)

    def pop(self, *, final: bool = False) -> List[Chunk]:
        chunks: List[Chunk] = []
        while True:
            if len(self._buffer) < 9:
                break
            header = _parse_header(self._buffer[:9])
            if header is None:
                offset = _find_alignment(self._buffer)
                if offset is None:
                    break
                if offset:
                    raw = bytes(self._buffer[:offset])
                    del self._buffer[:offset]
                    chunks.append(Chunk("opaque", raw, None))
                    continue
                break
            total = 9 + header.length
            if total > len(self._buffer):
                break
            raw = bytes(self._buffer[:total])
            del self._buffer[:total]
            chunks.append(Chunk("frame", raw, header))
        if final and self._buffer:
            chunks.append(Chunk("opaque", bytes(self._buffer), None))
            self._buffer.clear()
        return chunks

    def has_pending(self) -> bool:
        return bool(self._buffer)


def _parse_header(prefix: bytes) -> Optional[HTTP2Header]:
    if len(prefix) < 9:
        return None
    length = int.from_bytes(prefix[:3], "big")
    if length > MAX_HTTP2_FRAME_SIZE:
        return None
    frame_type = prefix[3]
    if frame_type > 0x9:
        return None
    flags = prefix[4]
    stream_id = int.from_bytes(prefix[5:9], "big") & 0x7FFFFFFF
    if stream_id == 0 and frame_type not in VALID_STREAM_ZERO_TYPES:
        return None
    return HTTP2Header(length, frame_type, flags, stream_id)


def _find_alignment(buffer: bytearray) -> Optional[int]:
    for offset in range(1, len(buffer)):
        if len(buffer) - offset < 9:
            return None
        if _parse_header(buffer[offset : offset + 9]) is not None:
            return offset
    return None
