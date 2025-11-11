"""gRPC and HTTP/2 seed frames and heuristics."""

from __future__ import annotations

HTTP2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
HTTP2_CLIENT_SETTINGS_FRAME = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"
HTTP2_SETTINGS_ACK_FRAME = b"\x00\x00\x00\x04\x01\x00\x00\x00\x00"
HTTP2_CLIENT_SEED = HTTP2_PREFACE + HTTP2_CLIENT_SETTINGS_FRAME

GRPC_HEADERS_FRAME = bytes.fromhex(
    "00008101040000000140073a6d6574686f6404504f535440073a736368656d65046874747040053a70"
    "6174681b2f706c616365686f6c6465722e536572766963652f4d6574686f64400a3a617574686f7269"
    "7479096c6f63616c686f7374400c636f6e74656e742d74797065106170706c69636174696f6e2f6770"
    "72634002746508747261696c657273"
)

_GRPC_KEYWORDS = (
    b"application/grpc",
    b"grpc-status",
    b"content-type",
    b"/Service/",
)


def frame_has_grpc_evidence(frame_type: int, payload: bytes) -> bool:
    """Return True when the payload suggests gRPC traffic."""
    if frame_type == 0 and len(payload) >= 5:
        compressed = payload[0]
        msg_len = int.from_bytes(payload[1:5], "big")
        if compressed in (0, 1) and msg_len <= len(payload) - 5:
            return True
    if frame_type in (1, 9):
        return any(marker in payload for marker in _GRPC_KEYWORDS)
    return False
