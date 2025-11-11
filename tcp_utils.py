"""Tiny helpers for building Ethernet/IP/TCP records."""

from __future__ import annotations

import ipaddress
import struct

ETHERTYPE_IPV4 = 0x0800
TCP_FLAG_FIN = 0x01
TCP_FLAG_SYN = 0x02
TCP_FLAG_PSH = 0x08
TCP_FLAG_ACK = 0x10
MAX_TCP_PAYLOAD = 65535 - 20 - 20


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for idx in range(0, len(data), 2):
        total += (data[idx] << 8) + data[idx + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_ipv4_header(src_ip: str, dst_ip: str, payload_len: int, ip_id: int) -> bytes:
    total_length = 20 + payload_len
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        ip_id & 0xFFFF,
        0,
        64,
        6,
        0,
        ipaddress.IPv4Address(src_ip).packed,
        ipaddress.IPv4Address(dst_ip).packed,
    )
    hdr_checksum = checksum(header)
    return header[:10] + struct.pack("!H", hdr_checksum) + header[12:]


def build_tcp_header(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes,
) -> bytes:
    base = struct.pack(
        "!HHIIHHHH",
        src_port,
        dst_port,
        seq,
        ack,
        (5 << 12) | flags,
        65535,
        0,
        0,
    )
    pseudo = (
        ipaddress.IPv4Address(src_ip).packed
        + ipaddress.IPv4Address(dst_ip).packed
        + struct.pack("!BBH", 0, 6, len(base) + len(payload))
    )
    tcp_checksum = checksum(pseudo + base + payload)
    return struct.pack(
        "!HHIIHHHH",
        src_port,
        dst_port,
        seq,
        ack,
        (5 << 12) | flags,
        65535,
        tcp_checksum,
        0,
    )
