"""Synthetic TCP/IP emitter for UNIX stream sockets."""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from grpc_seed import (
    GRPC_HEADERS_FRAME,
    HTTP2_CLIENT_SEED,
    HTTP2_SETTINGS_ACK_FRAME,
    frame_has_grpc_evidence,
)
from http2_tools import Chunk, HTTP2Splitter
from tcp_utils import (
    ETHERTYPE_IPV4,
    MAX_TCP_PAYLOAD,
    TCP_FLAG_ACK,
    TCP_FLAG_FIN,
    TCP_FLAG_PSH,
    TCP_FLAG_SYN,
    build_ipv4_header,
    build_tcp_header,
)

WRITE_SYSCALLS = {"write", "sendmsg", "sendto"}
READ_SYSCALLS = {"read", "recvmsg", "recvfrom"}
STATE_SYSCALLS = {"close", "shutdown"}

HANDSHAKE_DELTA = 0.0001
TIMESTAMP_EPSILON = 1e-6


@dataclass
class PacketRecord:
    ts_sec: int
    ts_usec: int
    data: bytes


@dataclass
class SideState:
    splitter: HTTP2Splitter = field(default_factory=HTTP2Splitter)
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None
    in_bytes: int = 0
    out_bytes: int = 0
    closed: bool = False
    accounted: bool = False


@dataclass
class Endpoint:
    mac: bytes
    ip: str
    port: int
    isn: int


@dataclass
class Flow:
    inode: Optional[int]
    index: int
    client: Endpoint
    server: Endpoint
    next_seq: Dict[str, int]
    handshake_done: bool = False
    seed_http2_done: bool = False
    seed_grpc_done: bool = False
    grpc_evidence: bool = False
    owners: Dict[Tuple[int, int, int], str] = field(default_factory=dict)
    sides: Dict[str, SideState] = field(init=False)

    def __post_init__(self) -> None:
        self.sides = {"A": SideState(), "B": SideState()}

    def side_for(self, owner: Tuple[int, int, int]) -> str:
        side = self.owners.get(owner)
        if side:
            return side
        assigned = set(self.owners.values())
        side = "A" if "A" not in assigned else "B"
        self.owners[owner] = side
        return side

    def peer(self, side: str) -> str:
        return "B" if side == "A" else "A"


class UnixTCPManager:
    """Emit Ethernet/IP/TCP packets for UNIX stream activity."""

    def __init__(
        self,
        *,
        base_src_ip: str = "10.0.0.0",
        base_dst_ip: str = "10.0.1.0",
        base_sport: int = 30000,
        dst_port: int = 50051,
        seed_http2: bool = False,
        seed_grpc: bool = False,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self._flows: Dict[Tuple, Flow] = {}
        self._base_src_ip = ipaddress.IPv4Address(base_src_ip)
        self._base_dst_ip = ipaddress.IPv4Address(base_dst_ip)
        self._base_sport = base_sport
        self._dst_port = dst_port
        self._seed_http2 = seed_http2
        self._seed_grpc = seed_grpc
        self._logger = logger or logging.getLogger(__name__)
        self._next_index = 0
        self._ip_id = 0

    def handle_event(self, event: Dict) -> List[PacketRecord]:
        if not event or event.get("protocol") != "UNIX-STREAM":
            return []
        syscall = event.get("syscall", "")
        result = event.get("result")
        payload: bytes = event.get("payload") or b""
        timestamp = float(event.get("time", 0.0))
        owner_key = (
            int(event.get("pid") or 0),
            int(event.get("fd") or 0),
            int(event.get("session") or 0),
        )
        flow = self._flow_for_event(event)
        side = flow.side_for(owner_key)

        if syscall in WRITE_SYSCALLS:
            return self._queue_bytes(flow, side, result, payload, timestamp)
        if syscall in READ_SYSCALLS:
            return self._queue_bytes(flow, flow.peer(side), result, payload, timestamp)
        if syscall in STATE_SYSCALLS:
            return self._handle_close(flow, side, timestamp, syscall, result)
        return []

    def flush(self) -> List[PacketRecord]:
        packets: List[PacketRecord] = []
        for flow in list(self._flows.values()):
            packets.extend(self._drain_side(flow, "A", final=True))
            packets.extend(self._drain_side(flow, "B", final=True))
        return packets

    # ------------------------------------------------------------------
    def _flow_for_event(self, event: Dict) -> Flow:
        inode = event.get("inode")
        if isinstance(inode, int):
            key = ("inode", inode)
        else:
            key = (
                "anon",
                event.get("protocol"),
                int(event.get("pid") or 0),
                int(event.get("fd") or 0),
                int(event.get("session") or 0),
            )
        flow = self._flows.get(key)
        if flow is None:
            flow = self._create_flow(inode if isinstance(inode, int) else None)
            self._flows[key] = flow
        return flow

    def _create_flow(self, inode: Optional[int]) -> Flow:
        index = self._next_index
        self._next_index += 1
        client_ip = str(self._base_src_ip + index + 1)
        server_ip = str(self._base_dst_ip + index + 1)
        client_mac = self._mac_for(index, client=True)
        server_mac = self._mac_for(index, client=False)
        inode_seed = inode if inode is not None else 100000 + index
        client_port = self._base_sport + (inode_seed % 10000)
        client_isn = 0x10000000 + inode_seed
        server_isn = 0x20000000 + inode_seed
        return Flow(
            inode=inode,
            index=index,
            client=Endpoint(client_mac, client_ip, client_port, client_isn),
            server=Endpoint(server_mac, server_ip, self._dst_port, server_isn),
            next_seq={"A": client_isn, "B": server_isn},
        )

    def _mac_for(self, index: int, *, client: bool) -> bytes:
        base = 0x020000000000 if client else 0x020000000100
        return (base + index).to_bytes(6, "big")

    # ------------------------------------------------------------------
    def _queue_bytes(
        self,
        flow: Flow,
        side: str,
        result: Optional[int],
        payload: bytes,
        timestamp: float,
    ) -> List[PacketRecord]:
        if not isinstance(result, int) or result <= 0:
            return []
        chunk = payload[:result]
        if not chunk:
            return []
        state = flow.sides[side]
        if state.first_ts is None:
            state.first_ts = timestamp
        state.last_ts = timestamp
        state.splitter.push(chunk)
        state.in_bytes += len(chunk)
        return self._drain_side(flow, side, final=False)

    def _handle_close(
        self,
        flow: Flow,
        side: str,
        timestamp: float,
        syscall: str,
        result: Optional[int],
    ) -> List[PacketRecord]:
        if syscall == "shutdown" and result not in (0, None):
            return []
        flow.sides[side].last_ts = timestamp
        packets = self._drain_side(flow, side, final=True)
        peer = flow.peer(side)
        flow.sides[peer].last_ts = timestamp
        packets.extend(self._drain_side(flow, peer, final=True))
        packets.extend(self._ensure_warmup(flow, timestamp))
        state = flow.sides[side]
        if not state.closed:
            seq = flow.next_seq[side]
            ack = flow.next_seq[peer]
            packets.append(self._build_record(flow, side, seq, ack, TCP_FLAG_FIN | TCP_FLAG_ACK, b"", timestamp))
            flow.next_seq[side] += 1
            state.closed = True
        ack_time = max(timestamp + HANDSHAKE_DELTA / 2, timestamp)
        packets.append(
            self._build_record(flow, peer, flow.next_seq[peer], flow.next_seq[side], TCP_FLAG_ACK, b"", ack_time)
        )
        return packets

    def _drain_side(self, flow: Flow, side: str, *, final: bool) -> List[PacketRecord]:
        state = flow.sides[side]
        chunks = state.splitter.pop(final=final)
        if not chunks:
            if final:
                self._log_accounting(flow, side)
            return []
        packets: List[PacketRecord] = []
        start_ts = state.first_ts if state.first_ts is not None else (state.last_ts or 0.0)
        for idx, chunk in enumerate(chunks):
            ts = start_ts + idx * TIMESTAMP_EPSILON
            packets.extend(self._emit_chunk(flow, side, chunk, ts))
        state.first_ts = start_ts + len(chunks) * TIMESTAMP_EPSILON if state.splitter.has_pending() else None
        if final:
            self._log_accounting(flow, side)
        return packets

    def _emit_chunk(self, flow: Flow, side: str, chunk: Chunk, ts: float) -> List[PacketRecord]:
        payload = chunk.data
        if not payload:
            return self._ensure_warmup(flow, ts)
        if chunk.kind == "frame" and chunk.header:
            frame_payload = payload[9:]
            if self._seed_grpc and not flow.seed_grpc_done and frame_has_grpc_evidence(chunk.header.frame_type, frame_payload):
                flow.grpc_evidence = True
        packets = self._ensure_warmup(flow, ts)
        state = flow.sides[side]
        peer = flow.peer(side)
        seq = flow.next_seq[side]
        ack = flow.next_seq[peer]
        for offset in range(0, len(payload), MAX_TCP_PAYLOAD):
            part = payload[offset : offset + MAX_TCP_PAYLOAD]
            ts_part = ts + offset * TIMESTAMP_EPSILON
            packets.append(
                self._build_record(flow, side, seq + offset, ack, TCP_FLAG_PSH | TCP_FLAG_ACK, part, ts_part)
            )
        flow.next_seq[side] += len(payload)
        state.out_bytes += len(payload)
        if chunk.kind != "frame":
            reason = "opaque" if chunk.kind == "opaque" else "trailing"
            self._logger.warning("unix flow %s flushed %d %s bytes", flow.inode, len(payload), reason)
        return packets

    def _ensure_warmup(self, flow: Flow, ts: float) -> List[PacketRecord]:
        packets: List[PacketRecord] = []
        if not flow.handshake_done:
            packets.extend(self._emit_handshake(flow, ts))
        if self._seed_http2 and not flow.seed_http2_done:
            packets.extend(self._emit_http2_seed(flow, ts))
        if self._seed_grpc and flow.grpc_evidence and not flow.seed_grpc_done:
            packets.extend(self._emit_grpc_seed(flow, ts))
        return packets

    def _emit_handshake(self, flow: Flow, ts: float) -> List[PacketRecord]:
        base = max(ts - 3 * HANDSHAKE_DELTA, 0.0)
        seq_a = flow.next_seq["A"]
        seq_b = flow.next_seq["B"]
        steps = (
            ("A", seq_a, 0, TCP_FLAG_SYN, base),
            ("B", seq_b, seq_a + 1, TCP_FLAG_SYN | TCP_FLAG_ACK, base + HANDSHAKE_DELTA),
            ("A", seq_a + 1, seq_b + 1, TCP_FLAG_ACK, base + 2 * HANDSHAKE_DELTA),
        )
        packets = [self._build_record(flow, side, seq, ack, flags, b"", when) for side, seq, ack, flags, when in steps]
        flow.next_seq["A"] = seq_a + 1
        flow.next_seq["B"] = seq_b + 1
        flow.handshake_done = True
        return packets

    def _emit_http2_seed(self, flow: Flow, ts: float) -> List[PacketRecord]:
        schedule = (
            ("A", HTTP2_CLIENT_SEED, 0),
            ("B", HTTP2_SETTINGS_ACK_FRAME, 1),
            ("A", HTTP2_SETTINGS_ACK_FRAME, 2),
        )
        packets: List[PacketRecord] = []
        for side, payload, index in schedule:
            send_ts = max(ts - (len(schedule) - 1 - index) * TIMESTAMP_EPSILON, 0.0)
            packets.append(
                self._build_record(
                    flow,
                    side,
                    flow.next_seq[side],
                    flow.next_seq[flow.peer(side)],
                    TCP_FLAG_PSH | TCP_FLAG_ACK,
                    payload,
                    send_ts,
                )
            )
            flow.next_seq[side] += len(payload)
        flow.seed_http2_done = True
        return packets

    def _emit_grpc_seed(self, flow: Flow, ts: float) -> List[PacketRecord]:
        packets = [
            self._build_record(
                flow,
                "A",
                flow.next_seq["A"],
                flow.next_seq["B"],
                TCP_FLAG_PSH | TCP_FLAG_ACK,
                GRPC_HEADERS_FRAME,
                max(ts - TIMESTAMP_EPSILON, 0.0),
            )
        ]
        flow.next_seq["A"] += len(GRPC_HEADERS_FRAME)
        flow.seed_grpc_done = True
        return packets

    def _log_accounting(self, flow: Flow, side: str) -> None:
        state = flow.sides[side]
        if state.accounted:
            return
        delta = state.in_bytes - state.out_bytes
        level = logging.INFO if delta == 0 else logging.WARNING
        self._logger.log(
            level,
            "unix flow %s side %s delivered %d/%d bytes (delta=%d)",
            flow.inode,
            side,
            state.out_bytes,
            state.in_bytes,
            delta,
        )
        state.accounted = True

    def _build_record(
        self,
        flow: Flow,
        side: str,
        seq: int,
        ack: int,
        flags: int,
        payload: bytes,
        ts: float,
    ) -> PacketRecord:
        endpoint = flow.client if side == "A" else flow.server
        peer = flow.server if side == "A" else flow.client
        ethernet = peer.mac + endpoint.mac + ETHERTYPE_IPV4.to_bytes(2, "big")
        self._ip_id = (self._ip_id + 1) & 0xFFFF
        tcp_header = build_tcp_header(endpoint.ip, peer.ip, endpoint.port, peer.port, seq, ack, flags, payload)
        ip_header = build_ipv4_header(endpoint.ip, peer.ip, len(tcp_header) + len(payload), self._ip_id)
        packet = ethernet + ip_header + tcp_header + payload
        ts_sec, ts_usec = _split_ts(ts)
        return PacketRecord(ts_sec=ts_sec, ts_usec=ts_usec, data=packet)


def _split_ts(ts: float) -> Tuple[int, int]:
    if ts < 0:
        ts = 0.0
    sec = int(ts)
    usec = int(round((ts - sec) * 1_000_000))
    if usec >= 1_000_000:
        sec += 1
        usec -= 1_000_000
    return sec, usec
