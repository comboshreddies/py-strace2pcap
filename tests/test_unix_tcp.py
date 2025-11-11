import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from grpc_seed import GRPC_HEADERS_FRAME, HTTP2_CLIENT_SEED, HTTP2_SETTINGS_ACK_FRAME  # type: ignore  # pylint: disable=import-error

TCP_FLAG_PSH = 0x08
TCP_FLAG_FIN = 0x01


def _escape(data: bytes) -> str:
    return ''.join('\\x{:02x}'.format(b) for b in data)


def _run_converter(tmp_path: Path, name: str, lines, *extra_args) -> Path:
    pcap_path = tmp_path / name
    cmd = [
        sys.executable,
        'py_strace2pcap.py',
        '--capture-unix-socket',
        '--no-capture-net',
        *extra_args,
        str(pcap_path),
    ]
    payload = '\n'.join(lines) + '\n'
    subprocess.run(cmd, input=payload, text=True, check=True)
    return pcap_path


def _read_pcap(path: Path):
    packets = []
    with path.open('rb') as fh:
        header = fh.read(24)
        magic, _, _, _, _, _, network = struct.unpack('<IHHIIII', header)
        assert magic == 0xA1B2C3D4
        assert network == 1
        while True:
            pkt_hdr = fh.read(16)
            if not pkt_hdr:
                break
            ts_sec, ts_usec, incl_len, _ = struct.unpack('<IIII', pkt_hdr)
            packets.append((ts_sec, ts_usec, fh.read(incl_len)))
    return packets


def _tcp_header_slice(pkt):
    ihl = (pkt[14] & 0x0F) * 4
    tcp_offset = 14 + ihl
    data_offset = (pkt[tcp_offset + 12] >> 4) * 4
    return tcp_offset, data_offset


def _tcp_flags(pkt):
    tcp_offset, _ = _tcp_header_slice(pkt)
    return struct.unpack('!H', pkt[tcp_offset + 12:tcp_offset + 14])[0] & 0x01FF


def _tcp_ports(pkt):
    tcp_offset, _ = _tcp_header_slice(pkt)
    return struct.unpack('!HH', pkt[tcp_offset:tcp_offset + 4])


def _tcp_payload(pkt):
    tcp_offset, data_offset = _tcp_header_slice(pkt)
    return pkt[tcp_offset + data_offset:]


def _tcp_checksum(pkt):
    tcp_offset, _ = _tcp_header_slice(pkt)
    return struct.unpack('!H', pkt[tcp_offset + 16:tcp_offset + 18])[0]


def test_frame_alignment_and_close(tmp_path):
    client_frame = b'\x00\x00\x05\x00\x01\x00\x00\x00\x01HELLO'
    server_frame = b'\x00\x00\x03\x00\x01\x00\x00\x00\x01ACK'
    lines = [
        f"1234 1760606087.10 write(54<UNIX-STREAM:[1606248]>, \"{_escape(client_frame[:5])}\", 5) = 5",
        f"1234 1760606087.10 write(54<UNIX-STREAM:[1606248]>, \"{_escape(client_frame[5:])}\", {len(client_frame) - 5}) = {len(client_frame) - 5}",
        f"1234 1760606087.10 read(54<UNIX-STREAM:[1606248]>, \"{_escape(server_frame)}\", {len(server_frame)}) = {len(server_frame)}",
        "1234 1760606087.10 close(54<UNIX-STREAM:[1606248]>) = 0",
    ]
    pcap_path = _run_converter(tmp_path, 'aligned.pcap', lines)
    packets = _read_pcap(pcap_path)
    data_packets = [pkt for _, _, pkt in packets if _tcp_flags(pkt) & TCP_FLAG_PSH]
    assert any(_tcp_payload(pkt) == client_frame for pkt in data_packets)
    assert any(_tcp_payload(pkt) == server_frame for pkt in data_packets)
    assert any(_tcp_flags(pkt) & TCP_FLAG_FIN for _, _, pkt in packets)
    assert _tcp_checksum(data_packets[0]) != 0


def test_seed_http2(tmp_path):
    server_frame = b'\x00\x00\x02\x00\x00\x00\x00\x00\x01OK'
    lines = [
        f"4321 1760606087.20 read(77<UNIX-STREAM:[42]>, \"{_escape(server_frame)}\", {len(server_frame)}) = {len(server_frame)}",
        "4321 1760606087.20 close(77<UNIX-STREAM:[42]>) = 0",
    ]
    pcap_path = _run_converter(tmp_path, 'seed_http2.pcap', lines, '--seed-http2')
    payloads = [_tcp_payload(pkt) for _, _, pkt in _read_pcap(pcap_path) if _tcp_flags(pkt) & TCP_FLAG_PSH]
    assert HTTP2_CLIENT_SEED in payloads
    assert HTTP2_SETTINGS_ACK_FRAME in payloads
    assert server_frame in payloads


def test_seed_grpc_auto(tmp_path):
    grpc_data = b'\x00\x00\x05\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00'
    lines = [
        f"7777 1760606087.30 write(31<UNIX-STREAM:[4242]>, \"{_escape(grpc_data)}\", {len(grpc_data)}) = {len(grpc_data)}",
        "7777 1760606087.30 close(31<UNIX-STREAM:[4242]>) = 0",
    ]
    pcap_path = _run_converter(tmp_path, 'seed_grpc.pcap', lines, '--seed-http2', '--seed-grpc')
    payloads = [_tcp_payload(pkt) for _, _, pkt in _read_pcap(pcap_path) if _tcp_flags(pkt) & TCP_FLAG_PSH]
    assert GRPC_HEADERS_FRAME in payloads
    assert grpc_data in payloads


def test_residual_flush(tmp_path):
    payload = b'PARTIAL'
    lines = [
        f"5555 1760606087.40 write(22<UNIX-STREAM:[888]>, \"{_escape(payload)}\", {len(payload)}) = {len(payload)}",
        "5555 1760606087.40 close(22<UNIX-STREAM:[888]>) = 0",
    ]
    pcap_path = _run_converter(tmp_path, 'residual.pcap', lines)
    payloads = [_tcp_payload(pkt) for _, _, pkt in _read_pcap(pcap_path) if _tcp_flags(pkt) & TCP_FLAG_PSH]
    assert payload in payloads


def test_retval_limits_payload(tmp_path):
    write_payload = b'ABCDEF'
    read_payload = b'GHIJKL'
    lines = [
        f"2024 1760606087.45 write(33<UNIX-STREAM:[1357]>, \"{_escape(write_payload)}\", {len(write_payload)}) = 3",
        f"2024 1760606087.45 read(33<UNIX-STREAM:[1357]>, \"{_escape(read_payload)}\", {len(read_payload)}) = 2",
        "2024 1760606087.45 close(33<UNIX-STREAM:[1357]>) = 0",
    ]
    pcap_path = _run_converter(tmp_path, 'retval.pcap', lines)
    packets = [pkt for _, _, pkt in _read_pcap(pcap_path) if _tcp_flags(pkt) & TCP_FLAG_PSH]
    client_payloads = [_tcp_payload(pkt) for pkt in packets if _tcp_ports(pkt)[1] == 50051]
    server_payloads = [_tcp_payload(pkt) for pkt in packets if _tcp_ports(pkt)[0] == 50051]
    assert client_payloads == [b'ABC']
    assert any(payload == b'GH' for payload in server_payloads)
