import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _run_converter(tmp_path: Path, name: str, lines) -> Path:
    pcap_path = tmp_path / name
    cmd = [
        sys.executable,
        'py_strace2pcap.py',
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


def test_inet_payload_passthrough(tmp_path):
    client = '1234 1760606087.50 write(3<TCP:[424242] 127.0.0.1:40000->127.0.0.1:80>,"\\x41\\x42\\x43", 3) = 3'
    server = '1234 1760606087.51 read(3<TCP:[424242] 127.0.0.1:40000->127.0.0.1:80>,"\\x44\\x45\\x46", 3) = 3'
    pcap_path = _run_converter(tmp_path, 'inet.pcap', [client, server])
    packets = _read_pcap(pcap_path)
    assert len(packets) == 2
    assert any(b'ABC' in data for _, _, data in packets)
    assert any(b'DEF' in data for _, _, data in packets)
