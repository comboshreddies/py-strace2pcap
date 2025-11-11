#!/usr/bin/env python3
""" tool for converting strace format to synthetic pcap
    1) pip3 install scapy
    2) strace -f -s65535 -o /tmp/straceSample -ttt -T -yy command
    3) py_strace2pcap.py file_to_store.pcap < /tmp/straceSample
    4) wireshark file_to_store.pcap """

import inspect

from scapy.all import RawPcapWriter

from strace_parser import StraceParser
from strace_parser_2_packet import StraceParser2Packet
from unix_tcp_synth import UnixTCPManager


def _write_record(pktdump, record):
    """Write a raw packet record, handling scapy compatibility quirks."""

    if not getattr(pktdump, "header_present", False):
        pktdump._write_header(None)
    kwargs = {
        "sec": record.ts_sec,
        "usec": record.ts_usec,
        "caplen": len(record.data),
        "wirelen": len(record.data),
    }
    try:
        pktdump.write_packet(record.data, **kwargs)
    except TypeError:
        # Older scapy releases expect the linktype positional argument.
        params = inspect.signature(pktdump._write_packet).parameters
        if "linktype" in params:
            kwargs["linktype"] = getattr(pktdump, "linktype", None)
        pktdump._write_packet(record.data, **kwargs)




def _iterate_events(strace_parser, stream):
    for line in stream:
        event = strace_parser.process(line)
        while event:
            yield event
            if strace_parser.has_split_cache():
                event = strace_parser.get_split_cache()
            else:
                break


if __name__ == '__main__':
    import argparse
    import sys

    parser = argparse.ArgumentParser(description='Convert strace output to PCAP')
    parser.add_argument('pcap_filename')

    def _add_boolean_flag(flag: str, *, default: bool, enable_help: str, disable_help: str) -> None:
        dest = flag.lstrip('-').replace('-', '_')
        if hasattr(argparse, 'BooleanOptionalAction'):
            parser.add_argument(
                flag,
                action=argparse.BooleanOptionalAction,
                default=default,
                help=enable_help,
            )
        else:  # pragma: no cover - Python <3.9 fallback
            group = parser.add_mutually_exclusive_group()
            group.add_argument(flag, dest=dest, action='store_true', help=enable_help)
            group.add_argument(f"--no-{flag.lstrip('-')}", dest=dest, action='store_false', help=disable_help)
            parser.set_defaults(**{dest: default})

    _add_boolean_flag(
        '--capture-unix-socket',
        default=False,
        enable_help='Enable synthetic TCP capture for AF_UNIX stream sockets',
        disable_help='Disable synthetic TCP capture for AF_UNIX stream sockets',
    )
    _add_boolean_flag(
        '--capture-net',
        default=True,
        enable_help='Enable capture of AF_INET/AF_INET6 sockets (default: enabled)',
        disable_help='Disable capture of AF_INET/AF_INET6 sockets',
    )
    parser.add_argument(
        '--seed-http2',
        action='store_true',
        default=False,
        help='Seed UNIX TCP flows with the HTTP/2 client preface and SETTINGS frames',
    )
    parser.add_argument(
        '--seed-grpc',
        action='store_true',
        default=False,
        help='Seed UNIX TCP flows with a gRPC HEADERS frame when evidence is observed (requires --seed-http2)',
    )

    args = parser.parse_args()

    if args.seed_grpc and not args.seed_http2:
        parser.error('--seed-grpc requires --seed-http2')

    linktype_value = 1  # DLT_EN10MB
    inet_linktype = 'ether'

    pktdump = RawPcapWriter(args.pcap_filename, linktype=linktype_value)

    strace_parser = StraceParser()
    inet_packetizer = StraceParser2Packet() if args.capture_net else None
    unix_manager = None
    if args.capture_unix_socket:
        unix_manager = UnixTCPManager(
            seed_http2=args.seed_http2,
            seed_grpc=args.seed_grpc,
        )

    for event in _iterate_events(strace_parser, sys.stdin):
        if not event:
            continue
        protocol = event.get('protocol')
        if protocol and protocol.startswith('UNIX'):
            if not unix_manager:
                continue
            if protocol != 'UNIX-STREAM':
                continue
            for record in unix_manager.handle_event(event):
                _write_record(pktdump, record)
            continue
        if not inet_packetizer:
            continue
        packet = inet_packetizer.process(event)
        if packet:
            pktdump.write(packet)

    if unix_manager:
        for record in unix_manager.flush():
            _write_record(pktdump, record)
