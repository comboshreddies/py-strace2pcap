#!/usr/bin/env python3
""" tool for converting strace format to synthetic pcap
    1) pip3 install scapy
    2) strace -f -s65535 -o /tmp/straceSample -ttt -T -yy command
    3) py_strace2pcap.py file_to_store.pcap < /tmp/straceSample
    4) wireshark file_to_store.pcap """


from scapy.all import RawPcapWriter
from strace_parser import StraceParser
from strace_parser_2_packet import StraceParser2Packet
from process_cascade import ProcessCascade


if __name__ == '__main__':
    import sys

    if len(sys.argv) != 2:
        print("provide no arguments or pcap_filename argument")
        sys.exit(1)

    pktdump = RawPcapWriter(sys.argv[1])

    for packet in ProcessCascade(
            StraceParser2Packet, ProcessCascade(StraceParser, sys.stdin)):
        pktdump.write(packet)
