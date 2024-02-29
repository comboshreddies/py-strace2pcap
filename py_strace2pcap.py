#!/usr/bin/env python3
""" tool for converting strace format to synthetic pcap
    1) pip3 install scapy
    2) strace -f -s65535 -o /tmp/straceSample -tt -T -yy -xx command
    3) py_strace2pcap.py file_to_store.pcap < /tmp/straceSample
    4) wireshark file_to_store.pcap """

from scapy.all import Ether, IP, TCP, UDP, PcapWriter

syscalls_all = ['sendto', 'recvfrom', 'recvmsg', 'read', 'write', 'sendmsg', 'close', 'shutdown']
protocols = ['TCP', 'UDP']

syscalls_format = {}
syscalls_format['single_chunk_payload'] = ['sendto', 'recvfrom', 'read', 'write']
syscalls_format['vector_payload'] = ['sendmsg', 'recvmsg']
syscalls_format['state'] = ['close', 'shutdown']
syscalls_out=['write', 'sendto', 'sendmsg']
syscalls_in=['read', 'recvfrom', 'recvmsg']

# there are more E-messages
nop_results = ['EAGAIN','EINPROGRESS','EBADF']

op_encode = {}
op_encode['read'] = 1
op_encode['write'] = 2
op_encode['sendmsg'] = 3
op_encode['recvmsg'] = 4
op_encode['recvfrom'] = 5
op_encode['sendto'] = 6
op_encode['close'] = 7

fd_track = {}
unfinish_resume = {}
sequence = {}


def encode_decimal2mac(enc):
    """ encode int to mac, we're econding pid , fd , steram and such """
    mac6 = (enc)%100
    mac5 = int(enc / 100) % 100
    mac4 = int(enc / 10000) % 100
    mac3 = int(enc / 1000000) % 100
    mac2 = int(enc / 100000000) % 100
    mac1 = int(enc / 10000000000)
    return f"{mac1:#04x}:{mac2:#04x}:{mac3:#04x}:{mac4:#04x}:{mac5:#04x}:{mac6:#04x}"

def is_stop_or_signal_line(line_args):
    """ is this line with exit and signals """
    if line_args[2] == '+++' :
        return True
    return False

def is_unwanted_resumed_syscall(args):
    """ skip unwanted resumed sycalls """
    if args[2] == '<...' and not args[3] in syscalls_all :
        return True
    return False

def is_unwanted_syscall(args):
    """ skip unwanted syscalls, arg3 syscall """
    syscall =  args[2].split('(')[0]
    if args[2] != '<...' and not syscall in syscalls_all :
        return True
    return False

def is_error_return_code(raw_line):
    """ if return code is -1 and belongs to nop_results """
    if len(raw_line.split(')')) > 1 and \
       len(raw_line.split(')')[1].split(' ')) > 3 and \
       raw_line.split(')')[1].split(' ')[3] in nop_results :
        return True
    return False

def is_unwanted_protocol(line_args):
    """ is this unwanted protocol """
    if len(line_args[2].split('<')) > 1 :
        protocol = line_args[2].split('<')[1].split(':')[0]
        # do not prase unwanted protocols
        if line_args[2] != '<...' and not protocol in protocols:
            return True
    return False

def is_unfinished(args):
    """ is line with unfinished syscall """
    return (args[-2] == '<unfinished' and args[-1][:-1] == '...>' )

def store_unfinished_line(pid, syscall, args):
    """ store unfinished line """ 
    key = f'{pid}-{syscall}'
    unfinish_resume[key] = ' '.join(args[:-2])

def is_resumed(args):
    """ is line with resumed syscall """
    return (args[2] == '<...' and args[4][0:7] == 'resumed' )

def reconstruct_resumed(pid, args):
    """ return reconstructed unfinished/resumed line """ 
    resumed_syscall = args[3]
    key = f'{pid}-{resumed_syscall}'
    if key in unfinish_resume :
        # reconstruct strace line
        new_line = unfinish_resume[key] + '"' + ' '.join(args[4:])[9:]
        del unfinish_resume[key]
        return new_line
    return False

def filter_and_reconstruct_line(parse_line):
    """ filter non wanted lines, reconstruct resumed, or return wanted lines """
    args = parse_line.split(' ')
    pid = int(args[0])
    syscall = args[2].split('(')[0]

    if is_stop_or_signal_line(args) or \
       is_unwanted_resumed_syscall(args) or \
       is_unwanted_syscall(args) or \
       is_error_return_code(parse_line) or \
       is_unwanted_protocol(args) :
        return False

    if is_unfinished(args) :
        store_unfinished_line(pid,syscall,args)
        return False

    if is_resumed(args) :
        return reconstruct_resumed(pid, args)

    return parse_line

def get_payload_chunk(syscall,args):
    """ scape payload from multiple payload strace encodings """
    payload = ""
    if syscall in syscalls_format['single_chunk_payload'] :
        payload = args[3].split('"')[1]

    if syscall in syscalls_format['vector_payload'] :
        vector = ' '.join(args[3:-4])
        msg_iov = vector.split('[')[1].split(']')[0]
        chunks = msg_iov.split('"')
        for segment in range(1, len(chunks),2) :
            payload += chunks[segment]
    return payload

def parse_tcpip(tcpip_chunk):
    """ from strace fd part that has tcpip content, parse srd/dst ip/port
        content may be srcip:srcport->dstip:dstport or
        number, and if it's a number, we return 127.0.0.x """
    if '->' in tcpip_chunk :
        first_ip = tcpip_chunk.split(':')[0]
        first_port = int(tcpip_chunk.split(':')[1].split('-')[0])
        second_ip = tcpip_chunk.split('>')[1].split(':')[0]
        second_port = int(tcpip_chunk.split('>')[1].split(':')[1])
    else :
        first_ip = '127.0.0.1'
        first_port = 11111
        second_ip = '127.0.0.2'
        second_port = 22222
    return [first_ip,first_port,second_ip,second_port]

def sorted_tcpip_params(syscall, net_info):
    """ parse tcpip and put in right order src/dst for pcap """
    (first_ip,first_port,second_ip,second_port) = parse_tcpip(net_info)
    if  syscall in syscalls_out :
        return [first_ip,first_port,second_ip,second_port]
    else :
        return [second_ip,second_port,first_ip,first_port]

def bytes_code_payload(line_payload):
    """ convert payload to bytes code """
    # strace hex code \xab to 0xab
    hex_payload = ",0x".join(line_payload.split('\\x'))[1:]
    # from 0xAB coded payload, create bytes stored payload
    p=[]
    for i in hex_payload.split(',') :
        p.append(int(i, 16))
    return bytes(p)

def parse_strace_line(strace_line):
    """ decode strace line to a structure, or return False """
    unified_line = filter_and_reconstruct_line(strace_line)
    if not unified_line :
        return False

    parsed_line = {}
    args = unified_line.split(' ')

    if len(args[2].split('<')) > 1 :
        parsed_line['protocol'] = args[2].split('<')[1].split(':')[0]
    else :
        return False

    parsed_line['pid'] = int(args[0])
    parsed_line['syscall'] = args[2].split('(')[0]

    parsed_line['fd'] = int(args[2].split('(')[1].split('<')[0])
    parsed_line['time'] = args[1]

    # parase ip address encoded in strace fd argument
    net_info = args[2].split('[')[1].split(']')[0]
    (parsed_line['source_ip'],parsed_line['source_port'],parsed_line['destination_ip'], \
       parsed_line['destination_port']) = sorted_tcpip_params(parsed_line['syscall'],net_info)

    # start tracking first occurance of pid-fd pair
    track_key = f"{parsed_line['pid']}-{parsed_line['fd']}"
    if not track_key in fd_track :
        fd_track[track_key] = 1

    # if syscall is close, fs is closed incrase fd_track for pid-fd key
    if parsed_line['syscall'] in syscalls_format['state'] :
        if track_key in fd_track :
            fd_track[track_key] += 1
        return False

    # TCP session unique number, ie count of different connections with same pair pid-fd
    parsed_line['session'] = fd_track[track_key]

    payload = get_payload_chunk(parsed_line['syscall'], args)
    parsed_line['payload'] = bytes_code_payload(payload)

    return parsed_line

def generate_sequence(c):
    """ generate sequence """
    return (c['fd']*100 + c['pid']*10000 + c['session']) % 4294967295

def generate_sequence_key(c):
    """ generate sequence_key """
    return  f"{c['source_ip']}:{c['source_port']}_{c['destination_ip']}:{c['destination_port']}_{c['pid']}:{c['fd']}{c['session']}"

def generate_tcp_packet(src_mac,dst_mac,p):
    """ generate tcp packet """
    seq_key = generate_sequence_key(p)
    if not seq_key in sequence:
        # encode sequence with fd, pid, and session
        sequence[seq_key] = generate_sequence(p)
    tcp_packet = Ether(src=src_mac, dst=dst_mac) / \
        IP(src=p['source_ip'], dst=p['destination_ip']) / \
        TCP(flags='PA', sport=p['source_port'], dport=p['destination_port'], seq=sequence[seq_key]) / \
        p['payload']
    if seq_key in sequence:
        sequence[seq_key]+=len(p['payload'])
    return tcp_packet

def generate_udp_packet(src_mac,dst_mac,p):
    """ generate udp packet """
    return Ether(src=src_mac, dst=dst_mac) / \
        IP(src=p['source_ip'], dst=p['destination_ip']) / \
        UDP(sport=p['source_port'], dport=p['destination_port']) / \
        p['payload']

def generate_pcap_packet(c):
    """ from parsed content generate pcap packet """
    if c :
        # encode pid to source mac
        source_mac = encode_decimal2mac(c['pid'])
        # encode fd, operation and session
        destination_mac = encode_decimal2mac(c['fd']+10000000000*op_encode[c['syscall']]+10000000*c['session'])
        if c['protocol'] == "TCP" :
            return generate_tcp_packet(source_mac, destination_mac, c)
        if c['protocol'] == "UDP" :
            return generate_udp_packet(source_mac, destination_mac, c)
    return False


if __name__ == '__main__':
    import sys

    if len(sys.argv) != 2 :
        print("first argument is pcap file name")
        sys.exit(1)

    pktdump = PcapWriter(sys.argv[1], append=True, sync=True)

    for line in sys.stdin:
        packet = generate_pcap_packet(parse_strace_line(line))
        if packet :
            pktdump.write(packet)
