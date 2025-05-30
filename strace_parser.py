""" strace -o /tmp/<file> -f -yy -ttt -xx -T parser """


class FileDescriptorTracker():
    """ pid-fd tracker helper class """

    def __init__(self):
        self.fd_track = {}

    def start_track(self, key):
        """ start tracking if not tracked """
        if key not in self.fd_track:
            self.fd_track[key] = 1

    def increase(self, key):
        """ closed fd arrived, increase fd track counter """
        if key in self.fd_track:
            self.fd_track[key] += 1
            return self.fd_track[key]
        return False

    def get(self, key):
        """ get current fd track counter """
        if key in self.fd_track:
            return self.fd_track[key]
        return False


class UnfinishedResume():
    """ keep track of unfinished lines """

    def __init__(self):
        self.unfinish_resume = {}

    def store_line(self, key, args):
        """ store unfinished line """
        self.unfinish_resume[key] = ' '.join(args[:-2])

    def reconstruct_resumed(self, key, args):
        """ return reconstructed unfinished/resumed line """
        if key in self.unfinish_resume:
            # reconstruct strace line
            new_line = self.unfinish_resume[key] + '"' + ' '.join(args[4:])[9:]
            del self.unfinish_resume[key]
            return new_line
        return False


class StraceParser():
    """ strace parser class """

    syscalls_all = [
        'sendto', 'recvfrom', 'recvmsg', 'read',
        'write', 'sendmsg', 'close', 'shutdown']
    protocols = ['TCP', 'UDP', 'TCPv6', 'UDPv6']
    protocols_ipv6 = ['TCPv6', 'UDPv6']
    protocols_ipv4 = ['TCP', 'UDP']

    syscalls_format = {}
    syscalls_format['single_chunk_payload'] = ['sendto', 'recvfrom', 'read', 'write']
    syscalls_format['vector_payload'] = ['sendmsg', 'recvmsg']
    syscalls_format['state'] = ['close', 'shutdown']
    syscalls_out = ['write', 'sendto', 'sendmsg']
    syscalls_in = ['read', 'recvfrom', 'recvmsg']
    syscalls_broken = ['sendto']

    # there are more E-messages
    nop_results = ['EAGAIN', 'EINPROGRESS', 'EBADF', 'ECONNRESET']

    split_cache_packet = {}
    scapy_max_payload = 65480

    def __init__(self):
        self.fd_track = FileDescriptorTracker()
        self.syscall_track = UnfinishedResume()

    def has_split_cache(self):
        """ checks is there cached packet object """
        if self.split_cache_packet:
            return True
        return False

    def get_split_cache(self):
        """ returns cached packet object """
        full_payload = self.split_cache_packet['payload']
        parsed = dict(self.split_cache_packet)
        if len(full_payload) > self.scapy_max_payload:
            parsed['payload'] = full_payload[:self.scapy_max_payload]
            self.split_cache_packet = dict(parsed)
            self.split_cache_packet['payload'] = full_payload[self.scapy_max_payload:]
        else:
            parsed['payload'] = full_payload
            self.split_cache_packet = {}
        return parsed

    def is_stop_or_signal_line(self, line_args):
        """ is this line with exit and signals """
        if line_args[2] == '+++':
            return True
        return False

    def is_unwanted_resumed_syscall(self, args):
        """ skip unwanted resumed sycalls """
        if args[2] == '<...' and not args[3] in self.syscalls_all:
            return True
        return False

    def is_unwanted_syscall(self, args):
        """ skip unwanted syscalls, arg2 syscall """
        syscall = args[2].split('(')[0]
        if args[2] != '<...' and syscall not in self.syscalls_all:
            return True
        return False

    def is_error_return_code(self, raw_line):
        """ if return code is -1 and belongs to nop_results """
        if (len(raw_line.split(')')) > 1 and
                len(raw_line.split(')')[1].split(' ')) > 3 and
                raw_line.split(')')[1].split(' ')[3] in self.nop_results):
            return True
        return False

    def is_unwanted_protocol(self, line_args):
        """ is this unwanted protocol """
        if len(line_args[2].split('<')) > 1:
            protocol = line_args[2].split('<')[1].split(':')[0]
            # do not prase unwanted protocols
            if line_args[2] != '<...' and protocol not in self.protocols:
                return True
        return False

    def is_unfinished(self, args):
        """ is line with unfinished syscall """
        return (args[-2] == '<unfinished' and args[-1][:-1] == '...>')

    def is_resumed(self, args):
        """ is line with resumed syscall """
        return (args[2] == '<...' and args[4][0:7] == 'resumed')

    def filter_and_reconstruct_line(self, parse_line):
        """ filter non wanted lines, reconstruct resumed, or return wanted lines """
        args = parse_line.split(' ')
        if args[1]:
            new_line = parse_line
        else:  # strace version 6 put 2 blanks after pid
            while args[1] == '':
                del args[1]
        new_line = ' '.join(args)

        pid = int(args[0])
        syscall = args[2].split('(')[0]
        if (self.is_stop_or_signal_line(args) or
                self.is_unwanted_resumed_syscall(args) or
                self.is_unwanted_syscall(args) or
                self.is_error_return_code(parse_line) or
                self.is_unwanted_protocol(args)):
            return False

        if self.is_unfinished(args):
            key = f'{pid}-{syscall}'
            self.syscall_track.store_line(key, args)
            return False

        if self.is_resumed(args):
            resumed_syscall = args[3]
            key = f'{pid}-{resumed_syscall}'
            return self.syscall_track.reconstruct_resumed(key, args)

        return new_line

    def get_payload_chunk(self, syscall, args):
        """ scape payload from multiple payload strace encodings """
        payload = ""
        if syscall in self.syscalls_format['single_chunk_payload']:
            payload = args[3].split('"')[1]

        if syscall in self.syscalls_format['vector_payload']:
            vector = ' '.join(args[3:-4])
            msg_iov = vector.split('[')[1].split(']')[0]
            chunks = msg_iov.split('"')
            for segment in range(1, len(chunks), 2):
                payload += chunks[segment]
        return payload

    def parse_tcpip_v4(self, tcpip_chunk, syscall, args):
        """ from strace fd part that has tcpip content, parse src/dst ip/port
            content may be srcip:srcport->dstip:dstport or
            number, and if it's a number, we return 127.0.0.x """
        if '->' in tcpip_chunk:
            first_ip = tcpip_chunk.split(':')[0]
            first_port = int(tcpip_chunk.split(':')[1].split('-')[0])
            second_ip = tcpip_chunk.split('>')[1].split(':')[0]
            second_port = int(tcpip_chunk.split('>')[1].split(':')[1])
        else:
            # set fake tcpip data, as real tcpip is partial or missing
            first_ip = '127.0.0.1'
            first_port = 11111
            second_ip = '127.0.0.2'
            second_port = 22222
            # in some cases, on some systemcalls, there is sockaddr at the end
            if syscall in self.syscalls_broken:
                reconstruct_line = ' '.join(args)
                brace_section = reconstruct_line.split('{')
                if not len(brace_section) > 1:
                    return False
                sockaddr_part = brace_section[1].split('}')[0]
                second_port = int(sockaddr_part.split('sin_port=htons(')[1].split(')')[0])
                second_ip_hex = sockaddr_part.split('sin_addr=inet_addr("')[1].split('"')[0]
                if second_ip_hex[0] == '\\':
                    second_ip = ""
                    for i in ",0x".join(second_ip_hex.split('\\x'))[1:].split(','):
                        second_ip += chr(int(i, 16))
                    # in such cases, close might contain source port,
                    # so we could recollect it
                    # but we have to track all previous usage of this pid-fd
                else:
                    second_ip = second_ip_hex
        return [first_ip, first_port, second_ip, second_port]

    def sorted_tcpip_v4_params(self, syscall, net_info, args):
        """ parse tcpip and put in right order src/dst for pcap """
        parsed_tcpip = self.parse_tcpip_v4(net_info, syscall, args)
        if not parsed_tcpip:
            return False
        (first_ip, first_port, second_ip, second_port) = parsed_tcpip
        if syscall in self.syscalls_out:
            return [first_ip, first_port, second_ip, second_port]
        return [second_ip, second_port, first_ip, first_port]

    def parse_tcpip_v6(self, tcpip_chunk):
        """ from strace fd part that has tcpip content, parse src/dst ip/port
            content may be srcip:srcport->dstip:dstport or
            number, and if it's a number, we return 127.0.0.x """
        if '->' in tcpip_chunk:
            first_part = tcpip_chunk.split('->')[0][1:]
            first_ip = first_part.split(']')[0]
            first_port = int(first_part.split(':')[-1])
            second_part = tcpip_chunk.split('->')[1][1:]
            second_ip = second_part.split(']')[0]
            second_port = int(second_part.split(':')[-1])
        else:
            # set fake tcpip data, as real tcpip is partial or missing
            first_ip = '::ffff:127.0.0.1'
            first_port = 11111
            second_ip = '::ffff:127.0.0.2'
            second_port = 22222
            # in some cases, on some systemcalls, there is sockaddr at the end
            # yet I do not have strace example of such
        return [first_ip, first_port, second_ip, second_port]

    def sorted_tcpip_v6_params(self, syscall, net_info):
        """ parse tcpip and put in right order src/dst for pcap """
        parsed_tcpip = self.parse_tcpip_v6(net_info)
        if not parsed_tcpip:
            return False
        (first_ip, first_port, second_ip, second_port) = parsed_tcpip
        if syscall in self.syscalls_out:
            return [first_ip, first_port, second_ip, second_port]
        return [second_ip, second_port, first_ip, first_port]

    def bytes_code_payload(self, line_payload):
        """ convert payload to bytes code """
        # strace hex code \xab to 0xab
        hex_payload = ",0x".join(line_payload.split('\\x'))[1:]
        # from 0xAB coded payload, create bytes stored payload
        p = []
        for i in hex_payload.split(','):
            if i:
                p.append(int(i, 16))
        return bytes(p)

    def parse_strace_line(self, strace_line):
        """ decode strace line to a structure, or return False """
        if not strace_line:
            return False
        unified_line = self.filter_and_reconstruct_line(strace_line)
        if not unified_line:
            return False
        parsed = {}
        args = unified_line.split(' ')

        if len(args[2].split('<')) > 1:
            parsed['protocol'] = args[2].split('<')[1].split(':')[0]
        else:
            return False

        parsed['pid'] = int(args[0])
        parsed['syscall'] = args[2].split('(')[0]

        if parsed['syscall'] in self.syscalls_out:
            parsed['direction_out'] = True
        else:
            parsed['direction_out'] = False

        parsed['fd'] = int(args[2].split('(')[1].split('<')[0])
        parsed['time'] = args[1]

        # parase ip address encoded in strace fd argument
        # net_info = args[2].split('[')[1].split(']')[-1]
        net_info = ']'.join('['.join(args[2].split('[')[1:]).split(']')[0:-1])

        net_parse = False
        if parsed['protocol'] in self.protocols_ipv4:
            net_parse = self.sorted_tcpip_v4_params(parsed['syscall'], net_info, args)
        if parsed['protocol'] in self.protocols_ipv6:
            net_parse = self.sorted_tcpip_v6_params(parsed['syscall'], net_info)

        if not net_parse:
            return False

        (parsed['source_ip'], parsed['source_port'], parsed['destination_ip'],
            parsed['destination_port']) = net_parse

        # start tracking first occurrence of pid-fd pair
        track_key = f"{parsed['pid']}-{parsed['fd']}"
        self.fd_track.start_track(track_key)

        # if syscall is close, fd is closed, incrase fd_track for pid-fd key
        if parsed['syscall'] in self.syscalls_format['state']:
            self.fd_track.increase(track_key)
            # recollect partially coded udp
            # if ':[' in args[2] and not '->' in args[2]:
            #    src_tcpip = args[2].split('[')[1].split(']')[0]
            #    src_port = src_tcpip.split(':')[1]
            #    src_addr = src_tcpip.split(':')[0]
            return False

        # TCP session unique number, ie count of different connections with same pair pid-fd
        parsed['session'] = self.fd_track.get(track_key)

        payload = self.get_payload_chunk(parsed['syscall'], args)

        full_payload = self.bytes_code_payload(payload)
        if len(full_payload) > self.scapy_max_payload:
            parsed['payload'] = full_payload[:self.scapy_max_payload]
            self.split_cache_packet = dict(parsed)
            self.split_cache_packet['payload'] = full_payload[self.scapy_max_payload:]
        else:
            parsed['payload'] = full_payload
        return parsed

    def process(self, pline):
        """ call to reserved process method, used by higher level generator """
        return self.parse_strace_line(pline)
