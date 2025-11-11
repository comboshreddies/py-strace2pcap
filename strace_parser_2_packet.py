"""Parse strace line to scapy packets."""

from scapy.all import Ether, Dot1Q, IP, IPv6, TCP, UDP, Raw


class StraceParser2Packet():
    """ Strace Parser to scapy Packet """

    op_encode = {}
    op_encode['read'] = 1
    op_encode['write'] = 2
    op_encode['sendmsg'] = 3
    op_encode['recvmsg'] = 4
    op_encode['recvfrom'] = 5
    op_encode['sendto'] = 6
    op_encode['close'] = 7

    def __init__(self, *, linktype: str = 'ether'):
        self.sequence = {}
        self.linktype = linktype
        self.ip_id = 0

    def has_split_cache(self):
        """ cheks is there split cache, but not implemented so False """
        return False

    def get_split_cache(self):
        """return next cached packet"""
        return False

    def encode_decimal2mac(self, enc):
        """ encode int to mac, we're econding pid , fd , steram and such """
        mac6 = (enc) % 100
        mac5 = int(enc / 100) % 100
        mac4 = int(enc / 10000) % 100
        mac3 = int(enc / 1000000) % 100
        mac2 = int(enc / 100000000) % 100
        mac1 = int(enc / 10000000000)
        return f"{mac1:#02d}:{mac2:#02d}:{mac3:#02d}:{mac4:#02d}:{mac5:#02d}:{mac6:#02d}"

    def generate_sequence(self, c):
        """ generate sequence """
        return (c['fd'] * 100 + c['pid'] * 10000 + c['session']) % 4294967296

    def generate_sequence_key(self, c):
        """ generate sequence_key """
        return f"{c['source_ip']}:{c['source_port']}_{c['destination_ip']}:\
            {c['destination_port']}_{c['pid']}:{c['fd']}{c['session']}"

    def _next_ip_id(self):
        self.ip_id = (self.ip_id + 1) % 65536
        return self.ip_id

    def generate_tcp_packet(self, p):
        """ generate tcp packet """
        seq_key = self.generate_sequence_key(p)
        if seq_key not in self.sequence:
            self.sequence[seq_key] = self.generate_sequence(p)
        payload = p['payload']
        base_layer = None
        if self.linktype == 'ether':
            if p['direction_out']:
                source_mac = self.encode_decimal2mac(p['pid'])
                destination_mac = self.encode_decimal2mac(
                    100000000 * self.op_encode[p['syscall']] + p['session'])
            else:
                destination_mac = self.encode_decimal2mac(p['pid'])
                source_mac = self.encode_decimal2mac(
                    100000000 * self.op_encode[p['syscall']] + p['session'])
            base_layer = Ether(src=source_mac, dst=destination_mac) / Dot1Q(vlan=p['fd'])
        ip_layer = IP(src=p['source_ip'], dst=p['destination_ip'])
        if self.linktype != 'ether':
            ip_layer.id = self._next_ip_id()
        tcp_layer = TCP(
            flags='PA', sport=p['source_port'], dport=p['destination_port'],
            seq=self.sequence[seq_key])
        packet = ip_layer / tcp_layer
        if payload:
            packet = packet / Raw(payload)
        packet.time = p['time']
        if base_layer is not None:
            packet = base_layer / packet
            packet.time = p['time']
            packet[Ether].time = p['time']
        self.sequence[seq_key] += len(payload)
        return packet

    def generate_udp_packet(self, p):
        """ generate udp packet """
        payload = p['payload']
        base_layer = None
        if self.linktype == 'ether':
            if p['direction_out']:
                source_mac = self.encode_decimal2mac(p['pid'])
                destination_mac = self.encode_decimal2mac(
                    100000000 * self.op_encode[p['syscall']] + p['session'])
            else:
                destination_mac = self.encode_decimal2mac(p['pid'])
                source_mac = self.encode_decimal2mac(
                    100000000 * self.op_encode[p['syscall']] + p['session'])
            base_layer = Ether(src=source_mac, dst=destination_mac) / Dot1Q(vlan=p['fd'])
        ip_layer = IP(src=p['source_ip'], dst=p['destination_ip'])
        if self.linktype != 'ether':
            ip_layer.id = self._next_ip_id()
        udp_layer = UDP(sport=p['source_port'], dport=p['destination_port'])
        packet = ip_layer / udp_layer
        if payload:
            packet = packet / Raw(payload)
        packet.time = p['time']
        if base_layer is not None:
            packet = base_layer / packet
            packet.time = p['time']
            packet[Ether].time = p['time']
        return packet

    def generate_tcp_packet_v6(self, src_mac, dst_mac, vlan, p):
        """ generate tcp packet """
        seq_key = self.generate_sequence_key(p)
        if seq_key not in self.sequence:
            self.sequence[seq_key] = self.generate_sequence(p)
        payload = p['payload']
        base_layer = None
        if self.linktype == 'ether':
            base_layer = Ether(src=src_mac, dst=dst_mac) / Dot1Q(vlan=vlan)
        ipv6_layer = IPv6(src=p['source_ip'], dst=p['destination_ip'])
        tcp_layer = TCP(
            flags='PA', sport=p['source_port'], dport=p['destination_port'],
            seq=self.sequence[seq_key])
        packet = ipv6_layer / tcp_layer
        if payload:
            packet = packet / Raw(payload)
        packet.time = p['time']
        if base_layer is not None:
            packet = base_layer / packet
            packet.time = p['time']
            packet[Ether].time = p['time']
        self.sequence[seq_key] = (len(payload) + self.sequence[seq_key]) % 4294967296
        return packet

    def generate_udp_packet_v6(self, src_mac, dst_mac, vlan, p):
        """ generate udp packet """
        payload = p['payload']
        base_layer = None
        if self.linktype == 'ether':
            base_layer = Ether(src=src_mac, dst=dst_mac) / Dot1Q(vlan=vlan)
        ipv6_layer = IPv6(src=p['source_ip'], dst=p['destination_ip'])
        udp_layer = UDP(sport=p['source_port'], dport=p['destination_port'])
        packet = ipv6_layer / udp_layer
        if payload:
            packet = packet / Raw(payload)
        packet.time = p['time']
        if base_layer is not None:
            packet = base_layer / packet
            packet.time = p['time']
            packet[Ether].time = p['time']
        return packet

    def generate_pcap_packet(self, c):
        """ from parsed content generate pcap packet """
        if not c:
            return False

        if c.get('protocol', '').startswith('UNIX'):
            return False

        if c.get('protocol') == "TCP":
            return self.generate_tcp_packet(c)
        if c.get('protocol') == "UDP":
            return self.generate_udp_packet(c)
        if c.get('protocol') == "TCPv6":
            if c['direction_out']:
                source_mac = self.encode_decimal2mac(c['pid'])
                destination_mac = self.encode_decimal2mac(
                    100000000 * self.op_encode[c['syscall']] + c['session'])
            else:
                destination_mac = self.encode_decimal2mac(c['pid'])
                source_mac = self.encode_decimal2mac(
                    100000000 * self.op_encode[c['syscall']] + c['session'])
            fd_vlan = c['fd']
            return self.generate_tcp_packet_v6(source_mac, destination_mac, fd_vlan, c)
        if c.get('protocol') == "UDPv6":
            if c['direction_out']:
                source_mac = self.encode_decimal2mac(c['pid'])
                destination_mac = self.encode_decimal2mac(
                    100000000 * self.op_encode[c['syscall']] + c['session'])
            else:
                destination_mac = self.encode_decimal2mac(c['pid'])
                source_mac = self.encode_decimal2mac(
                    100000000 * self.op_encode[c['syscall']] + c['session'])
            fd_vlan = c['fd']
            return self.generate_udp_packet_v6(source_mac, destination_mac, fd_vlan, c)

        return False

    def process(self, c):
        """ call to reserved process method, used by higher level generator """
        return self.generate_pcap_packet(c)
