""" parse strace line to parsed dict items result """

from scapy.all import Ether, IP, TCP, UDP

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

    sequence = {}

    def encode_decimal2mac(self, enc):
        """ encode int to mac, we're econding pid , fd , steram and such """
        mac6 = (enc)%100
        mac5 = int(enc / 100) % 100
        mac4 = int(enc / 10000) % 100
        mac3 = int(enc / 1000000) % 100
        mac2 = int(enc / 100000000) % 100
        mac1 = int(enc / 10000000000)
        return f"{mac1:#02d}:{mac2:#02d}:{mac3:#02d}:{mac4:#02d}:{mac5:#02d}:{mac6:#02d}"

    def generate_sequence(self, c):
        """ generate sequence """
        return (c['fd']*100 + c['pid']*10000 + c['session']) % 4294967295

    def generate_sequence_key(self, c):
        """ generate sequence_key """
        return  f"{c['source_ip']}:{c['source_port']}_{c['destination_ip']}: \
            {c['destination_port']}_{c['pid']}:{c['fd']}{c['session']}"

    def generate_tcp_packet(self, src_mac, dst_mac,p):
        """ generate tcp packet """
        seq_key = self.generate_sequence_key(p)
        if not seq_key in self.sequence :
            self.sequence[seq_key] = self.generate_sequence(p)
        tcp_packet = Ether(src=src_mac, dst=dst_mac) / \
            IP(src=p['source_ip'], dst=p['destination_ip']) / \
            TCP(flags='PA', sport=p['source_port'], dport=p['destination_port'], \
                seq=self.sequence[seq_key]) / \
            p['payload']
        if seq_key in self.sequence:
            self.sequence[seq_key]+=len(p['payload'])
        return tcp_packet

    def generate_udp_packet(self, src_mac, dst_mac,p):
        """ generate udp packet """
        return Ether(src=src_mac, dst=dst_mac) / \
            IP(src=p['source_ip'], dst=p['destination_ip']) / \
            UDP(sport=p['source_port'], dport=p['destination_port']) / \
            p['payload']

    def generate_pcap_packet(self, c):
        """ from parsed content generate pcap packet """
        if c :
            # encode pid to source mac
            source_mac = self.encode_decimal2mac(c['pid'])
            # encode fd, operation and session
            destination_mac = self.encode_decimal2mac(c['fd']*1000000+10000000000* \
                self.op_encode[c['syscall']]+c['session'])
            if c['protocol'] == "TCP" :
                return self.generate_tcp_packet(source_mac, destination_mac, c)
            if c['protocol'] == "UDP" :
                return self.generate_udp_packet(source_mac, destination_mac, c)
        return False

    def process(self, c):
        """ call to reserved process method, used by higher level generator """
        return self.generate_pcap_packet(c)
