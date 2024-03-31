# py_strace2pcap
convert specific strace output file to pcap using scapy python library

![example wireshark](https://github.com/comboshreddies/py-strace2pcap/blob/main/images/mongo_find.png?raw=true)


# setup
1) install needed python module
```console
pip3 install scapy
```
or
```console
pip3 install -r requirements.txt
```
2) start strace
```console
strace -f -s65535 -o /tmp/straceSample -ttt -T -yy -xx command
```
3) start conversion from strace to pcap
```console
py_strace2pcap.py file_to_store.pcap < /tmp/straceSample
```
4) read network traffic from strace with wireshark, tshark, or tcpdump
```console
wireshark file_to_store.pcap
```

# helpers
1) there is example straceSample in example directory, along with example straceSample.pcap

2) when protocol is not recognized in wireshark/tshark, do use decode packet on tcp payload (check screenshots in images directory)
or specify dissector in commandline while running tshark/wireshark
example below is for mongo protocol
```console
wireshark ./example/straceSample.pcap  -d tcp.port==27017,mongo 
```
3) if program observed with strace logs too much operations, and file becomes too large, to add **-e trace=network** to strace command, to isolate just network traffic

4) strace data encodings:

* PID from strace file is encoded in eth.addr (src or dst depending on direction of packet), it is encoded as deciman within hex/byte of ethernet mac, so for PID 123456 you should see mac address 00:00:00:12:34:56

* FD (file descriptor) from strace is encoded in vlan ID (802.1q), for example FD 17 is encoded as VlanID 17

* session (unique fd session) is encoded in other eth.add (src or dst) at lower part of mac starting from eth.addr[5]

* system call is encoded along with session on eth.addr[1]
   * read = 1
   * write = 2
   * sendmsg = 3
   * recvmsg = 4
   * recvfrom = 5
   * sendto = 6

6) 

# known issues
1) strace version 6 (tested on gentoo with version 6.6) might return strace format with two blank spaces following pid,
that will break formating (fixed in code). 

# reporting issues
please send strace command you've used and strace output

# todo:
0) tool for strace -xx conversion to ascii payload (standard strace output)
1) localhost comm
2) UNIX-STREAM
3) NETLINK

