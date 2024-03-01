# py_strace2pcap
convert specific strace output file to pcap using scapy

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

# known issues
1) strace version 6 (tested on gentoo with version 6.6) might return strace format with two blank spaces following pid,
that will break formating (fixed in code). 

# reporting issues
please send strace command you've used and strace output
