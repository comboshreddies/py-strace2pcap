# py-strace2pcap
convert specific strace output file to pcap using scapy

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
strace -f -s65535 -o /tmp/straceSample -tt -T -yy -xx command
```
3) start conversion from stract to pcap
```console
strace2pcap.py file_to_store.pcap < /tmp/straceSample
```
4) read network traffic from strace with wireshark, tshark, or tcpdump
```console
wireshark file_to_store.pcap
```

