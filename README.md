# py-strace2pcap
convert specific strace output file to pcap using scapy

# setup
1) 
```console
pip3 install scapy
```
or
```console
pip3 install -r requirements.txt
```
2) 
```console
strace -f -s65535 -o /tmp/straceSample -tt -T -yy command
```
3) 
```console
strace2pcap.py file_to_store.pcap < /tmp/straceSample
```
4) 
```console
wireshark file_to_store.pcap
"""

