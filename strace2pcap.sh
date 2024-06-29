#!/bin/sh

if [ $# -ne 2 ] ; then
  echo "$0 <pcap_file_path> \"command to execute or -p , ie strace arguments>\""
  echo "note -> keep strace arugments within qoutes"
  exit 1
fi

OUT_FILE="$1"
STRACE_ARGS="$2"

echo "import scapy" | python3
ERR=$?
if [ $ERR -ne 0 ] ; then
   echo to run conversion to pcap, please install scapy python module
   exit 2 
fi

strace -f -s655350 -o "! ./py_strace2pcap.py $OUT_FILE" -ttt -T -yy -xx -e trace=network  $STRACE_ARGS

