#!/bin/sh 

if [ $# -ne 1 ] ; then
  echo "$0 \"command to execute or -p , ie strace arguments>\""
  echo "note -> keep strace arugments within qoutes"
  exit 1
fi

OUT_FILE=$(mktemp /tmp/strace2pcap-pipe.XXXX)
STRACE_ARGS="$1"

echo "import scapy" | python3
ERR=$?
if [ $ERR -ne 0 ] ; then
   echo to run conversion to pcap, please install scapy python module
   exit 2 
fi

strace -f -s655350 -o "! ./py_strace2pcap.py " "$OUT_FILE" -ttt -T -yy -xx -e trace=network $STRACE_ARGS > /dev/null  &
STRACE_PID=$!
tail  --pid=$STRACE_PID -c 1000000 -f "$OUT_FILE"
rm "$OUT_FILE"

