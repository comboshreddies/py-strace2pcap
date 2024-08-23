#!/bin/sh
tshark -r $1 -T pdml -Y 'tcp.port==11211'  |\
  grep   -e 'frame.time_epoch' -e 'tcp.payload' |\
  sed 's/.*frame.time_epoch.*show="\([0123456789.]*\)".*/{"time": "\1"},/g' |\
  sed 's|.* value="\(.*\)"/>|\1,\n\r|g' |\
  awk '{if($1 ~ /{/) print $0 ; else {print "" ;system("echo "$0" | xxd -r -p ")}}'