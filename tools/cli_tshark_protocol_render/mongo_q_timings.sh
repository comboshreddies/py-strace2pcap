#!/usr/bin/env sh

FILE=$1

tshark -r "$FILE" -T pdml -Y 'tcp.port==27017' -d'tcp.port==27017,mongo' |\
  grep -e 'Transmission Contro' -e 'Internet Protocol'  -e 'frame.time_epoch' -e mongo.element.name -e mongo.element.value.string -e 'showname="ObjectID:' |\
  sed 's/.*frame.time_epoch.*show="\([0123456789.]*\)".*/time \1/g' |\
  sed 's/.*Internet Protocol Version 4, Src: \([0123456789.]*\), Dst: \([0123456789.]*\)" size.*/ip \1 \2/g' |\
  sed 's/.*"Transmission Control Protocol, Src Port: \([0123456789]*\), Dst Port: \([0123456789]*\), Seq.*/port \1 \2/g' |\
  grep -e ^port -e ^tcp -e^ip -e ^time  -e '<field' |\
  grep -e '^            <field' -e ^port -e ^tcp -e ^ip -e ^time -e '^          <' -e '^                  <field'|\
  grep -v -e 't: $clusterTime"' -e 't: operationTime"' -e 't: $db"' -e 't: lsid"' |\
  awk '{ if($1=="time") {time=$2; print time,ip,port,proto,oid;proto="" } if($1=="ip") ip=$2" "$3;if($1=="port") port=$2" "$3; if($1=="<field") proto=proto" "substr($4,0,length($4)-1)}' |\
  awk '{o=$6;if(o=="aggregate" || o=="findAndModify" || o=="topologyVersion" || o=="isMaster" || o=="listDatabases" || o=="listCollections" || o=="insert" || o=="find" || o=="update" || o=="endSession" || o=="saslStart" || o=="saslContinue" || o=="create" || o=="ping" || o=="endSessions" || o=="count" || o=="drop" || o=="createIndexes" || o=="listIndexes") { print "Q "$0;} else {if(NF>5) print "R "$0;}}' | awk '{if($1=="Q") {k=sprintf("%15s %5s %15s %5s",$3,$5,$4,$6);t[k]=$2;ops="";for(i=7;i<=NF;i++) ops=ops" "$i;op[k]=ops} if($1=="R") {k=sprintf("%15s %5s %15s %5s",$4,$6,$3,$5); if(t[k]){printf("%12.6f %12.6f %12.6f %s %s\n",t[k],$2,$2-t[k],k,op[k])}}}'


