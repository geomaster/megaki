#!/bin/bash
pids=()
for ((i=0; i<$1; ++i)) do
	LD_LIBRARY_PATH=bin tests/playground > tmp/timing$i.txt &
	pids+=($!)
done

for pid in pids; do
	wait ${pids[i]}
done

for type in {hs,msg,rehs}; do
	grep ^$type tmp/timing*.txt | egrep -o [0-9]+ | awk '{total+=$0; count++} END {print total/count "us"}' > $(printf "data/%savg.txt" "$type")
done

rm tmp/timing*.txt
