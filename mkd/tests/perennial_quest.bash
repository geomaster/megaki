#!/bin/bash
DIR="$( cd "$( dirname "$0" )" && pwd )"

while :
do
  # HALT
	for ((i=0;i<2500;++i))
	do
    nc 127.0.0.1 6363 < $(DIR)/../data/example-syn.bin > /dev/null &
	done
	sleep 5

  # HAMMERZEIT!
	for ((i=0;i<30;++i))
	do
    LD_LIBRARY_PATH=$(DIR)/../../libsazukari/bin $(DIR)/../../libsazukari/tests/playground &
	done

	sleep 20
	killall playground
done
